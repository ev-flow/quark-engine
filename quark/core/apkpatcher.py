from __future__ import annotations

from contextlib import suppress
import mmap
import struct
import zlib
from typing import Iterator, Tuple
import logging
from quark import config
from quark.utils.logger import defaultHandler

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(defaultHandler)
log.disabled = not config.DEBUG

EOCD_SIGNATURE = b"PK\x05\x06"
CDH_SIGNATURE = b"PK\x01\x02"
LFH_SIGNATURE = b"PK\x03\x04"

# A set of all compression methods defined in the ZIP file format spec.
# See https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT for details.
VALID_COMPRESSION_METHODS = set(range(0, 21)) | set(range(93, 100))


class SeekableMMap(mmap.mmap):
    """
    A mmap.mmap subclass that adds the seekable method required by
    zipfile.ZipFile in Python 3.12 or earlier.
    """

    def seekable(self) -> bool:
        """
        Return whether the file supports seeking. Always return True.
        See https://docs.python.org/3/library/mmap.html#mmap.mmap.seekable.
        """
        return True


class ApkPatcher:
    """
    A utility class to handle anti-analysis techniques in Android APK files.
    """

    @staticmethod
    def patch(raw_data: mmap.mmap) -> bool:
        """
        Finds and patches known anti-analysis techniques in an APK.

        This function perform patches in place and suppresses any errors to
        prevent crashes that would interrupt the analysis.

        :param raw_data: A memory-mapped file object of the APK.
        :return: True if any part of the APK was patched; False otherwise.
        """
        try:
            eocd_offset = ApkPatcher._find_eocd(raw_data)
            cdh_count, cdh_start_offset = ApkPatcher._parse_eocd(
                raw_data, eocd_offset
            )
            compression_patched = ApkPatcher._patch_invalid_compression_method(
                raw_data, cdh_count, cdh_start_offset
            )
            manifest_patched = ApkPatcher._patch_manifest_signature(
                raw_data, cdh_count, cdh_start_offset
            )
            return compression_patched or manifest_patched

        except BaseException as e:
            log.exception(e)
            return False

    @staticmethod
    def _find_eocd(raw_data: mmap.mmap) -> int:
        """
        Finds the End of Central Directory (EOCD) record in the APK data.

        :param raw_data: A memory-mapped file object of the APK.
        :raises ValueError: If the EOCD signature cannot be found.
        """
        eocd_offset = raw_data.rfind(EOCD_SIGNATURE)
        if eocd_offset == -1:
            raise ValueError("EOCD signature not found in the file.")
        return eocd_offset

    @staticmethod
    def _parse_eocd(raw_data: mmap.mmap, eocd_offset: int) -> Tuple[int, int]:
        """
        Parses the EOCD to find the Central Directory offset and entry count.

        :param raw_data: A memory-mapped file object of the APK.
        :param eocd_offset: The offset of the EOCD record.
        :return: A tuple containing the total number of CDH entries and the
                 starting offset of the first CDH entry.
        """
        cdh_count_offset = eocd_offset + 10
        cdh_start_offset_offset = eocd_offset + 16

        (cdh_count,) = struct.unpack_from("<H", raw_data, cdh_count_offset)
        (cdh_start_offset,) = struct.unpack_from(
            "<I", raw_data, cdh_start_offset_offset
        )
        return cdh_count, cdh_start_offset

    @staticmethod
    def _iter_cdh(
        raw_data: mmap.mmap, cdh_count: int, cdh_start_offset: int
    ) -> Iterator[tuple[int, bool]]:
        """
        Iterates over the Central Directory Headers (CDH) and yields offsets.

        :param raw_data: A memory-mapped file object of the APK.
        :param cdh_count: The total number of CDH entries.
        :param cdh_start_offset: The starting offset of the first CDH entry.
        :return: An iterator that yields the offset of each CDH.
        """
        current_offset = cdh_start_offset
        for _ in range(cdh_count):
            actual_signature = raw_data[
                current_offset : current_offset + len(CDH_SIGNATURE)
            ]
            is_valid_signature = actual_signature == CDH_SIGNATURE
            yield current_offset, is_valid_signature

            filename_len_offset = current_offset + 28
            extra_field_len_offset = current_offset + 30
            comment_len_offset = current_offset + 32

            (filename_len,) = struct.unpack_from(
                "<H", raw_data, filename_len_offset
            )
            (extra_field_len,) = struct.unpack_from(
                "<H", raw_data, extra_field_len_offset
            )
            (comment_len,) = struct.unpack_from(
                "<H", raw_data, comment_len_offset
            )
            current_offset += 46 + filename_len + extra_field_len + comment_len

    @staticmethod
    def _patch_invalid_compression_method(
        raw_data: mmap.mmap, cdh_count: int, cdh_start_offset: int
    ) -> bool:
        """
        Finds and patches entries with invalid compression methods.


        This function checks the compression method in all Central Directory
        Headers (CDHs). If an invalid compression method is found, it patches
        the method to 0 in both the CDH and the corresponding Local File Header
        (LFH). It also updates the compressed size to match the uncompressed
        size.

        :param raw_data: A memory-mapped file object of the APK.
        :param cdh_count: The total number of CDH entries.
        :param cdh_start_offset: The starting offset of the first CDH entry.
        :return: True if any compression method was patched, False otherwise.
        """
        isPatched = False

        for current_offset, is_valid_signature in ApkPatcher._iter_cdh(
            raw_data, cdh_count, cdh_start_offset
        ):
            if not is_valid_signature:
                log.warning(
                    f"Found invalid CDH signature at offset {current_offset}."
                    " Try parsing it anyway."
                )

            compression_method_offset = current_offset + 10
            lfh_offset_offset = current_offset + 42

            compression_method, *_ = struct.unpack_from(
                "<H", raw_data, compression_method_offset
            )
            lfh_offset, *_ = struct.unpack_from(
                "<I", raw_data, lfh_offset_offset
            )

            if compression_method in VALID_COMPRESSION_METHODS:
                continue

            struct.pack_into("<H", raw_data, compression_method_offset, 0)
            isPatched = True

            uncompressed_size_offset = current_offset + 24
            uncompressed_size, *_ = struct.unpack_from(
                "<I", raw_data, uncompressed_size_offset
            )

            compressed_size_offset = current_offset + 20
            struct.pack_into(
                "<I", raw_data, compressed_size_offset, uncompressed_size
            )

            actual_lfh_signature = raw_data[
                lfh_offset : lfh_offset + len(LFH_SIGNATURE)
            ]
            if not actual_lfh_signature == LFH_SIGNATURE:
                log.warning(
                    f"Found invalid LFH signature at offset {lfh_offset}."
                    " Try patching it anyway."
                )

            lfh_compression_method_offset = lfh_offset + 8
            struct.pack_into("<H", raw_data, lfh_compression_method_offset, 0)

            lfh_compression_size_offset = lfh_offset + 18
            struct.pack_into(
                "<I", raw_data, lfh_compression_size_offset, uncompressed_size
            )

        return isPatched

    @staticmethod
    def _patch_manifest_signature(
        raw_data: mmap.mmap, cdh_count: int, cdh_start_offset: int
    ) -> bool:
        """
        Finds and patches the signature of an uncompressed AndroidManifest.xml.

        If the manifest file is found and its compression method is STORED (0),
        this method checks if the first byte of its data is 0x03. If not, it
        patches the byte and updates the CRC-32 checksum in the LFH and CDH.

        :param raw_data: A memory-mapped file object of the APK.
        :param cdh_count: The total number of CDH entries.
        :param cdh_start_offset: The starting offset of the first CDH entry.
        :return: True if the manifest signature was patched, False otherwise.
        """
        is_patched = False

        expected_file_name = "AndroidManifest.xml".encode(
            "utf-8", errors="ignore"
        )
        expected_file_name_len = len(expected_file_name)

        for current_offset, is_valid_signature in ApkPatcher._iter_cdh(
            raw_data, cdh_count, cdh_start_offset
        ):
            if not is_valid_signature:
                log.warning(
                    f"Found invalid CDH signature at offset {current_offset}."
                    " Try parsing it anyway."
                )
                
            # Check filename
            filename_offset = current_offset + 46
            actual_file_name = raw_data[
                filename_offset : filename_offset + expected_file_name_len
            ]

            if actual_file_name != expected_file_name:
                continue

            # Check compression method (0 = STORED)
            compression_method_offset = current_offset + 10
            (compression_method,) = struct.unpack_from(
                "<H", raw_data, compression_method_offset
            )

            if compression_method != 0:
                continue

            # Get LFH offset to find the actual file data
            lfh_offset_offset = current_offset + 42
            (lfh_offset,) = struct.unpack_from(
                "<I", raw_data, lfh_offset_offset
            )

            actual_lfh_signature = raw_data[
                lfh_offset : lfh_offset + len(LFH_SIGNATURE)
            ]
            if not actual_lfh_signature == LFH_SIGNATURE:
                log.warning(
                    "Found invalid LFH signature at"
                    f" offset {lfh_offset}. Try patching it anyway."
                )

            uncompressed_size_offset = current_offset + 24
            (uncompressed_size,) = struct.unpack_from(
                "<I", raw_data, uncompressed_size_offset
            )
            if uncompressed_size == 0:
                log.info(
                    "Found uncompressed size of 0 at"
                    f" offset {current_offset}. Skip checking the signature."
                )

            # Calculate data offset from LFH
            lfh_filename_len_offset = lfh_offset + 26
            lfh_extra_field_len_offset = lfh_offset + 28
            (lfh_filename_len,) = struct.unpack_from(
                "<H", raw_data, lfh_filename_len_offset
            )
            (lfh_extra_field_len,) = struct.unpack_from(
                "<H", raw_data, lfh_extra_field_len_offset
            )
            data_offset = (
                lfh_offset + 30 + lfh_filename_len + lfh_extra_field_len
            )

            # Check and patch the AXML signature (first byte of data)
            if raw_data[data_offset] == 0x03:
                # Manifest starts with 0x03. no need to continue iterating
                break

            raw_data[data_offset] = 0x03
            is_patched = True

            # Calculate new CRC on the patched data in chunks.
            new_crc = 0
            chunk_size = 65536  # 64KB
            data_view = memoryview(raw_data)
            for i in range(0, uncompressed_size, chunk_size):
                chunk_boundary = min(i + chunk_size, uncompressed_size)
                chunk = data_view[
                    data_offset + i : data_offset + chunk_boundary
                ]
                new_crc = zlib.crc32(chunk, new_crc)

            # Update CRC in CDH
            cdh_crc_offset = current_offset + 16
            struct.pack_into("<I", raw_data, cdh_crc_offset, new_crc)

            # Update CRC in LFH
            lfh_crc_offset = lfh_offset + 14
            struct.pack_into("<I", raw_data, lfh_crc_offset, new_crc)

            # Manifest found and processed, no need to continue iterating
            break

        return is_patched
