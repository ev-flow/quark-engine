from __future__ import annotations

from contextlib import suppress
import mmap
import struct
import zlib
from typing import Iterator, Tuple

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
        with suppress(BaseException):
            eocd_offset = ApkPatcher._find_eocd(raw_data)
            cdh_count, cdh_start_offset = ApkPatcher._parse_eocd(
                raw_data, eocd_offset
            )
            compression_patched = ApkPatcher._patch_invalid_compression_method(
                raw_data, cdh_count, cdh_start_offset
            )
            return compression_patched
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
    ) -> Iterator[int]:
        """
        Iterates over the Central Directory Headers (CDH) and yields offsets.

        :param raw_data: A memory-mapped file object of the APK.
        :param cdh_count: The total number of CDH entries.
        :param cdh_start_offset: The starting offset of the first CDH entry.
        :return: An iterator that yields the offset of each CDH.
        """
        current_offset = cdh_start_offset
        for _ in range(cdh_count):
            if not raw_data[current_offset:].startswith(CDH_SIGNATURE):
                # No a valid CDH signature, skip it
                continue

            yield current_offset

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

        for current_offset in ApkPatcher._iter_cdh(
            raw_data, cdh_count, cdh_start_offset
        ):
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

            if not raw_data[lfh_offset:].startswith(LFH_SIGNATURE):
                # No a valid LFH signature, skip it
                continue

            lfh_compression_method_offset = lfh_offset + 8
            struct.pack_into("<H", raw_data, lfh_compression_method_offset, 0)

            lfh_compression_size_offset = lfh_offset + 18
            struct.pack_into(
                "<I", raw_data, lfh_compression_size_offset, uncompressed_size
            )

        return isPatched
