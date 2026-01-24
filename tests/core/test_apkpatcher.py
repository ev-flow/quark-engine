import mmap
import zipfile
from pathlib import Path

import pytest

from quark.core.apkpatcher import (
    VALID_COMPRESSION_METHODS,
    ApkPatcher,
    SeekableMMap,
)


@pytest.fixture(scope="session")
def apkContent(SAMPLE_PATH_3d52b):
    with open(SAMPLE_PATH_3d52b, "rb") as fp, SeekableMMap(
        fp.fileno(), 0, access=mmap.ACCESS_COPY
    ) as mm:
        yield mm


class TestApkPatcher:
    def test_patch(self, apkContent: SeekableMMap):
        """
        Tests that ApkPatcher.patch correctly fixes invalid compression methods,
        updates sizes, and patches AndroidManifest.xml signature.
        """
        # The return values of patch indicates if any modification was made.
        # Assuming SAMPLE_PATH_3d52b requires patching for both.
        # If the sample APK doesn't have issues, this assertion might need adjustment
        # (e.g., to be more specific about *which* part was patched).
        # For now, we assert that *some* patching occurred.
        assert ApkPatcher.patch(apkContent) is True

        # Verify all compression methods and sizes are valid.
        manifest_found = False
        with zipfile.ZipFile(apkContent, "r") as patched_zf:  # type: ignore
            for info in patched_zf.infolist():
                # Compression method and size checks
                assert info.compress_type in VALID_COMPRESSION_METHODS, (
                    f"File '{info.filename}' has invalid compression "
                    f"type {info.compress_type} after patching."
                )

                if info.compress_type == 0:  # Only check STORED for size match
                    assert info.compress_size == info.file_size, (
                        f"File '{info.filename}' has type STORED but "
                        f"mismatched sizes (compress:{info.compress_size}, "
                        f"file:{info.file_size})."
                    )

                # Manifest signature check
                if info.filename == "AndroidManifest.xml":
                    manifest_found = True
                    # Read AndroidManifest.xml content from the patched ZIP
                    manifest_content = patched_zf.read(info.filename)
                    assert (
                        len(manifest_content) > 0
                    ), "AndroidManifest.xml content is empty."
                    assert manifest_content[0] == 0x03, (
                        "First byte of AndroidManifest.xml"
                        " is not 0x03 after patching."
                    )

        assert (
            manifest_found
        ), "AndroidManifest.xml not found in the patched APK."
