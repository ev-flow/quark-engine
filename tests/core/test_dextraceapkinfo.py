# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

"""
Unit and integration tests for DexTraceImp in quark/core/dextraceapkinfo.py.

Tests cover bugs that were fixed:
  1. _normalize_class did not handle the case where input starts with "L" but
     lacks a trailing ";" — it would produce a double-"L" prefix.
  2. find_method used raw == equality against DexTrace-normalized class names,
     so class names from rule files (which lack the trailing ";") returned empty
     lists.
  3. APKs with bogus ZIP compression types (e.g. 8744) caused DexTrace to
     return 0% confidence on all rules: DexTraceImp must detect the patching
     done by ApkPatcher and forward a patched temp file to DexTrace APIs so
     DexTrace reads the corrected bytes.
"""

import os
import zipfile
from unittest.mock import patch

import pytest

try:
    from quark.core.dextraceapkinfo import DexTraceImp

    _HAS_DEXTRACE = True
except ImportError:
    _HAS_DEXTRACE = False

pytestmark = pytest.mark.skipif(
    not _HAS_DEXTRACE, reason="DexTrace not installed"
)


@pytest.fixture(scope="module")
def dextrace_instance(SAMPLE_PATH_Ahmyth):
    """Return a DexTraceImp instance backed by the Ahmyth APK."""
    return DexTraceImp(SAMPLE_PATH_Ahmyth)


# ---------------------------------------------------------------------------
# Integration tests for find_method with class names lacking trailing ";"
# ---------------------------------------------------------------------------


class TestFindMethodClassNormalization:
    """
    Regression tests verifying that find_method accepts class names both with
    and without a trailing semicolon and returns the same non-empty result.

    SmsManager.sendTextMessage is called by Ahmyth for SMS exfiltration, so it
    is reliably present in the Ahmyth call graph.
    """

    def test_find_method_with_canonical_class_name(self, dextrace_instance):
        """Fully-qualified Dalvik class name (with semicolon) returns results."""
        results = dextrace_instance.find_method(
            "Landroid/telephony/SmsManager;", "sendTextMessage", None
        )
        assert results, (
            "find_method returned empty list for canonical class name "
            "'Landroid/telephony/SmsManager;'"
        )

    def test_find_method_without_trailing_semicolon_matches(
        self, dextrace_instance
    ):
        """Bug regression: class name without trailing semicolon returns same
        non-empty result as the canonical form."""
        with_semicolon = dextrace_instance.find_method(
            "Landroid/telephony/SmsManager;", "sendTextMessage", None
        )
        # Clear LRU cache so the two calls are independent (different args).
        dextrace_instance.find_method.cache_clear()
        without_semicolon = dextrace_instance.find_method(
            "Landroid/telephony/SmsManager", "sendTextMessage", None
        )
        assert without_semicolon, (
            "find_method returned empty list when class name lacks trailing ';' "
            "— regression of the _normalize_class / find_method bug"
        )
        assert set(with_semicolon) == set(without_semicolon), (
            "find_method returns different results depending on whether the "
            "trailing ';' is present"
        )

    def test_find_method_slash_separated_without_l_prefix_matches(
        self, dextrace_instance
    ):
        """Bug regression: slash-separated class name without L prefix returns
        same non-empty result as the canonical form."""
        canonical = dextrace_instance.find_method(
            "Landroid/telephony/SmsManager;", "sendTextMessage", None
        )
        dextrace_instance.find_method.cache_clear()
        slash_only = dextrace_instance.find_method(
            "android/telephony/SmsManager", "sendTextMessage", None
        )
        assert slash_only, (
            "find_method returned empty list for slash-separated class name "
            "without L prefix"
        )
        assert set(canonical) == set(slash_only)


# ---------------------------------------------------------------------------
# Bogus ZIP compression anti-analysis fix (3d52b APK)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dextrace_3d52b(SAMPLE_PATH_3d52b):
    """DexTraceImp backed by the APK that uses a bogus compression type (8744)
    on AndroidManifest.xml as an anti-analysis trick."""
    return DexTraceImp(SAMPLE_PATH_3d52b)


@pytest.mark.skipif(not _HAS_DEXTRACE, reason="DexTrace not installed")
class TestBogusCompressionFix:
    """Regression tests for the bogus ZIP compression / permissions fix.

    The 3d52b APK sets AndroidManifest.xml's compression type to 8744 while
    storing data uncompressed.  Before the fix this caused 0% confidence on
    all Quark rules because permissions came back empty (Level 1 failure).
    """

    def test_apk_is_detected_as_patched(self, dextrace_3d52b):
        """ApkPatcher must recognise the bogus compression and set isPatched."""
        assert dextrace_3d52b.isPatched is True

    def test_permissions_non_empty(self, dextrace_3d52b):
        """After the fix, permissions must be non-empty (Level 1 passes)."""
        perms = dextrace_3d52b.permissions
        assert len(perms) > 0, (
            "permissions is empty — Level 1 will fail for all rules "
            "(regression of bogus-compression fix)"
        )

    def test_permissions_include_expected(self, dextrace_3d52b):
        """INTERNET permission must be present (known from manual inspection)."""
        assert "android.permission.INTERNET" in dextrace_3d52b.permissions

    def test_no_temp_file_leak_after_gc(self, SAMPLE_PATH_3d52b):
        """DexTraceImp must not leave temp APK files on disk after the instance is GC'd."""
        import glob
        import tempfile

        tmp_dir = tempfile.gettempdir()
        apk_before = set(glob.glob(os.path.join(tmp_dir, "*.apk")))
        instance = DexTraceImp(SAMPLE_PATH_3d52b)
        del instance
        apk_after = set(glob.glob(os.path.join(tmp_dir, "*.apk")))
        assert not (apk_after - apk_before), (
            "DexTraceImp leaked temp APK files after __del__: "
            f"{apk_after - apk_before}"
        )


# ---------------------------------------------------------------------------
# Manifest fast-fail: DexTraceImp must raise ValueError on broken manifests
# ---------------------------------------------------------------------------


class TestManifestFastFail:
    """
    Regression tests for Issue 4 (broken manifest fast-fail).

    trickmo/tanglebot APKs have unreadable AndroidManifest.xml entries.
    Before the fix, DexTraceImp silently swallowed the parse error and ran
    3 full DEX passes (134 s on trickmo).  After the fix it raises ValueError
    immediately, matching Androguard's behavior.
    """

    @pytest.mark.parametrize(
        "include_manifest,manifest_content",
        [
            (True, b"not-valid-axml-bytes"),  # bad AXML bytes
            (False, None),  # missing manifest entry
        ],
    )
    def test_unreadable_manifest_raises_value_error(
        self, tmp_path, include_manifest, manifest_content
    ):
        """APK with bad or absent AndroidManifest.xml raises ValueError."""
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            if include_manifest:
                zf.writestr("AndroidManifest.xml", manifest_content)
            zf.writestr("classes.dex", b"")
        with pytest.raises(ValueError, match="AndroidManifest"):
            DexTraceImp(str(apk_path))


# ---------------------------------------------------------------------------
# Smali parsing helpers (_strip_smali_comment, _method_sig_to_androguard_
# format, _parse_smali_to_bytecodeobject)
# ---------------------------------------------------------------------------


class TestStripSmaliComment:
    """Regression tests for _strip_smali_comment."""

    def test_no_comment_returns_stripped_input(self):
        assert (
            DexTraceImp._strip_smali_comment("  const/4 v0, 0x0  ")
            == "const/4 v0, 0x0"
        )

    def test_trailing_comment_is_removed(self):
        assert (
            DexTraceImp._strip_smali_comment("const/4 v0, 0x0 // comment")
            == "const/4 v0, 0x0"
        )

    def test_comment_marker_inside_string_literal_is_kept(self):
        smali = 'const-string v0, "http://example.com" // set url'
        assert (
            DexTraceImp._strip_smali_comment(smali)
            == 'const-string v0, "http://example.com"'
        )


class TestMethodSigToAndroguardFormat:
    """Regression tests for _method_sig_to_androguard_format."""

    def test_non_method_sig_is_returned_unchanged(self):
        assert (
            DexTraceImp._method_sig_to_androguard_format("Lcom/example/Foo;")
            == "Lcom/example/Foo;"
        )

    def test_method_sig_gains_spaced_args(self):
        sig = "Lcom/example/Foo;->bar(ILjava/lang/String;)V"
        assert (
            DexTraceImp._method_sig_to_androguard_format(sig)
            == "Lcom/example/Foo;->bar(I Ljava/lang/String;)V"
        )

    def test_method_sig_with_no_args(self):
        sig = "Lcom/example/Foo;->bar()V"
        assert (
            DexTraceImp._method_sig_to_androguard_format(sig)
            == "Lcom/example/Foo;->bar()V"
        )

    def test_malformed_sig_falls_back_to_raw_string(self):
        # Has "->" and "(" but a descriptor that descriptor_to_androguard_
        # format() cannot parse (no closing paren) must not raise — it
        # should fall back to the original string.
        sig = "Lcom/example/Foo;->bar(ILjava/lang/String;"
        assert DexTraceImp._method_sig_to_androguard_format(sig) == sig


class TestParseSmaliToBytecodeObject:
    """Regression tests for _parse_smali_to_bytecodeobject."""

    def test_mnemonic_only_instruction(self, dextrace_instance):
        bytecode = dextrace_instance._parse_smali_to_bytecodeobject(
            "return-void"
        )
        assert bytecode.mnemonic == "return-void"
        assert bytecode.registers is None
        assert bytecode.parameter is None

    def test_empty_smali_raises_value_error(self, dextrace_instance):
        with pytest.raises(ValueError, match="Empty smali"):
            dextrace_instance._parse_smali_to_bytecodeobject("   ")

    def test_const_numeric_literal_is_parsed_as_int(self, dextrace_instance):
        bytecode = dextrace_instance._parse_smali_to_bytecodeobject(
            "const/4 v0, 0x1"
        )
        assert bytecode.mnemonic == "const/4"
        assert bytecode.registers == ["v0"]
        assert bytecode.parameter == 1

    def test_const_non_numeric_literal_is_kept_as_string(
        self, dextrace_instance
    ):
        # A const-family literal that isn't a valid int() text (e.g. a
        # symbolic placeholder) must not raise -- the ValueError is
        # swallowed and the raw text is kept unparsed.
        bytecode = dextrace_instance._parse_smali_to_bytecodeobject(
            "const/4 v0, not_a_number"
        )
        assert bytecode.mnemonic == "const/4"
        assert bytecode.parameter == "not_a_number"

    def test_const_string_strips_quotes(self, dextrace_instance):
        bytecode = dextrace_instance._parse_smali_to_bytecodeobject(
            'const-string v0, "hello"'
        )
        assert bytecode.parameter == "hello"

    def test_invoke_parameter_normalized_to_androguard_format(
        self, dextrace_instance
    ):
        smali = (
            "invoke-virtual {v0, v1}, "
            "Lcom/example/Foo;->bar(ILjava/lang/String;)V"
        )
        bytecode = dextrace_instance._parse_smali_to_bytecodeobject(smali)
        assert bytecode.mnemonic == "invoke-virtual"
        assert bytecode.registers == ["v0", "v1"]
        assert (
            bytecode.parameter
            == "Lcom/example/Foo;->bar(I Ljava/lang/String;)V"
        )

    def test_field_access_parameter_uses_space_instead_of_colon(
        self, dextrace_instance
    ):
        smali = (
            "iget-object v0, v1, Lcom/example/Foo;->name:Ljava/lang/String;"
        )
        bytecode = dextrace_instance._parse_smali_to_bytecodeobject(smali)
        assert bytecode.mnemonic == "iget-object"
        assert (
            bytecode.parameter == "Lcom/example/Foo;->name Ljava/lang/String;"
        )


# ---------------------------------------------------------------------------
# _disasm_by_sig (mocked dextrace.api.disasm_method)
# ---------------------------------------------------------------------------


class TestDisasmBySig:
    """Regression tests for _disasm_by_sig, mocking the DexTrace-provided
    disasm_method() so no real disassembly is performed."""

    SIG = "Lcom/example/Foo;->bar()V"

    def test_disasm_disabled_returns_none(self, dextrace_instance):
        dextrace_instance._disasm_by_sig.cache_clear()
        dextrace_instance._enable_disasm = False
        try:
            with patch(
                "quark.core.dextraceapkinfo.disasm_method"
            ) as mock_disasm:
                assert dextrace_instance._disasm_by_sig(self.SIG) is None
                mock_disasm.assert_not_called()
        finally:
            dextrace_instance._enable_disasm = True
            dextrace_instance._disasm_by_sig.cache_clear()

    def test_disasm_method_raises_returns_none(self, dextrace_instance):
        dextrace_instance._disasm_by_sig.cache_clear()
        with patch(
            "quark.core.dextraceapkinfo.disasm_method",
            side_effect=RuntimeError("boom"),
        ):
            assert dextrace_instance._disasm_by_sig(self.SIG) is None
        dextrace_instance._disasm_by_sig.cache_clear()

    def test_disasm_result_missing_methods_key_returns_none(
        self, dextrace_instance
    ):
        dextrace_instance._disasm_by_sig.cache_clear()
        with patch(
            "quark.core.dextraceapkinfo.disasm_method",
            return_value={"not_methods": {}},
        ):
            assert dextrace_instance._disasm_by_sig(self.SIG) is None
        dextrace_instance._disasm_by_sig.cache_clear()

    def test_disasm_result_exact_sig_match_returns_instructions(
        self, dextrace_instance
    ):
        dextrace_instance._disasm_by_sig.cache_clear()
        normalized_sig = dextrace_instance._normalize_dextrace_sig(self.SIG)
        fake_result = {
            "methods": {
                normalized_sig: {
                    "instructions": [
                        {"smali": "return-void"},
                        {"no_smali_key": True},
                        "not-a-dict",
                    ]
                }
            }
        }
        with patch(
            "quark.core.dextraceapkinfo.disasm_method",
            return_value=fake_result,
        ):
            result = dextrace_instance._disasm_by_sig(self.SIG)
        assert result == [{"smali": "return-void"}]
        dextrace_instance._disasm_by_sig.cache_clear()

    def test_disasm_result_falls_back_to_normalized_key_match(
        self, dextrace_instance
    ):
        dextrace_instance._disasm_by_sig.cache_clear()
        # Key in the result uses a differently-formatted (but equivalent
        # after normalization) signature than the lookup key.
        fake_result = {
            "methods": {
                "Lcom/example/Foo;->bar()V  ": {
                    "instructions": [{"smali": "return-void"}]
                }
            }
        }
        with patch(
            "quark.core.dextraceapkinfo.disasm_method",
            return_value=fake_result,
        ):
            result = dextrace_instance._disasm_by_sig(self.SIG)
        assert result == [{"smali": "return-void"}]
        dextrace_instance._disasm_by_sig.cache_clear()

    def test_disasm_result_no_matching_method_returns_none(
        self, dextrace_instance
    ):
        dextrace_instance._disasm_by_sig.cache_clear()
        fake_result = {"methods": {"Lother/Class;->other()V": {}}}
        with patch(
            "quark.core.dextraceapkinfo.disasm_method",
            return_value=fake_result,
        ):
            assert dextrace_instance._disasm_by_sig(self.SIG) is None
        dextrace_instance._disasm_by_sig.cache_clear()

    def test_disasm_result_instructions_not_a_list_returns_none(
        self, dextrace_instance
    ):
        dextrace_instance._disasm_by_sig.cache_clear()
        normalized_sig = dextrace_instance._normalize_dextrace_sig(self.SIG)
        fake_result = {
            "methods": {normalized_sig: {"instructions": "not-a-list"}}
        }
        with patch(
            "quark.core.dextraceapkinfo.disasm_method",
            return_value=fake_result,
        ):
            assert dextrace_instance._disasm_by_sig(self.SIG) is None
        dextrace_instance._disasm_by_sig.cache_clear()

    def test_disasm_result_empty_instruction_list_returns_none(
        self, dextrace_instance
    ):
        dextrace_instance._disasm_by_sig.cache_clear()
        normalized_sig = dextrace_instance._normalize_dextrace_sig(self.SIG)
        fake_result = {"methods": {normalized_sig: {"instructions": []}}}
        with patch(
            "quark.core.dextraceapkinfo.disasm_method",
            return_value=fake_result,
        ):
            assert dextrace_instance._disasm_by_sig(self.SIG) is None
        dextrace_instance._disasm_by_sig.cache_clear()


# ---------------------------------------------------------------------------
# _build_graph offset fallback (missing invoke offset for a caller)
# ---------------------------------------------------------------------------


class TestBuildGraphMissingOffsetFallback:
    """Regression test for _build_graph's missing-offset fallback path.

    When any call in a caller's call list is missing an "offset", _build_
    graph must log a warning and keep DexTrace's original per-caller call
    order instead of raising or guessing an offset-based order.
    """

    def test_missing_offset_falls_back_to_original_order_and_warns(
        self, dextrace_instance, caplog
    ):
        caller_sig = "Lcom/example/RegressionCaller;->missingOffset()V"
        callee_a = "Lcom/example/RegressionCalleeA;->a()V"
        callee_b = "Lcom/example/RegressionCalleeB;->b()V"

        api_calls = [
            {
                "caller_sig": caller_sig,
                "callee_sig": callee_a,
                "offset": 10,
            },
            {
                "caller_sig": caller_sig,
                "callee_sig": callee_b,
                # No offset for this call -> the whole caller must fall
                # back to original order instead of offset-based sorting.
            },
        ]

        from quark.core.dextraceapkinfo import log as dextrace_log

        with caplog.at_level("WARNING", logger="quark.core.dextraceapkinfo"):
            with patch.object(dextrace_log, "disabled", False):
                dextrace_instance._build_graph(api_calls)

        assert "falling back to original call order" in caplog.text

        caller_mo = dextrace_instance._sig_to_method_object(caller_sig)
        callee_mo_a = dextrace_instance._sig_to_method_object(callee_a)
        callee_mo_b = dextrace_instance._sig_to_method_object(callee_b)

        ordered_callees = [
            mo for mo, _ in dextrace_instance._calls_by_caller[caller_mo]
        ]
        assert ordered_callees == [callee_mo_a, callee_mo_b]
