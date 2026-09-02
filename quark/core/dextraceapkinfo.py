# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/ev-flow/quark-engine
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import functools
import logging
import os
import re
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from os import PathLike
from typing import DefaultDict
from collections.abc import Generator, Iterable

from quark import config
from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.logger import defaultHandler
from quark.utils.tools import descriptor_to_androguard_format

# DexTrace public API (NO CLI fallback)
# You said: api.py is DexTrace’s external interface.
from dextrace.api import (  # type: ignore
    DextraceApiOptions,
    disasm_method,
    extract_abstract_methods,
    extract_api_calls,
    extract_class_hierarchy,
    extract_declared_methods,
    extract_strings,
    parse_manifest,
)

# ---- Compatibility cache object (MethodObject.cache) ----
@dataclass(frozen=True)
class DextraceMethodCache:
    """
    Minimal fields Quark/MethodObject may access.
    """
    full_name: str
    external: bool
    is_android_api: bool


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(defaultHandler)
log.disabled = not config.DEBUG

# Shared default for classes with no DEX-derived hierarchy entry
# (external/framework classes). Every Java class ultimately extends Object.
# Never mutate — shared across every unresolved-class lookup.
_OBJECT_ONLY_PARENT: set[str] = {"Ljava/lang/Object;"}


class DexTraceImp(BaseApkinfo):
    """
    DexTrace-based Apkinfo backend.

    - Call graph source: dextrace.api.extract_api_calls() (pure function)
    - Evidence source:  dextrace.api.disasm_method() (pure function)
    - Permissions:      dextrace.api.get_apk_permissions() (pure function)

    NO CLI fallback.
    """

    def __init__(
        self,
        apk_filepath: str | PathLike,
        tmp_dir: str | PathLike | None = None,
        *,
        api_options: DextraceApiOptions | None = None,
        enable_disasm: bool = True,
        debug: bool = False,
    ):
        import tempfile

        self._patched_tmp: str | None = None
        super().__init__(apk_filepath, "dextrace", tmp_dir)

        # BaseApkinfo.patch() rewrote self.data (mmap copy) in-place.
        # DexTrace API only accepts file paths, so write the patched bytes to a
        # temp file and point all DexTrace calls there.
        if self.isPatched and self.ret_type == "APK":
            fd, self._patched_tmp = tempfile.mkstemp(suffix=".apk")
            try:
                os.write(fd, self.data[:])
            finally:
                os.close(fd)  # close fd; file remains on disk until __del__

        self._target_path = self._patched_tmp if self._patched_tmp else str(apk_filepath)
        self._options = api_options or DextraceApiOptions()
        self._enable_disasm = bool(enable_disasm)
        self._debug = bool(debug)

        # Permissions (APK mode only). parse_manifest() raises ValueError on
        # unreadable manifest so Quark exits fast (trickmo/tanglebot pattern).
        self._permissions: list[str] = []
        if self.ret_type == "APK":
            self._permissions = list(
                parse_manifest(self._target_path).get("permissions", [])
            )

        # registries
        self._method_by_sig: dict[tuple[str, str, str], MethodObject] = {}

        # Quark graph structures
        self._calls_by_caller: DefaultDict[MethodObject, list[tuple[MethodObject, int]]] = defaultdict(list)
        self._callers_by_callee: DefaultDict[MethodObject, set[MethodObject]] = defaultdict(set)

        # Helper: signature-indexed ordered callees (for evidence)
        self._calls_by_caller_sig: DefaultDict[str, list[tuple[str, int]]] = defaultdict(list)

        # Build call graph from DexTrace api.
        # extract_api_calls() triggers _all_dex_data_cached(), which performs a
        # single class_def_item scan and caches api_calls, abstract_methods, and
        # parent_map together.  The extract_abstract_methods() call below is a
        # cache hit — no ZIP re-open, no second DEX pass.
        dex_report = extract_api_calls(self._target_path, options=self._options)
        api_calls = self._extract_api_calls(dex_report)
        self._build_graph(api_calls)
        
        # Register abstract methods
        self._register_abstract_methods()

        # Register a concrete method with no outgoing calls and no
        # visible caller within the same DEX(es)
        self._register_no_caller_callee_methods()

        # Class-keyed index so find_method() avoids O(|all_methods|) scans
        self._methods_by_class: DefaultDict[str, list[MethodObject]] = defaultdict(list)
        for _mo in self._method_by_sig.values():
            self._methods_by_class[_mo.class_name].append(_mo)

    def _register_no_caller_callee_methods(self):
        """Register declared methods invisible to the call graph.

        extract_api_calls() only sees invoke-* bytecode targets, and
        _register_abstract_methods() only sees code_off==0 declarations.
        A concrete method with no outgoing calls and no visible caller
        within the same DEX(es) (e.g. an interface-callback override like
        HostnameVerifier.verify()) is invisible to both, so this walks
        every declared method up front to fill in the rest. Runs off the
        already-cached DexTrace scan (no extra ZIP open or class_def_item
        pass), and keeps all_methods/android_apis/custom_methods correct
        from the start regardless of access order.
        """
        for sig in extract_declared_methods(self._target_path):
            self._sig_to_method_object(sig)

    def __del__(self):
        if self._patched_tmp:
            with suppress(Exception):
                os.unlink(self._patched_tmp)

    # ---------- Basic metadata ----------
    @property
    def permissions(self) -> list[str]:
        return self._permissions

    # ---------- Method sets ----------
    @functools.cached_property
    def all_methods(self) -> set[MethodObject]:
        return set(self._method_by_sig.values())

    @functools.cached_property
    def android_apis(self) -> set[MethodObject]:
        return {m for m in self.all_methods if m.cache.is_android_api}

    @functools.cached_property
    def custom_methods(self) -> set[MethodObject]:
        return {m for m in self.all_methods if not m.cache.external}

    # ---------- Find method ----------
    @functools.lru_cache
    def find_method(
        self,
        class_name: str | None = None,
        method_name: str | None = None,
        descriptor: str | None = None,
    ) -> list[MethodObject]:
        if class_name:
            normalized_class = self._normalize_class(class_name)
            candidates: Iterable[MethodObject] = self._methods_by_class.get(normalized_class, [])
        else:
            candidates = self._method_by_sig.values()
        if method_name:
            candidates = (m for m in candidates if m.name == method_name)
        if descriptor:
            candidates = (m for m in candidates if m.descriptor == descriptor)
        return list(candidates)

    # ---------- XREFs ----------
    @functools.lru_cache
    def upperfunc(self, method_object: MethodObject) -> set[MethodObject]:
        return set(self._callers_by_callee.get(method_object, set()))

    @functools.lru_cache
    def lowerfunc(self, method_object: MethodObject) -> list[tuple[MethodObject, int]]:
        # Second element is call-order (0..n-1), stable and per-caller
        return list(self._calls_by_caller.get(method_object, []))

    # ---------- Bytecode ----------
    def _yield_bytecode_from_json(self, ins_json: list[dict]) -> Generator[BytecodeObject]:
        for ins in ins_json:
            smali = (ins.get("smali") or "").strip()
            if not smali or smali.startswith(":"):
                continue
            try:
                yield self._parse_smali_to_bytecodeobject(smali)
            except Exception:
                continue

    def get_method_bytecode(self, method_object: MethodObject) -> Generator[BytecodeObject]:
        """
        Best-effort for Quark stage-5 evidence/reporting.
        We convert smali lines to BytecodeObject.

        Fast path: methods that appear as callers in the DexTrace call graph
        definitely have DEX bytecode.  Yield a no-op sentinel FIRST so that
        callers who only check `next(..., None)` (e.g. find_api_usage) short-
        circuit without triggering the expensive disasm call.  Full consumers
        (e.g. _evaluate_method) iterate past the sentinel and get real opcodes.
        """
        if method_object in self._calls_by_caller:
            yield BytecodeObject("", None, "")  # sentinel — signals "has bytecode"

        ins_json = self._get_method_instructions_json(method_object)
        if ins_json:
            yield from self._yield_bytecode_from_json(ins_json)

    def get_strings(self) -> set[str]:
        return set(extract_strings(self._target_path))

    @functools.cached_property
    def superclass_relationships(self) -> dict[str, set[str]]:
        # extract_class_hierarchy() reads from the _all_dex_data_cached() result
        # that was already populated by extract_api_calls() in __init__ — no ZIP
        # re-open and no second class_def_item scan. It returns one fresh set
        # per class already, so no accumulation is needed here.
        #
        # External classes (not defined in this DEX) get no entry; default
        # them to Object instead of a lookup dead end.
        return defaultdict(
            lambda: _OBJECT_ONLY_PARENT,
            extract_class_hierarchy(self._target_path),
        )

    @functools.cached_property
    def subclass_relationships(self) -> dict[str, set[str]]:
        result: DefaultDict[str, set[str]] = defaultdict(set)
        for cls, supers in self.superclass_relationships.items():
            for superclass in supers:
                result[superclass].add(cls)
        return result

    # ---------- Evidence / wrapper smali ----------
    @functools.lru_cache
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> dict[str, object]:
        """
        Quark evidence expects:
          first  = [mnemonic, "L...;->callee(...)R"]
          second = [mnemonic, "L...;->callee(...)R"]
        (NOT Quark's spaced full_name)
        """
        parent_sig = self._methodobject_to_dextrace_sig(parent_method)
        calls = self._calls_by_caller_sig.get(parent_sig, [])

        first_idx = None
        second_idx = None

        first_sig = self._methodobject_to_dextrace_sig(first_method)
        second_sig = self._methodobject_to_dextrace_sig(second_method)

        for i, (callee_sig, _order) in enumerate(calls):
            if first_idx is None and callee_sig == first_sig:
                first_idx = i
            if first_idx is not None and callee_sig == second_sig:
                second_idx = i
                break

        # IMPORTANT: always use dextrace sig as callee signature in evidence
        first_callee_sig = self._method_sig_to_androguard_format(first_sig)
        second_callee_sig = self._method_sig_to_androguard_format(second_sig)

        # default fallback
        first_line = ["invoke", first_callee_sig]
        second_line = ["invoke", second_callee_sig]
        first_hex = ""
        second_hex = ""

        first_context: list[dict] = []
        second_context: list[dict] = []
        first_context_smali: list[str] = []
        second_context_smali: list[str] = []

        def _it_smali(it: dict) -> str:
            return (it.get("smali") or "").strip()

        def _it_hex(it: dict) -> str:
            h = it.get("raw_hex") or it.get("hex") or it.get("bytes") or it.get("insn_hex")
            return (h or "").strip()

        def _it_off(it: dict) -> int | None:
            v = it.get("offset")
            if v is None:
                return None
            try:
                return int(v)
            except Exception:
                return None

        def _it_byte_off(it: dict) -> int | None:
            v = it.get("byte_off") or it.get("byteOff")
            if v is None:
                return None
            try:
                return int(v)
            except Exception:
                return None

        ins_json = self._get_method_instructions_json(parent_method)
        if ins_json:
            n1 = self._WHITESPACE_RE.sub("", first_callee_sig or "")
            n2 = self._WHITESPACE_RE.sub("", second_callee_sig or "")
            i1 = None
            i2 = None
            for j, it in enumerate(ins_json):
                s = _it_smali(it)
                if not s or s.startswith(":"):
                    continue
                ns = self._WHITESPACE_RE.sub("", s)
                if i1 is None and n1 and n1 in ns:
                    i1 = j
                if i2 is None and n2 and n2 in ns:
                    i2 = j
                if i1 is not None and i2 is not None:
                    break

            def _make_ctx(center: int, window: int) -> tuple[list[dict], list[str]]:
                a = max(0, center - window)
                b = min(len(ins_json), center + window + 1)
                ctx_dicts: list[dict] = []
                ctx_smali: list[str] = []
                for k in range(a, b):
                    it = ins_json[k]
                    s = _it_smali(it)
                    if not s:
                        continue
                    ctx_smali.append(s)
                    ctx_dicts.append(
                        {
                            "smali": s,
                            "hex": _it_hex(it),
                            "offset": _it_off(it),
                            "byte_off": _it_byte_off(it),
                        }
                    )
                return ctx_dicts, ctx_smali

            window = int(getattr(self._options, "disasm_context_window", 2) or 2)

            if i1 is not None:
                s1 = _it_smali(ins_json[i1])
                if s1 and not s1.startswith(":"):
                    bc1 = self._parse_smali_to_bytecodeobject(s1)
                    first_line = [bc1.mnemonic, *(bc1.registers or []), first_callee_sig]
                first_hex = _it_hex(ins_json[i1]) or ""
                first_context, first_context_smali = _make_ctx(i1, window=window)

            if i2 is not None:
                s2 = _it_smali(ins_json[i2])
                if s2 and not s2.startswith(":"):
                    bc2 = self._parse_smali_to_bytecodeobject(s2)
                    second_line = [bc2.mnemonic, *(bc2.registers or []), second_callee_sig]
                second_hex = _it_hex(ins_json[i2]) or ""
                second_context, second_context_smali = _make_ctx(i2, window=window)

        return {
            "first": first_line,
            "first_hex": first_hex,
            "second": second_line,
            "second_hex": second_hex
        }

    # =========================
    # Internal helpers
    # =========================

    def _extract_api_calls(self, dex_report: dict) -> list[dict]:
        """
        Accept these containers:
        - {"dex": {"api_calls": [...]}}
        - {"dex": {"apiCalls": [...]}}
        - {"api_calls": [...]}
        - {"apiCalls": [...]}
        """
        if not isinstance(dex_report, dict):
            return []

        root = dex_report
        if isinstance(dex_report.get("dex"), dict):
            root = dex_report["dex"]

        for key in ("api_calls", "apiCalls", "apiCall", "calls"):
            calls = root.get(key)
            if isinstance(calls, list):
                # api.py already normalizes ApiCall -> dict
                return [c for c in calls if isinstance(c, dict)]

        if isinstance(root.get("result"), dict):
            rr = root["result"]
            for key in ("api_calls", "apiCalls", "calls"):
                calls = rr.get(key)
                if isinstance(calls, list):
                    return [c for c in calls if isinstance(c, dict)]

        return []

    def _build_graph(self, api_calls: list[dict]) -> None:
        """
        Build Quark graph using stable per-caller call order.

        Strategy:
        - Group by caller_sig
        - Sort by invoke offset/uoff/byte_off if present (best-effort)
        - Enumerate -> call order (0..n-1) for Quark lowerfunc()
        - Also populate _calls_by_caller_sig for evidence
        """
        def _pick(d: dict, *keys):
            for k in keys:
                if k in d and d.get(k) is not None:
                    return d.get(k)
            return None

        def _parse_dextrace_sig(sig: str) -> dict:
            """
            Parse into {"class":..., "method":..., "proto":...}
            Accept: Lpkg/name/Cls;->m(I)Z
            """
            s = (sig or "").strip()
            if not s:
                return {}
            s = self._WHITESPACE_RE.sub("", s)

            if "->" not in s:
                return {"class": s}

            cls, rest = s.split("->", 1)
            if "(" in rest:
                mname = rest.split("(", 1)[0]
                proto = "(" + rest.split("(", 1)[1]
            else:
                mname = rest
                proto = ""
            if not cls.startswith("L"):
                cls = "L" + cls
            if not cls.endswith(";") and ";" not in cls:
                cls = cls + ";"
            return {"class": cls, "method": mname, "proto": proto}

        def _extract_method_raw(call: dict, which: str) -> dict:
            if not isinstance(call, dict):
                return {}

            raw = call.get(which)
            if isinstance(raw, dict):
                return raw

            # TODO - Remove this after changing the default library
            # because DexTrace now don't produce these keys.
            raw = _pick(call, f"{which}_method", f"{which}Method", f"{which}_info", f"{which}Info")
            if isinstance(raw, dict):
                return raw

            # TODO - Remove this after changing the default library
            # because DexTrace now don't produce these keys.
            sig = _pick(call, f"{which}_sig", f"{which}Sig", f"{which}_signature", f"{which}Signature")
            if isinstance(sig, str) and sig.strip():
                return _parse_dextrace_sig(sig)

            return {}

        def _extract_offset(call: dict) -> int | None:
            if not isinstance(call, dict):
                return None

            inv = call.get("invoke")
            if isinstance(inv, dict):
                v = _pick(
                    inv,
                    "offset",
                    "uoff",
                    "insn_off",
                    "insnOff",
                    "byte_off",
                    "byteOff",
                    "idx",
                    "index",
                    "order",
                )
                if v is not None:
                    try:
                        return int(v)
                    except Exception:
                        pass

            v = _pick(
                call,
                "offset",
                "uoff",
                "insn_off",
                "byte_off",
                "idx",
                "index",
                "order",
                "invoke_offset",
                "invokeOffset",
            )
            if v is not None:
                try:
                    return int(v)
                except Exception:
                    pass
            return None

        per_caller: DefaultDict[str, list[tuple[int | None, str]]] = defaultdict(list)

        for call in api_calls:
            if not isinstance(call, dict):
                continue

            caller_raw = _extract_method_raw(call, "caller")
            callee_raw = _extract_method_raw(call, "callee")

            caller_mo = self._to_method_object(caller_raw or {})
            callee_mo = self._to_method_object(callee_raw or {})

            caller_sig = self._methodobject_to_dextrace_sig(caller_mo)
            callee_sig = self._methodobject_to_dextrace_sig(callee_mo)

            off = _extract_offset(call)
            per_caller[caller_sig].append((off, callee_sig))

        for caller_sig, items in per_caller.items():
            # If every call carries a real offset, sort by it
            # If any call is missing one, alert and keep DexTrace's original
            # per-caller call order instead of guessing.
            if any(off is None for off, _ in items):
                log.warning(
                    "DexTrace call report missing invoke offset for caller "
                    "%s; falling back to original call order for its %d "
                    "callees instead of offset-based sequencing.",
                    caller_sig,
                    len(items),
                )
                items_sorted = list(enumerate(items))
            else:
                items_sorted = sorted(enumerate(items), key=lambda x: int(x[1][0]))

            caller_mo = self._sig_to_method_object(caller_sig)

            for order, (_orig_idx, (off, callee_sig)) in enumerate(items_sorted):
                callee_mo = self._sig_to_method_object(callee_sig)

                reported_offset = int(off) if off is not None else int(order)

                self._calls_by_caller[caller_mo].append((callee_mo, reported_offset))
                self._callers_by_callee[callee_mo].add(caller_mo)

                self._calls_by_caller_sig[caller_sig].append((callee_sig, reported_offset))

    def _register_abstract_methods(self) -> None:
        """Register abstract/interface method declarations into _method_by_sig.

        extract_api_calls() only sees invoke-* bytecode targets, so abstract
        methods (code_off=0) never appear as callees and are absent from the
        call graph.  Quark's find_api_usage needs them as stepping-stones for
        subtype resolution (level-2/3 combination check).

        This method reads from the cached _all_dex_data_cached() result — no
        ZIP re-open and no second class_def_item scan.
        """
        for sig in extract_abstract_methods(self._target_path):
            # _sig_to_method_object is idempotent: returns existing entry if present
            self._sig_to_method_object(sig)

    def _create_method_object(self, cls: str, name: str, desc: str) -> MethodObject:
        key = (cls, name, desc)
        if key in self._method_by_sig:
            return self._method_by_sig[key]
        full_name = f"{cls}->{name}{desc}"
        external = self._is_external_class(cls)
        is_android_api = self._is_android_api_class(cls)
        cache = DextraceMethodCache(full_name=full_name, external=external, is_android_api=is_android_api)
        mo = MethodObject(class_name=cls, name=name, descriptor=desc, cache=cache)
        self._method_by_sig[key] = mo
        return mo

    def _sig_to_method_object(self, dextrace_sig: str) -> MethodObject:
        """
        Create/find a MethodObject from a DexTrace method signature:
          Lpkg/name/Class;->method(Args)Ret
        """
        sig = self._normalize_dextrace_sig(dextrace_sig)

        m = re.match(r"^(L[^;]+;)->([^(]+)(\(.*\).*)$", sig)
        if not m:
            cls = ""
            name = sig
            desc = ""
        else:
            cls = m.group(1)
            name = m.group(2)
            desc = m.group(3)

        desc = self._normalize_descriptor(desc)
        return self._create_method_object(cls, name, desc)

    def _to_method_object(self, raw: dict) -> MethodObject:
        """
        Normalize raw method dict to Quark MethodObject.
        Accept flexible key names.
        """
        if not isinstance(raw, dict):
            raw = {}

        cls = raw.get("class") or raw.get("class_name") or raw.get("clazz") or ""
        name = raw.get("method") or raw.get("name") or raw.get("method_name") or ""
        desc = raw.get("descriptor") or raw.get("proto") or raw.get("signature") or ""

        cls = self._normalize_class(str(cls))
        desc = self._normalize_descriptor(str(desc))
        return self._create_method_object(cls, str(name), desc)

    def _normalize_class(self, cls: str) -> str:
        cls = str(cls).strip()
        if not cls:
            return cls
        if cls.startswith("L") and cls.endswith(";"):
            return cls.replace(".", "/")
        if cls.startswith("L") and not cls.endswith(";"):
            return f"{cls};"
        if "/" in cls and not cls.startswith("L"):
            return f"L{cls};"
        return f"L{cls.replace('.', '/')};"

    def _normalize_descriptor(self, desc: str) -> str:
        desc = str(desc).strip()
        if not desc:
            return desc
        if "(" in desc and ")" in desc:
            try:
                # Quark uses androguard-format descriptors with spaces
                return descriptor_to_androguard_format(desc.replace(" ", ""))
            except Exception:
                return desc
        return desc

    def _normalize_dextrace_sig(self, sig: str) -> str:
        return self._WHITESPACE_RE.sub("", str(sig))

    def _methodobject_to_dextrace_sig(self, mo: MethodObject) -> str:
        """
        Convert Quark MethodObject to DexTrace signature (no spaces):
          Lcls;->name(Args)Ret
        """
        cls = (mo.class_name or "").strip()
        name = (mo.name or "").strip()
        desc = (mo.descriptor or "").strip()

        desc = self._WHITESPACE_RE.sub("", desc)
        cls = self._normalize_class(cls)
        return f"{cls}->{name}{desc}"

    def _is_android_api_class(self, cls: str) -> bool:
        # Android framework + Java/Kotlin stdlib
        return cls.startswith("Landroid/") or cls.startswith("Ljava/") or cls.startswith("Ljavax/") or cls.startswith(
            "Lkotlin/"
        )

    def _is_external_class(self, cls: str) -> bool:
        # Conservative: framework/stdlib are external.
        return self._is_android_api_class(cls)

    # -------- Disasm integration (DexTrace api) --------

    @functools.lru_cache(maxsize=4096)
    def _disasm_by_sig(self, dextrace_sig: str) -> list[dict] | None:
        """
        Cached disasm result by DexTrace signature.
        Returns list[dict] like:
          [{"offset":..,"byte_off":..,"smali":"...","raw_hex":"..."} ...] or None.
        """
        if not self._enable_disasm:
            return None

        sig = self._normalize_dextrace_sig(dextrace_sig)
        if self._debug:
            print("[dextrace api disasm]", sig)

        try:
            out = disasm_method(self._target_path, sig, options=self._options)
        except Exception:
            return None

        methods = out.get("methods")
        if not isinstance(methods, dict):
            return None

        m = methods.get(sig)
        if not isinstance(m, dict):
            # fallback: try normalized key match
            for k, v in methods.items():
                if isinstance(k, str) and self._normalize_dextrace_sig(k) == sig and isinstance(v, dict):
                    m = v
                    break
            if not isinstance(m, dict):
                return None

        ins = m.get("instructions")
        if not isinstance(ins, list):
            return None

        out_list: list[dict] = []
        for it in ins:
            if isinstance(it, dict) and "smali" in it:
                out_list.append(it)
        return out_list or None

    def _get_method_instructions_json(self, method_object: MethodObject) -> list[dict] | None:
        sig = self._methodobject_to_dextrace_sig(method_object)
        return self._disasm_by_sig(sig)

    # -------- Small smali parser --------
    _SMALI_SPLIT_RE = re.compile(r"[{},]+")
    _WHITESPACE_RE = re.compile(r"\s+")

    @staticmethod
    def _strip_smali_comment(smali: str) -> str:
        idx = smali.find("//")
        if idx == -1:
            return smali.strip()
        if smali[:idx].count('"') % 2 == 0:
            return smali[:idx].strip()
        in_string = False
        for i, c in enumerate(smali):
            if c == '"':
                in_string = not in_string
            elif not in_string and smali[i:i+2] == '//':
                return smali[:i].strip()
        return smali.strip()

    @staticmethod
    def _method_sig_to_androguard_format(sig: str) -> str:
        # sig is "Lcls;->name(Args)Ret" with no spaces between args;
        # reformat the descriptor part to androguard style (spaced args).
        # Not a method signature (no "->"/"(") — return unchanged.
        if not sig or "->" not in sig or "(" not in sig:
            return sig
        try:
            cls, rest = sig.split("->", 1)
            name, _, tail = rest.partition("(")
            proto = ("(" + tail).replace(" ", "")
            return f"{cls}->{name}{descriptor_to_androguard_format(proto)}"
        except Exception:
            # if anything fails, keep raw signature
            return sig

    def _parse_smali_to_bytecodeobject(self, smali: str) -> BytecodeObject:
        smali = self._strip_smali_comment(smali)
        if not smali:
            raise ValueError("Empty smali")

        if " " not in smali:
            return BytecodeObject(smali, None, None)

        mnemonic, args_str = smali.split(maxsplit=1)
        args = [a.strip() for a in self._SMALI_SPLIT_RE.split(args_str) if a.strip()]

        regs: list[str] = []
        params: list[str] = []
        for a in args:
            if a.startswith(("v", "p")):
                regs.append(a)
            else:
                params.append(a)

        parameter = params[-1] if params else None

        # smali string literals keep their surrounding quotes (e.g. "wifi");
        # androguard's operand values are the raw string with no quotes, so
        # strip them here to match that convention.
        if parameter and len(parameter) >= 2 and parameter[0] == '"' and parameter[-1] == '"':
            parameter = (
                parameter[1:-1]
                .replace('\\"', '"')
                .replace('\\n', '\n')
                .replace('\\t', '\t')
                .replace('\\\\', '\\')
            )

        # const/const-wide family and the /lit8 /lit16 arithmetic family
        # (e.g. add-int/lit8, rsub-int) carry a numeric literal (const-string
        # and const-class are handled above/below instead) — androguard's
        # operand value is an int, so parse smali's textual literal (decimal
        # or 0x-hex, with an optional 'L' wide-literal suffix) the same way.
        if (
            parameter is not None
            and (
                (
                    mnemonic.startswith("const")
                    and not mnemonic.startswith(("const-string", "const-class"))
                )
                or "/lit" in mnemonic
                or mnemonic.startswith("rsub-int")
            )
        ):
            try:
                parameter = int(parameter.rstrip("Ll"), 0)
            except (TypeError, ValueError):
                pass

        # ---- IMPORTANT: normalize invoke parameter to Quark/Androguard style ----
        # smali invoke last arg is usually: Lcls;->m(Args)Ret
        # Quark pattern in rules often uses androguard format with spaces:
        #   Lcls; m (ArgsWithSpaces)Ret
        if parameter and mnemonic.startswith("invoke-"):
            parameter = self._method_sig_to_androguard_format(parameter)

        # ---- normalize field parameter to Quark/Androguard style ----
        # smali field access last arg is: Lcls;->field:Type
        # Androguard format uses a space instead of the colon: Lcls;->field Type
        if (
            parameter
            and mnemonic.startswith(("iget", "iput", "sget", "sput"))
            and "->" in parameter
            and ":" in parameter.split("->", 1)[1]
        ):
            cls, rest = parameter.split("->", 1)
            fname, ftype = rest.split(":", 1)
            parameter = f"{cls}->{fname} {ftype}"

        return BytecodeObject(mnemonic, regs, parameter)
