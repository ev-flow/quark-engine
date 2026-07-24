# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/ev-flow/quark-engine
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import functools
import re
from collections import defaultdict
from dataclasses import dataclass
from os import PathLike
from typing import DefaultDict, Dict, Generator, Iterable, List, Optional, Set, Tuple

from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import descriptor_to_androguard_format

# DexTrace public API (NO CLI fallback)
# You said: api.py is DexTrace’s external interface.
from dextrace.api import (  # type: ignore
    DextraceApiOptions,
    disasm_method,
    extract_api_calls,
    get_apk_permissions,
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
        tmp_dir: str | PathLike = None,
        *,
        api_options: Optional[DextraceApiOptions] = None,
        enable_disasm: bool = True,
        debug: bool = False,
    ):
        super().__init__(apk_filepath, "dextrace", tmp_dir)

        self._target_path = str(apk_filepath)
        self._options = api_options or DextraceApiOptions()
        self._enable_disasm = bool(enable_disasm)
        self._debug = bool(debug)

        # Permissions (APK mode only) via DexTrace api
        self._permissions: List[str] = []
        if self.ret_type == "APK":
            try:
                self._permissions = list(get_apk_permissions(self._target_path))
            except Exception:
                self._permissions = []

        # registries
        self._method_by_sig: Dict[Tuple[str, str, str], MethodObject] = {}

        # Quark graph structures
        self._calls_by_caller: DefaultDict[MethodObject, List[Tuple[MethodObject, int]]] = defaultdict(list)
        self._callers_by_callee: DefaultDict[MethodObject, Set[MethodObject]] = defaultdict(set)

        # Helper: signature-indexed ordered callees (for evidence)
        self._calls_by_caller_sig: DefaultDict[str, List[Tuple[str, int]]] = defaultdict(list)

        # Build call graph from DexTrace api
        dex_report = extract_api_calls(self._target_path, options=self._options)
        api_calls = self._extract_api_calls(dex_report)
        self._build_graph(api_calls)

    # ---------- Basic metadata ----------
    @property
    def permissions(self) -> List[str]:
        return self._permissions

    # ---------- Method sets ----------
    @functools.cached_property
    def all_methods(self) -> Set[MethodObject]:
        return set(self._method_by_sig.values())

    @property
    def android_apis(self) -> Set[MethodObject]:
        return {m for m in self.all_methods if getattr(m, "cache", None) and m.cache.is_android_api}

    @property
    def custom_methods(self) -> Set[MethodObject]:
        return {m for m in self.all_methods if getattr(m, "cache", None) and not m.cache.external}

    # ---------- Find method ----------
    @functools.lru_cache()
    def find_method(
        self,
        class_name: Optional[str] = None,
        method_name: Optional[str] = None,
        descriptor: Optional[str] = None,
    ) -> List[MethodObject]:
        methods: Iterable[MethodObject] = self.all_methods
        if class_name:
            methods = (m for m in methods if m.class_name == class_name)
        if method_name:
            methods = (m for m in methods if m.name == method_name)
        if descriptor:
            methods = (m for m in methods if m.descriptor == descriptor)
        return list(methods)

    # ---------- XREFs ----------
    @functools.lru_cache()
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        return set(self._callers_by_callee.get(method_object, set()))

    @functools.lru_cache()
    def lowerfunc(self, method_object: MethodObject) -> List[Tuple[MethodObject, int]]:
        # Second element is call-order (0..n-1), stable and per-caller
        return list(self._calls_by_caller.get(method_object, []))

    # ---------- Bytecode ----------
    def get_method_bytecode(self, method_object: MethodObject) -> Generator[BytecodeObject, None, None]:
        """
        Best-effort for Quark stage-5 evidence/reporting.
        We convert smali lines to BytecodeObject.
        """
        ins_json = self._get_method_instructions_json(method_object)
        if not ins_json:
            return
        for ins in ins_json:
            smali = (ins.get("smali") or "").strip()
            if not smali or smali.startswith(":"):
                continue
            try:
                yield self._parse_smali_to_bytecodeobject(smali)
            except Exception:
                continue

    def get_strings(self) -> Set[str]:
        return set()

    @property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        return defaultdict(set)

    @property
    def subclass_relationships(self) -> Dict[str, Set[str]]:
        return defaultdict(set)

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
        first_callee_sig = first_sig
        second_callee_sig = second_sig

        # default fallback
        first_line = ["invoke", first_callee_sig]
        second_line = ["invoke", second_callee_sig]
        first_hex = ""
        second_hex = ""

        first_context: List[dict] = []
        second_context: List[dict] = []
        first_context_smali: List[str] = []
        second_context_smali: List[str] = []

        def _it_smali(it: dict) -> str:
            return (it.get("smali") or "").strip()

        def _it_hex(it: dict) -> str:
            h = it.get("raw_hex") or it.get("hex") or it.get("bytes") or it.get("insn_hex")
            return (h or "").strip()

        def _it_off(it: dict) -> Optional[int]:
            v = it.get("offset")
            if v is None:
                return None
            try:
                return int(v)
            except Exception:
                return None

        def _it_byte_off(it: dict) -> Optional[int]:
            v = it.get("byte_off") or it.get("byteOff")
            if v is None:
                return None
            try:
                return int(v)
            except Exception:
                return None

        ins_json = self._get_method_instructions_json(parent_method)
        if ins_json:

            def _norm(s: str) -> str:
                # remove ALL whitespace for robust matching
                return re.sub(r"\s+", "", s or "")

            def _find_line_idx(needle_sig: str) -> Optional[int]:
                n = _norm(needle_sig)
                if not n:
                    return None
                for j, it in enumerate(ins_json):
                    s = _it_smali(it)
                    if not s or s.startswith(":"):
                        continue
                    if n in _norm(s):
                        return j
                return None

            i1 = _find_line_idx(first_callee_sig)
            i2 = _find_line_idx(second_callee_sig)

            def _make_ctx(center: int, window: int) -> Tuple[List[dict], List[str]]:
                a = max(0, center - window)
                b = min(len(ins_json), center + window + 1)
                ctx_dicts: List[dict] = []
                ctx_smali: List[str] = []
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
                    first_line = [s1.split()[0], first_callee_sig]
                first_hex = _it_hex(ins_json[i1]) or ""
                first_context, first_context_smali = _make_ctx(i1, window=window)

            if i2 is not None:
                s2 = _it_smali(ins_json[i2])
                if s2 and not s2.startswith(":"):
                    second_line = [s2.split()[0], second_callee_sig]
                second_hex = _it_hex(ins_json[i2]) or ""
                second_context, second_context_smali = _make_ctx(i2, window=window)

        return {
            "first": first_line,
            "first_hex": first_hex,
            "second": second_line,
            "second_hex": second_hex,
            "meta": {
                "parent": parent_sig,
                "first_call_order": first_idx,
                "second_call_order": second_idx,
                "first_context": first_context,
                "second_context": second_context,
                "first_context_smali": first_context_smali,
                "second_context_smali": second_context_smali,
                "note": "Evidence from DexTrace api disasm_method(). Callee signatures forced to L...;->m(...)R form.",
            },
        }

    # =========================
    # Internal helpers
    # =========================

    def _extract_api_calls(self, dex_report: dict) -> List[dict]:
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

    def _build_graph(self, api_calls: List[dict]) -> None:
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
            s = re.sub(r"\s+", "", s)

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

            raw = _pick(call, f"{which}_method", f"{which}Method", f"{which}_info", f"{which}Info")
            if isinstance(raw, dict):
                return raw

            sig = _pick(call, f"{which}_sig", f"{which}Sig", f"{which}_signature", f"{which}Signature")
            if isinstance(sig, str) and sig.strip():
                return _parse_dextrace_sig(sig)

            return {}

        def _extract_offset(call: dict) -> Optional[int]:
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

        per_caller: DefaultDict[str, List[Tuple[Optional[int], str]]] = defaultdict(list)

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
            # stable sort: offset-present first (ascending), then missing; keep original order as tiebreaker
            items_sorted = sorted(
                enumerate(items),
                key=lambda x: (x[1][0] is None, x[1][0] if x[1][0] is not None else 0, x[0]),
            )

            caller_mo = self._sig_to_method_object(caller_sig)

            for order, (_orig_idx, (_off, callee_sig)) in enumerate(items_sorted):
                callee_mo = self._sig_to_method_object(callee_sig)

                self._calls_by_caller[caller_mo].append((callee_mo, int(order)))
                self._callers_by_callee[callee_mo].add(caller_mo)

                self._calls_by_caller_sig[caller_sig].append((callee_sig, int(order)))

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

        key = (cls, str(name), desc)
        if key in self._method_by_sig:
            return self._method_by_sig[key]

        full_name = f"{cls}->{name}{desc}"
        external = self._is_external_class(cls)
        is_android_api = self._is_android_api_class(cls)
        cache = DextraceMethodCache(full_name=full_name, external=external, is_android_api=is_android_api)
        mo = MethodObject(class_name=cls, name=str(name), descriptor=desc, cache=cache)
        self._method_by_sig[key] = mo
        return mo

    def _normalize_class(self, cls: str) -> str:
        cls = str(cls).strip()
        if not cls:
            return cls
        if cls.startswith("L") and cls.endswith(";"):
            return cls.replace(".", "/")
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
        return re.sub(r"\s+", "", str(sig))

    def _methodobject_to_dextrace_sig(self, mo: MethodObject) -> str:
        """
        Convert Quark MethodObject to DexTrace signature (no spaces):
          Lcls;->name(Args)Ret
        """
        cls = (mo.class_name or "").strip()
        name = (mo.name or "").strip()
        desc = (mo.descriptor or "").strip()

        desc = re.sub(r"\s+", "", desc)
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
    def _disasm_by_sig(self, dextrace_sig: str) -> Optional[List[dict]]:
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

        out_list: List[dict] = []
        for it in ins:
            if isinstance(it, dict) and "smali" in it:
                out_list.append(it)
        return out_list or None

    def _get_method_instructions_json(self, method_object: MethodObject) -> Optional[List[dict]]:
        sig = self._methodobject_to_dextrace_sig(method_object)
        return self._disasm_by_sig(sig)

    # -------- Small smali parser --------
    _SMALI_SPLIT_RE = re.compile(r"[{},]+")

    def _parse_smali_to_bytecodeobject(self, smali: str) -> BytecodeObject:
        smali = smali.rsplit("//", maxsplit=1)[0].strip()
        if not smali:
            raise ValueError("Empty smali")

        if " " not in smali:
            return BytecodeObject(smali, None, None)

        mnemonic, args_str = smali.split(maxsplit=1)
        args = [a.strip() for a in self._SMALI_SPLIT_RE.split(args_str) if a.strip()]

        regs: List[str] = []
        params: List[str] = []
        for a in args:
            if a.startswith(("v", "p")):
                regs.append(a)
            else:
                params.append(a)

        parameter = params[-1] if params else None

        # ---- IMPORTANT: normalize invoke parameter to Quark/Androguard style ----
        # smali invoke last arg is usually: Lcls;->m(Args)Ret
        # Quark pattern in rules often uses androguard format with spaces:
        #   Lcls; m (ArgsWithSpaces)Ret
        if parameter and mnemonic.startswith("invoke-") and "->" in parameter and "(" in parameter:
            try:
                cls, rest = parameter.split("->", 1)
                mname = rest.split("(", 1)[0]
                proto = "(" + rest.split("(", 1)[1]  # includes return type
                proto = proto.replace(" ", "")
                # make it androguard-format (adds spaces between params)
                proto_fmt = descriptor_to_androguard_format(proto)
                # match Quark's common printing style: "Lcls; method (..).."
                parameter = f"{cls}->{mname}{proto_fmt}"
            except Exception:
                # if anything fails, keep raw parameter
                pass

        return BytecodeObject(mnemonic, regs or None, parameter)
