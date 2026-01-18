# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/ev-flow/quark-engine
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import functools
import json
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from os import PathLike
from typing import DefaultDict, Dict, Generator, Iterable, List, Optional, Set, Tuple

from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import descriptor_to_androguard_format

try:
    from androguard.core.bytecodes.apk import APK  # type: ignore
    _HAS_ANDROGUARD = True
except Exception:
    _HAS_ANDROGUARD = False


# ---- Compatibility cache object (MethodObject.cache) ----
@dataclass(frozen=True)
class DextraceMethodCache:
    """
    Provide minimal fields Quark/MethodObject may access.
    Keep it simple: we mainly need full_name/external/is_android_api.
    """
    full_name: str
    external: bool
    is_android_api: bool


class DexTraceImp(BaseApkinfo):
    """
    DexTrace-based Apkinfo backend.

    - Call graph source:
        dextrace dex --apis --json <APK/DEX>

      We accept schema variants:
        - {"dex": {"api_calls": [...]}}
        - {"api_calls": [...]}

      Each api_call item best-effort supports:
        - caller/callee dicts with class/method/descriptor (or name/proto/signature)
        - or caller_sig/callee_sig string fields

    - Evidence source (optional, best-effort):
        dextrace disasm <APK/DEX> --method <SIG>

      Expected output schema:
        {"methods": { "<sig>": {"instructions":[{"smali":...}, ...] } }, "errors": {...}}
    """

    def __init__(
        self,
        apk_filepath: str | PathLike,
        tmp_dir: str | PathLike = None,
        dextrace_bin: str = "dextrace",
        dextrace_dex_args: Optional[List[str]] = None,
        dextrace_disasm_args: Optional[List[str]] = None,
        enable_disasm: bool = True,
        debug: bool = False,
    ):
        super().__init__(apk_filepath, "dextrace", tmp_dir)
        self._target_path = str(apk_filepath)
        self._dextrace_bin = dextrace_bin

        # CLI args
        self._dextrace_dex_args = dextrace_dex_args or ["dex", "--apis", "--json"]
        self._dextrace_disasm_args = dextrace_disasm_args or ["disasm"]
        self._enable_disasm = bool(enable_disasm)
        self._debug = bool(debug)

        # Permissions (APK mode only)
        self._permissions: List[str] = []
        if self.ret_type == "APK":
            self._permissions = self._extract_permissions_apk(self._target_path)

        # Run DexTrace once to build call graph
        dex_json = self._run_dextrace_json([self._dextrace_bin, *self._dextrace_dex_args, self._target_path])
        self._api_calls = self._extract_api_calls(dex_json)

        # registries
        self._method_by_sig: Dict[Tuple[str, str, str], MethodObject] = {}
        # Quark API uses MethodObject
        self._calls_by_caller: DefaultDict[MethodObject, List[Tuple[MethodObject, int]]] = defaultdict(list)
        self._callers_by_callee: DefaultDict[MethodObject, Set[MethodObject]] = defaultdict(set)

        # for wrapper evidence, it is easier to use signature strings
        self._calls_by_caller_sig: DefaultDict[str, List[Tuple[str, int]]] = defaultdict(list)

        self._build_graph(self._api_calls)

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
        return list(self._calls_by_caller.get(method_object, []))

    # ---------- Bytecode ----------
    def get_method_bytecode(self, method_object: MethodObject) -> Generator[BytecodeObject, None, None]:
        # Optional for Quark stage 5; best-effort
        ins_json = self._get_method_instructions_json(method_object)
        if not ins_json:
            return
        for ins in ins_json:
            smali = (ins.get("smali") or "").strip()
            if not smali or smali.startswith(":"):
                continue
            yield self._parse_smali_to_bytecodeobject(smali)

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
        Quark uses this for reporting evidence (smali + hex).
        We try to give best-effort evidence using DexTrace disasm output.
        """
        parent_sig = self._methodobject_to_dextrace_sig(parent_method)
        calls = self._calls_by_caller_sig.get(parent_sig, [])

        first_idx = None
        second_idx = None

        first_sig = self._methodobject_to_dextrace_sig(first_method)
        second_sig = self._methodobject_to_dextrace_sig(second_method)

        for i, (callee_sig, _idx) in enumerate(calls):
            if first_idx is None and callee_sig == first_sig:
                first_idx = i
            if first_idx is not None and callee_sig == second_sig:
                second_idx = i
                break

        first_full = getattr(getattr(first_method, "cache", None), "full_name", first_method.full_name)
        second_full = getattr(getattr(second_method, "cache", None), "full_name", second_method.full_name)

        first_line = ["invoke", first_full]
        second_line = ["invoke", second_full]

        first_context: List[str] = []
        second_context: List[str] = []

        ins_json = self._get_method_instructions_json(parent_method)
        if ins_json:
            # Try to locate the exact call lines and provide a bit of context
            smalis = [(it.get("smali") or "").strip() for it in ins_json]
            # filter empty
            smalis = [s for s in smalis if s]

            def _find_line_idx(needle: str) -> Optional[int]:
                for j, s in enumerate(smalis):
                    if s.startswith(":"):
                        continue
                    if needle in s:
                        return j
                return None

            i1 = _find_line_idx(first_full)
            i2 = _find_line_idx(second_full) if i1 is not None else None

            if i1 is not None:
                first_line = [smalis[i1].split()[0], smalis[i1]]
                a = max(0, i1 - 2)
                b = min(len(smalis), i1 + 3)
                first_context = smalis[a:b]

            if i2 is not None:
                second_line = [smalis[i2].split()[0], smalis[i2]]
                a = max(0, i2 - 2)
                b = min(len(smalis), i2 + 3)
                second_context = smalis[a:b]

        return {
            "first": first_line,
            "first_hex": "",
            "second": second_line,
            "second_hex": "",
            "meta": {
                "parent": getattr(getattr(parent_method, "cache", None), "full_name", parent_method.full_name),
                "first_call_order": first_idx,
                "second_call_order": second_idx,
                "first_context": first_context,
                "second_context": second_context,
                "note": "Evidence from DexTrace disasm (context+hex best-effort).",
            },
        }

    # =========================
    # Internal helpers
    # =========================

    def _run_dextrace_json(self, cmd: List[str]) -> dict:
        try:
            p = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
        except FileNotFoundError as e:
            raise RuntimeError(
                f"DexTrace binary not found: {self._dextrace_bin}. "
                f"Set dextrace_bin=... or ensure it's in PATH."
            ) from e
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                "DexTrace failed.\n"
                f"CMD: {' '.join(cmd)}\n"
                f"STDERR:\n{(e.stderr or '')[:4000]}"
            ) from e

        try:
            return json.loads(p.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                "DexTrace output is not valid JSON.\n"
                f"First 2000 chars:\n{p.stdout[:2000]}"
            ) from e

    def _extract_api_calls(self, dex_json: dict) -> List[dict]:
        """
        Align to DexTrace field naming (best-effort, tolerant):

        Accept these containers:
        - {"dex": {"api_calls": [...]}}
        - {"dex": {"apiCalls": [...]}}
        - {"api_calls": [...]}
        - {"apiCalls": [...]}

        Return list of call dicts (possibly empty).
        """
        if not isinstance(dex_json, dict):
            return []

        # 1) unwrap dex root if present
        root = dex_json
        if isinstance(dex_json.get("dex"), dict):
            root = dex_json["dex"]

        # 2) common key variants
        for key in ("api_calls", "apiCalls", "apiCall", "calls"):
            calls = root.get(key)
            if isinstance(calls, list):
                return calls

        # 3) sometimes it's nested one more layer
        if isinstance(root.get("result"), dict):
            rr = root["result"]
            for key in ("api_calls", "apiCalls", "calls"):
                calls = rr.get(key)
                if isinstance(calls, list):
                    return calls

        return []


    def _build_graph(self, api_calls: List[dict]) -> None:
        """
        Build:
        - method registry
        - caller -> [(callee, order)]
        - callee -> {callers}

        Fully aligned to DexTrace variants:
        - caller/callee dict OR caller_sig/callee_sig string variants
        - offset variants: invoke.offset, offset, idx, index, order, invoke_idx...
        """

        def _pick(d: dict, *keys):
            for k in keys:
                if k in d and d.get(k) is not None:
                    return d.get(k)
            return None

        def _parse_dextrace_sig(sig: str) -> dict:
            """
            Parse these forms into {"class":..., "method":..., "proto":...}:
            - Lpkg/name/Cls;->m(I)Z
            - Lpkg/name/Cls; m (I)Z     (spaces tolerated)
            - Lpkg/name/Cls;-><init>(Lx;)V
            """
            s = (sig or "").strip()
            if not s:
                return {}

            # normalize spaces
            s = " ".join(s.split())

            # canonical: L...;->name(proto)ret
            if "->" in s:
                cls, rest = s.split("->", 1)
                cls = cls.strip()
                rest = rest.strip().replace(" ", "")
                if not cls.startswith("L"):
                    cls = "L" + cls
                if not cls.endswith(";"):
                    # allow "Lpkg/name/Cls" without ';'
                    if ";" in cls:
                        pass
                    else:
                        cls = cls + ";"

                if "(" in rest:
                    mname = rest.split("(", 1)[0]
                    proto = "(" + rest.split("(", 1)[1]
                else:
                    mname = rest
                    proto = ""
                return {"class": cls, "method": mname, "proto": proto}

            # non-canonical: "L...; name (..).."
            if ";" in s:
                semi = s.find(";")
                cls = s[: semi + 1].strip()
                rest = s[semi + 1 :].strip()

                # rest may be: "getSIMContactNumbers ()V" / "getSIMContactNumbers()V"
                rest_nospace = rest.replace(" ", "")
                if "(" in rest_nospace:
                    mname = rest_nospace.split("(", 1)[0]
                    proto = "(" + rest_nospace.split("(", 1)[1]
                else:
                    mname = rest_nospace
                    proto = ""
                return {"class": cls, "method": mname, "proto": proto}

            # last resort: treat whole string as class (rare)
            return {"class": s}

        def _extract_method_raw(call: dict, which: str) -> dict:
            """
            which in {"caller","callee"}.
            Priority:
            1) dict form: caller/callee
            2) dict alias: caller_method/callee_method, callerMethod/calleeMethod
            3) sig form: caller_sig/callee_sig, callerSig/calleeSig
            """
            if not isinstance(call, dict):
                return {}

            # dict direct
            raw = call.get(which)
            if isinstance(raw, dict):
                return raw

            # dict alias
            raw = _pick(
                call,
                f"{which}_method",
                f"{which}Method",
                f"{which}_info",
                f"{which}Info",
            )
            if isinstance(raw, dict):
                return raw

            # signature string variants
            sig = _pick(call, f"{which}_sig", f"{which}Sig", f"{which}_signature", f"{which}Signature")
            if isinstance(sig, str) and sig.strip():
                return _parse_dextrace_sig(sig)

            return {}

        def _extract_offset(call: dict) -> int:
            """
            DexTrace may place offset in:
            - call["invoke"]["offset"]
            - call["invoke"]["uoff"] / ["insn_off"] / ["index"] / ["idx"] / ["order"]
            - call["offset"] / ["idx"] / ["index"] / ["order"]
            If missing, we fallback to append order (stable).
            """
            if not isinstance(call, dict):
                return -1

            inv = call.get("invoke")
            if isinstance(inv, dict):
                v = _pick(inv, "offset", "uoff", "insn_off", "insnOff", "byte_off", "byteOff", "idx", "index", "order")
                if v is not None:
                    try:
                        return int(v)
                    except Exception:
                        pass

            v = _pick(call, "offset", "uoff", "insn_off", "idx", "index", "order", "invoke_offset", "invokeOffset")
            if v is not None:
                try:
                    return int(v)
                except Exception:
                    pass

            return -1

        for call in api_calls:
            if not isinstance(call, dict):
                continue

            caller_raw = _extract_method_raw(call, "caller")
            callee_raw = _extract_method_raw(call, "callee")

            # some DexTrace dumps might use different key name for callee
            if not callee_raw:
                alt = _pick(call, "callee_method", "calleeMethod", "calleeMethodInfo")
                if isinstance(alt, dict):
                    callee_raw = alt

            caller = self._to_method_object(caller_raw or {})
            callee = self._to_method_object(callee_raw or {})

            offset = _extract_offset(call)
            if offset < 0:
                # fallback: stable order per-caller
                offset = len(self._calls_by_caller[caller])

            self._calls_by_caller[caller].append((callee, int(offset)))
            self._callers_by_callee[callee].add(caller)

    def _sig_to_method_object(self, dextrace_sig: str) -> MethodObject:
        """
        Create/find a MethodObject from a DexTrace method signature:
          Lpkg/name/Class;->method(Args)Ret
        """
        sig = self._normalize_dextrace_sig(dextrace_sig)
        m = re.match(r"^(L[^;]+;)->([^(]+)(\\(.*\\).*)$", sig)
        if not m:
            # fallback: best-effort bucket
            cls = ""
            name = sig
            desc = ""
        else:
            cls = m.group(1)
            name = m.group(2)
            desc = m.group(3)

        # Quark expects androguard-style descriptor (spaces between args)
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
        # Ensure it starts with '(' and contains ')'
        if "(" in desc and ")" in desc:
            try:
                # Quark uses androguard-format descriptors with spaces
                return descriptor_to_androguard_format(desc.replace(" ", ""))
            except Exception:
                return desc
        return desc

    def _normalize_dextrace_sig(self, sig: str) -> str:
        # remove whitespace that sometimes appears in reports
        return re.sub(r"\\s+", "", str(sig))

    def _methodobject_to_dextrace_sig(self, mo: MethodObject) -> str:
        """
        Convert Quark MethodObject to DexTrace signature (no spaces):
          Lcls;->name(Args)Ret
        """
        cls = (mo.class_name or "").strip()
        name = (mo.name or "").strip()
        desc = (mo.descriptor or "").strip()

        # Quark descriptors include spaces; DexTrace expects none.
        desc = re.sub(r"\\s+", "", desc)

        # Ensure class looks like L...;
        cls = self._normalize_class(cls)
        return f"{cls}->{name}{desc}"

    def _is_android_api_class(self, cls: str) -> bool:
        # Android framework + Java/Kotlin stdlib
        return cls.startswith("Landroid/") or cls.startswith("Ljava/") or cls.startswith("Ljavax/") or cls.startswith("Lkotlin/")

    def _is_external_class(self, cls: str) -> bool:
        # Keep it conservative: only framework/stdlib are external.
        # Support libs (androidx / android/support) are NOT treated as framework here
        # because they live inside the APK and often participate in wrapper sequences.
        return self._is_android_api_class(cls)

    def _extract_permissions_apk(self, apk_path: str) -> List[str]:
        if not _HAS_ANDROGUARD:
            return []
        try:
            a = APK(apk_path)
            perms = a.get_permissions() or []
            return list(perms)
        except Exception:
            return []

    # -------- Disasm integration --------

    @functools.lru_cache(maxsize=4096)
    def _disasm_by_sig(self, dextrace_sig: str) -> Optional[List[dict]]:
        """
        Cached disasm result by DexTrace signature.
        Returns list[dict] like [{"offset":..,"byte_off":..,"smali":"..."}] or None.
        """
        if not self._enable_disasm:
            return None

        sig = self._normalize_dextrace_sig(dextrace_sig)  # IMPORTANT: define sig first (fix crash)
        if self._debug:
            print("[dextrace disasm]", sig)

        cmd = [self._dextrace_bin, *self._dextrace_disasm_args, self._target_path, "--method", sig]
        try:
            out = self._run_dextrace_json(cmd)
        except Exception:
            return None

        methods = out.get("methods")
        if not isinstance(methods, dict):
            return None

        m = methods.get(sig)
        if not isinstance(m, dict):
            # fallback: try whitespace-normalized key match
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
        return BytecodeObject(mnemonic, regs or None, parameter)
