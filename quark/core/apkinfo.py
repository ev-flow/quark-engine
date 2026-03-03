# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import click
import functools
import hashlib
import io
import logging
import re
import sys
import zipfile
import zlib
from collections import defaultdict
from os import PathLike
from typing import Dict, List, Optional, Set, Union

from androguard.core.analysis.analysis import MethodAnalysis
from androguard.core.bytecodes.dvm_types import Operand
from androguard.misc import AnalyzeAPK, get_default_session
from androguard.core.dex import Instruction45cc, Instruction4rcc, get_kind, Kind

from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.evaluator.pyeval import PyEval


class AndroguardImp(BaseApkinfo):
    """Information about apk based on androguard analysis"""

    def __init__(self, apk_filepath: Union[str, PathLike], auto_fix_checksum=False):
        super().__init__(apk_filepath, "androguard", auto_fix_checksum=auto_fix_checksum)

        if self.ret_type == "APK":
            # Suppress Androguard warnings about AndroidManifest,
            # as we don't use Androguard’s AndroidManifest parsing results.
            logging.getLogger("androguard.axml").disabled = True
            logging.getLogger("androguard.apk").disabled = True
            try:
                # return the APK, list of DalvikVMFormat, and Analysis objects
                self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(self.data, raw=True)
            except Exception as e:
                # Check if the exception looks like a checksum error
                if self._looks_like_checksum_error(e):
                    # If auto_fix_checksum is not enabled, ask the user for confirmation
                    if not self.auto_fix_checksum:
                        if sys.stdin.isatty() and sys.stdout.isatty():
                            # If the environment is interactive, ask the user for confirmation
                            agree = click.confirm(
                                "\n⚠ Detected damaged DEX checksum/signature."
                                "\n   Fixing will modify DEX headers and invalidate APK signatures (hashes will change)."
                                "\n   Proceed to repair and continue the analysis?",
                                default=False,
                                show_default=True,
                            )

                            if not agree:
                                # If the user does not agree, cancel the repair and keep the original file
                                click.echo("\n✖ Repair canceled by user. Keeping the original file.\n", err=True)

                                raise e
                        else:
                            # If the environment is non-interactive, print a message and abort the analysis
                            click.echo(
                                "ℹ Detected damaged DEX checksum/signature but --auto-fix-checksum was not provided "
                                "and the environment is non-interactive. Skipping repair and aborting.\n"
                                "   Hint: rerun with --auto-fix-checksum to repair automatically.",
                                err=True,
                            )
                            raise e


                    # Repack the APK with fixed DEX headers
                    fixed_bytes = self._repack_apk_with_fixed_dex_headers_from_bytes(self.data)

                    # Check if the APK was actually repacked
                    if fixed_bytes:
                        # Analyze the repacked APK
                        self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(fixed_bytes, raw=True)
                    else:
                        # If the APK was not actually repacked, raise the original exception
                        raise e
                else:
                    # If the exception does not look like a checksum error, raise the original exception
                    raise e
        elif self.ret_type == "DEX":
            try:
                # return the sha256hash, DalvikVMFormat, and Analysis objects
                _, _, self.analysis = get_default_session().addDEX(self.apk_filename, self.data)
            except Exception as e:
                # Check if the exception looks like a checksum error
                if self._looks_like_checksum_error(e):
                    # If auto_fix_checksum is not enabled, ask the user for confirmation
                    if not self.auto_fix_checksum:
                        if sys.stdin.isatty() and sys.stdout.isatty():
                            # If the environment is interactive, ask the user for confirmation
                            agree = click.confirm(
                                "\n⚠ Detected damaged DEX checksum/signature."
                                "\n   Fixing will modify DEX headers and invalidate APK signatures (hashes will change)."
                                "\n   Proceed to repair and continue the analysis?",
                                default=False,
                                show_default=True,
                            )

                            if not agree:
                                # If the user does not agree, cancel the repair and keep the original file
                                click.echo("✖ Repair canceled by user. Keeping the original file.", err=True)

                                raise e
                        else:
                            # If the environment is non-interactive, print a message and abort the analysis
                            click.echo(
                                "ℹ Detected damaged DEX checksum/signature but --auto-fix-checksum was not provided "
                                "and the environment is non-interactive. Skipping repair and aborting.\n"
                                "   Hint: rerun with --auto-fix-checksum to repair automatically.",
                                err=True,
                            )
                            raise e

                    # Fix the header of the DEX file
                    fixed = self._fix_single_dex_header(self.data)

                    # Check if the DEX file was actually fixed
                    if fixed != self.data:
                        # Analyze the fixed DEX file
                        _, _, self.analysis = get_default_session().addDEX(self.apk_filename, fixed)
                    else:
                        # If the DEX file was not actually fixed, raise the original exception
                        raise e
                else:
                    # If the exception does not look like a checksum error, raise the original exception
                    raise e
        else:
            raise ValueError("Unsupported File type.")

    def _repack_apk_with_fixed_dex_headers_from_bytes(self, apk_bytes: bytes) -> Optional[bytes]:
        """Repack the APK with fixed DEX headers from bytes.
        
        Open the APK in memory, fix the headers of all .dex files, and repack them back into bytes.
        Only return the new APK if there were actually changes; otherwise return None.

        """
        try:
            # Open the APK in memory
            in_io = io.BytesIO(apk_bytes)
            
            # Open the APK as a zip file
            with zipfile.ZipFile(in_io, "r") as zf:
                # Create a new zip file to store the fixed DEX files
                updated = False
                out_io = io.BytesIO()

                # Open the new zip file to store the fixed DEX files
                with zipfile.ZipFile(out_io, "w", compression=zipfile.ZIP_DEFLATED) as out_zf:
                    # Iterate over all files in the APK
                    for info in zf.infolist():
                        # Read the data of the file
                        data = zf.read(info.filename)

                        # Check if the file is a DEX file
                        if info.filename.lower().endswith(".dex"):
                            # Fix the header of the DEX file
                            fixed = self._fix_single_dex_header(data)

                            # Check if the DEX file was actually fixed
                            if fixed != data:
                                updated = True
                                data = fixed

                        # keep basic zip entry metadata
                        zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                        zi.compress_type = zipfile.ZIP_DEFLATED
                        zi.external_attr = info.external_attr
                        zi.create_system = info.create_system

                        # Write the fixed DEX file to the new zip file
                        out_zf.writestr(zi, data)

                # Return the new APK if there were actually changes; otherwise return None
                return out_io.getvalue() if updated else None
        except Exception as e:
            # If there was an error, return None
            return None


    def _looks_like_checksum_error(self,e: Exception) -> bool:
        """Check if the exception looks like a checksum error."""
        s = str(e).lower()

        keywords = ("checksum", "adler32", "wrong adler32")
        return any(kw in s for kw in keywords)

    @property
    def android_apis(self) -> Set[MethodObject]:
        apis = set()

        for external_cls in self.analysis.get_external_classes():
            for meth_analysis in external_cls.get_methods():
                if meth_analysis.is_android_api():
                    apis.add(meth_analysis)

        return {self._convert_to_method_object(api) for api in apis}

    @property
    def custom_methods(self) -> Set[MethodObject]:
        return {
            self._convert_to_method_object(meth_analysis)
            for meth_analysis in self.analysis.get_methods()
            if not meth_analysis.is_external()
        }

    @functools.cached_property
    def all_methods(self) -> Set[MethodObject]:
        return {
            self._convert_to_method_object(meth_analysis)
            for meth_analysis in self.analysis.get_methods()
        }

    @functools.lru_cache()
    def find_method(
        self,
        class_name: Optional[str] = ".*",
        method_name: Optional[str] = ".*",
        descriptor: Optional[str] = ".*",
    ) -> List[MethodObject]:
        if not class_name:
            class_name = ".*"

        if class_name != ".*":
            regex_class_name = re.escape(class_name)
        else:
            regex_class_name = class_name

        if not method_name:
            method_name = ".*"

        if method_name != ".*":
            regex_method_name = f"^{re.escape(method_name)}$"
        else:
            regex_method_name = f"^{method_name}$"

        if not descriptor:
            descriptor = ".*"

        if descriptor != ".*":
            regex_descriptor = re.escape(descriptor)
        else:
            regex_descriptor = descriptor

        method_result = self.analysis.find_methods(
            classname=regex_class_name,
            methodname=regex_method_name,
            descriptor=regex_descriptor,
        )

        return [self._convert_to_method_object(item) for item in method_result]

    @functools.lru_cache()
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        method_analysis = method_object.cache
        return {
            self._convert_to_method_object(call)
            for _, call, _ in method_analysis.get_xref_from()
        }

    @functools.lru_cache()
    def lowerfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        method_analysis = method_object.cache
        return {
            (self._convert_to_method_object(call), offset)
            for _, call, offset in method_analysis.get_xref_to()
        }

    def get_method_bytecode(
        self, method_object: MethodObject
    ) -> Set[MethodObject]:
        method_analysis = method_object.cache
        try:
            for (
                _,
                ins,
            ) in method_analysis.get_method().get_instructions_idx():
                bytecode_obj = None
                register_list = []
                
                if type(ins) is Instruction45cc:
                    ins_operands = self.get_instruction45cc_operands(ins)
                elif type(ins) is Instruction4rcc:
                    ins_operands = self.get_instruction4rcc_operands(ins)
                else:
                    ins_operands = ins.get_operands()

                # count the number of the registers.
                length_operands = len(ins_operands)
                if length_operands == 0:
                    # No register, no parameter
                    bytecode_obj = BytecodeObject(
                        ins.get_name(),
                        None,
                        None,
                    )
                else:
                    index_of_parameter_starts = None
                    for i in range(length_operands - 1, -1, -1):
                        if (
                            not isinstance(ins_operands[i][0], Operand)
                            or ins_operands[i][0].name != "REGISTER"
                        ):
                            index_of_parameter_starts = i
                            break

                    if index_of_parameter_starts is not None:
                        parameter = ins_operands[
                            index_of_parameter_starts
                        ]
                        parameter = (
                            parameter[2]
                            if len(parameter) == 3
                            else parameter[1]
                        )

                        for i in range(index_of_parameter_starts):
                            register_list.append(
                                "v" + str(ins_operands[i][1]),
                            )
                    else:
                        parameter = None
                        for i in range(length_operands):
                            register_list.append(
                                "v" + str(ins_operands[i][1]),
                            )

                    bytecode_obj = BytecodeObject(
                        ins.get_name(), register_list, parameter
                    )

                yield bytecode_obj
        except AttributeError:
            # TODO Log the rule here
            pass

    def get_instruction45cc_operands(self, ins: Instruction45cc):
        operands = []
        if ins.A > 0: 
            operands.append((Operand.REGISTER, ins.C))
        if ins.A > 1: 
            operands.append((Operand.REGISTER, ins.D))
        if ins.A > 2: 
            operands.append((Operand.REGISTER, ins.E))
        if ins.A > 3: 
            operands.append((Operand.REGISTER, ins.F))
        if ins.A > 4: 
            operands.append((Operand.REGISTER, ins.G))

        kind = get_kind(ins.cm, Kind.METH, ins.BBBB)
        operands.append((Operand.KIND + ins.get_kind(), ins.BBBB, kind))
        return operands

    def get_instruction4rcc_operands(self, ins: Instruction4rcc):
        operands = []
        for r in range(ins.CCCC, ins.NNNN + 1):
            operands.append((Operand.REGISTER, r))

        kind = get_kind(ins.cm, Kind.METH, ins.BBBB)
        operands.append((Operand.KIND + ins.get_kind(), ins.BBBB, kind))
        return operands

    def get_strings(self) -> str:
        return {
            str(string_analysis.get_orig_value())
            for string_analysis in self.analysis.get_strings()
        }

    @functools.lru_cache()
    def _construct_bytecode_instruction(self, instruction):
        """
        Construct a list of strings from the given bytecode instructions.

        :param instruction: instruction instance from androguard
        :return: a list with bytecode instructions strings
        """
        instruction_list = [instruction.get_name()]
        reg_list = []

        # count the number of the registers.
        length_operands = len(instruction.get_operands())
        if length_operands == 0:
            # No register, no parameter
            return instruction_list

        elif length_operands == 1:
            # Only one register

            reg_list.append(f"v{instruction.get_operands()[length_operands - 1][1]}")

            instruction_list.extend(reg_list)

            return instruction_list
        elif length_operands >= 2:
            # the last one is parameter, the other are registers.

            parameter = instruction.get_operands()[length_operands - 1]
            for i in range(length_operands - 1):
                reg_list.append(
                    "v" + str(instruction.get_operands()[i][1]),
                )
            parameter = parameter[2] if len(parameter) == 3 else parameter[1]
            instruction_list.extend(reg_list)
            instruction_list.append(parameter)

            return instruction_list

    @functools.lru_cache()
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:
        method_analysis = parent_method.cache

        result = {
            "first": None,
            "first_hex": None,
            "second": None,
            "second_hex": None,
        }

        first_method_pattern = PyEval.get_method_pattern(
            first_method.class_name, first_method.name, first_method.descriptor
        )
        second_method_pattern = PyEval.get_method_pattern(
            second_method.class_name,
            second_method.name,
            second_method.descriptor,
        )

        for _, ins in method_analysis.get_method().get_instructions_idx():
            if first_method_pattern in str(ins):
                result["first"] = self._construct_bytecode_instruction(ins)
                result["first_hex"] = ins.get_hex()
            if second_method_pattern in str(ins):
                result["second"] = self._construct_bytecode_instruction(ins)
                result["second_hex"] = ins.get_hex()

        return result

    @functools.cached_property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        hierarchy_dict = defaultdict(set)

        for _class in self.analysis.get_classes():
            hierarchy_dict[str(_class.name)].add(str(_class.extends))
            hierarchy_dict[str(_class.name)].union(
                str(implements) for implements in _class.implements
            )

        return hierarchy_dict

    @property
    def subclass_relationships(self) -> Dict[str, Set[str]]:
        hierarchy_dict = defaultdict(set)

        for _class in self.analysis.get_classes():
            class_name = str(_class.name)
            hierarchy_dict[str(_class.extends)].add(class_name)
            for implements in _class.implements:
                hierarchy_dict[str(implements)].add(class_name)

        return hierarchy_dict

    @staticmethod
    @functools.lru_cache
    def _convert_to_method_object(
        method_analysis: MethodAnalysis,
    ) -> MethodObject:
        return MethodObject(
            access_flags=method_analysis.access,
            class_name=str(method_analysis.class_name),
            name=str(method_analysis.name),
            descriptor=str(method_analysis.descriptor),
            cache=method_analysis,
        )

    @staticmethod
    def _fix_single_dex_header(dex: bytes) -> bytes:
        """Fix the header of a single DEX file.

        Layout:
        - 0x08..0x0B: Adler32
        - 0x0C..0x1F: SHA-1
        """

        # Check if the DEX file is valid
        if len(dex) < 0x20 or not dex.startswith(b"dex\n"):
            # Invalid DEX file
            # Return the original DEX file without any changes
            return dex

        # SHA-1 Signature (20 bytes)
        sha1 = hashlib.sha1(dex[0x20:]).digest()
        # Adler32 Checksum (4 bytes) little-endian
        ad = zlib.adler32(dex[0x0C:]) & 0xFFFFFFFF

        # Update the header
        out = bytearray(dex)
        # Update the SHA-1 Signature
        out[0x0C:0x20] = sha1
        # Update the Adler32 Checksum
        out[0x08:0x0C] = ad.to_bytes(4, "little")

        return bytes(out)
