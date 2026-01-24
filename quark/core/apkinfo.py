# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
import re
from collections import defaultdict
from os import PathLike
from typing import Dict, List, Optional, Set, Union

from androguard.core.analysis.analysis import MethodAnalysis
from androguard.core.bytecodes.dvm_types import Operand
from androguard.misc import AnalyzeAPK, AnalyzeDex

from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.evaluator.pyeval import PyEval


class AndroguardImp(BaseApkinfo):
    """Information about apk based on androguard analysis"""

    __slots__ = ("apk", "dalvikvmformat", "analysis", "_manifest")

    def __init__(self, apk_filepath: Union[str, PathLike]):
        super().__init__(apk_filepath, "androguard")

        if self.ret_type == "APK":
            # return the APK, list of DalvikVMFormat, and Analysis objects
            self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(self.data, raw=True)
        elif self.ret_type == "DEX":
            # return the sha256hash, DalvikVMFormat, and Analysis objects
            _, _, self.analysis = get_default_session().addDEX(self.apk_filename, self.data)
        else:
            raise ValueError("Unsupported File type.")

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

    @property
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

                # count the number of the registers.
                length_operands = len(ins.get_operands())
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
                            not isinstance(ins.get_operands()[i][0], Operand)
                            or ins.get_operands()[i][0].name != "REGISTER"
                        ):
                            index_of_parameter_starts = i
                            break

                    if index_of_parameter_starts is not None:
                        parameter = ins.get_operands()[
                            index_of_parameter_starts
                        ]
                        parameter = (
                            parameter[2]
                            if len(parameter) == 3
                            else parameter[1]
                        )

                        for i in range(index_of_parameter_starts):
                            register_list.append(
                                "v" + str(ins.get_operands()[i][1]),
                            )
                    else:
                        parameter = None
                        for i in range(length_operands):
                            register_list.append(
                                "v" + str(ins.get_operands()[i][1]),
                            )

                    bytecode_obj = BytecodeObject(
                        ins.get_name(), register_list, parameter
                    )

                yield bytecode_obj
        except AttributeError:
            # TODO Log the rule here
            pass

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

    @property
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
