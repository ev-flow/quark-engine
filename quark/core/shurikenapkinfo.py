# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import re
import functools
from collections import defaultdict
from os import PathLike
from typing import Dict, List, Optional, Set, Iterator, Generator, Tuple

try:
    from shuriken import Dex, Apk
    from shuriken.dex import (
        hdvmmethodanalysis_t,
        hdvminstruction_t,
        dvmdisassembled_method_t,
        hdvmclass_t,
    )
    _has_shuriken = True
except ModuleNotFoundError:
    _has_shuriken = False

from quark.core.interface.baseapkinfo import BaseApkinfo, CoreLibraryUnavailable
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import descriptor_to_androguard_format


class ShurikenImp(BaseApkinfo):
    """A class that retrieves APK or DEX information using Shuriken-Analyzer.
    """

    def __init__(
        self,
        apk_filepath: str | PathLike,
        tmp_dir: str | PathLike = None,
    ):
        if not _has_shuriken:
            raise CoreLibraryUnavailable(
                "The Shuriken-based core library is not available because"
                " Shuriken-Analyzer was not installed. To use this core"
                " library, follow the instructions on the GitHub page"
                " 'https://github.com/Shuriken-Group/Shuriken-Analyzer' to"
                " install Shuriken-Analyzer and its Python bindings."
            )

        super().__init__(apk_filepath, "shuriken", tmp_dir)
        match self.ret_type:
            case "APK":
                self.analysis = Apk(apk_filepath, create_xrefs=True)
            case "DEX":
                self.analysis = Dex(apk_filepath)
                self.analysis.disassemble_dex()
                self.analysis.create_dex_analysis(1)
                self.analysis.analyze_classes()
                self._manifest = None
            case _:
                raise ValueError("Unsupported File type.")

        self.__patternToIdentifyMethodCall = re.compile(r"->[\w\$_<>-]+\(")
        self.__patternToIdentifyMemberField = re.compile(r"->[\w\$_<>-]+(?!\() ")

    @property
    def android_apis(self) -> Set[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Return all Android APIs used by the sample.

        :return: a set of MethodObjects
        """
        methods = self.all_methods
        androidAPIs = set(
            filter(
                lambda method: (
                    method.is_android_api() and method.cache.is_android_api
                ),
                methods,
            )
        )

        return androidAPIs

    @property
    def custom_methods(self) -> Set[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Return all custom methods declared by the sample.

        :return: a set of MethodObjects
        """
        return {
            method for method in self.all_methods if not method.cache.external
        }

    @functools.cached_property
    def all_methods(self) -> Set[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Return all methods in the sample, including Android APIs and custom
        methods.

        :return: a set of MethodObjects
        """
        methods = set()

        match self.ret_type:
            case "APK":
                numOfMethod = (
                    self.analysis.get_number_of_methodanalysis_objects()
                )
                for i in range(numOfMethod):
                    methodAnalysis = self.analysis.get_analyzed_method_by_idx(
                        i
                    )
                    methods.add(
                        self.__convertToMethodObject(methodAnalysis)
                    )

            case "DEX":
                # TODO - Wait for the upstream to support getting all methods.
                for i in range(self.analysis.get_number_of_classes()):
                    rawClass = self.analysis.get_class_by_id(i)
                    className = rawClass.class_name.decode()
                    classAnalysis = self.analysis.get_analyzed_class(className)
                    for j in range(classAnalysis.n_of_methods):
                        methodAnalysis = classAnalysis.methods[j].contents
                        method = self.__convertToMethodObject(
                            methodAnalysis
                        )
                        lowerMethodInfo = self.lowerfunc(method)
                        lowerMethods = [info[0] for info in lowerMethodInfo]
                        methods = methods.union(set(lowerMethods))
                        methods.add(method)
            case _:
                raise ValueError("Unsupported File type.")

        return methods

    @functools.lru_cache()
    def find_method(
        self,
        class_name: Optional[str] = None,
        method_name: Optional[str] = None,
        descriptor: Optional[str] = None,
    ) -> List[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Find a method with the given class name, method name, and descriptor.

        :param class_name: the class name of the target method. Defaults to
        None
        :param method_name: the method name of the target method. Defaults to
        None
        :param descriptor: the descriptor of the target method. Defaults to
        None
        :return: a list of the target MethodObject
        """
        methods = self.all_methods
        if class_name:
            methods = (m for m in methods if class_name == m.class_name)

        if method_name:
            methods = (m for m in methods if method_name == m.name)

        if descriptor:
            methods = (m for m in methods if descriptor == m.descriptor)

        return list(methods)

    @functools.lru_cache()
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Find the xrefs from the specified method.

        :param method_object: a target method which the returned methods
        should call
        :return: a set of MethodObjects
        """
        methodAnalysis = method_object.cache
        upperFuncs = set()
        for i in range(methodAnalysis.n_of_xreffrom):
            upperFuncs.add(
                self.__convertToMethodObject(
                    methodAnalysis.xreffrom[i].method.contents
                )
            )

        return upperFuncs

    @functools.lru_cache()
    def lowerfunc(
        self, method_object: MethodObject
    ) -> list[Tuple[MethodObject, int]]:
        """
        Inherited from baseapkinfo.py.
        Find the xrefs to the specified method.

        :param method_object: a target method used to find what methods it
        calls
        :return: a set of tuples consisting of the called method and the
        offset of the invocation
        """
        methodAnalysis = method_object.cache

        lowerFuncs = []
        for i in range(methodAnalysis.n_of_xrefto):
            xref = methodAnalysis.xrefto[i]
            lowerFuncs.append(
                (
                    self.__convertToMethodObject(xref.method.contents),
                    xref.idx,
                )
            )

        return lowerFuncs

    def get_method_bytecode(
        self, method_object: MethodObject
    ) -> Generator[BytecodeObject, None, None]:
        """
        Inherited from baseapkinfo.py.
        Return the bytecodes of the specified method.

        :param method_object: a target method to get the corresponding
        bytecodes
        :yield: a generator of BytecodeObjects
        """
        if method_object.cache.external:
            return
        disassembledMethod = self.__getDisassembledMethod(method_object)
        for i in range(disassembledMethod.n_of_instructions):
            rawSmali = disassembledMethod.instructions[i].disassembly.decode(
                errors="backslashreplace"
            )
            yield self.__parseSmali(rawSmali)

    def __parseParameter(self, parameter: str) -> int | float | str:
        """
        Parse the parameter into the data it represents.

        :param parameter: a parameter string to be parsed
        :return: the data parsed from the parameter, which could be:
                - Address
                - 64/32-bit float or integer
                - Method call
                - Member field
                - Type
                - Original string if unable to be parsed.
        """
        if parameter.startswith("0x"):
            # The parameter is an address.
            try:
                return int(parameter, 16)
            except (TypeError, ValueError):
                return parameter

        if parameter.startswith("#"):
            # The parameter is a 64-bit float.
            try:
                return float(parameter[1:])
            except (TypeError, ValueError):
                return parameter

        # Test if the parameter is a 32-bit integer.
        try:
            return int(parameter, 10)
        except (TypeError, ValueError):
            pass

        # Test if the parameter is a 32-bit float.
        try:
            parameter = float(parameter, 10)
            return parameter
        except (TypeError, ValueError):
            pass

        if self.__patternToIdentifyMethodCall.search(parameter):
            parameter = self.__convertMethodCallFormat(parameter)

        if self.__patternToIdentifyMemberField.search(parameter):
            parameter = self.__convertMemberFieldFormat(parameter)

        return parameter

    @staticmethod
    def __splitSmali(smali: str) -> Tuple[str, List[str], List[str]]:
        """
        Split a smali code string into a mnemonic, registers, and parameters.

        :param smali: a smali code string
        :return: a tuple consisting the mnemonic, the registers, and the
        parameters in the smali
        """
        if smali == "":
            raise ValueError("Argument cannot be empty.")

        if " " not in smali:
            return smali, None, None

        parameters = []
        if smali and smali[-1] in ('\"', "\'"):
            # Extract String
            quoteChar = smali[-1]
            firstQuotePosition = smali.find(quoteChar)
            parameters.append(smali[firstQuotePosition:][1:-1])
            smali = smali[:firstQuotePosition].strip()

        mnemonic, argsStr = smali.split(maxsplit=1)
        args = [arg.strip() for arg in re.split("[{},]+", argsStr) if arg]

        while args and not args[-1].startswith("v"):
            parameters.append(args.pop())

        return mnemonic, args, parameters

    def __parseSmali(self, smali: str) -> BytecodeObject:
        """
        Parse the given smali code string into a BytecodeObject.

        :param smali: a smali code string disassembled from an instruction
        :return: a BytecodeObject
        """
        smali = smali.rsplit("//", maxsplit=1)[0].strip()

        mnemonic, argsList, parameterList = self.__splitSmali(smali)
        parameter = self.__parseParameter(
            parameterList[-1]) if parameterList else None

        return BytecodeObject(mnemonic, argsList, parameter)

    def get_strings(self) -> Set[str]:
        """
        Inherited from baseapkinfo.py.
        Return all strings in the sample.

        :return: a set of strings
        """
        match self.ret_type:
            case "APK":
                dexList = (
                    self.analysis.get_dex_file_by_index(i)
                    for i in range(self.analysis.get_number_of_dex_files())
                )

                rawString = (
                    self.analysis.get_string_by_id_from_dex(dex, i)
                    for dex in dexList
                    for i in range(
                        self.analysis.get_number_of_strings_from_dex(dex)
                    )
                )

            case "DEX":
                rawString = (
                    self.analysis.get_string_by_id(i).decode(
                        errors="backslashreplace"
                    )
                    for i in range(self.analysis.get_number_of_strings())
                )

            case _:
                raise ValueError("Unsupported File type.")

        return {s for s in rawString if s}

    def __findMethodCallInstruction(
        self,
        method: MethodObject,
        instructions: list["hdvminstruction_t"],
        start: int = 0,
    ) -> int | None:
        """
        Find the instruction that calls the method.

        :param method: the target method to find
        :param instructions: a list of instructions
        :param start: the starting index to search from, defaults to 0
        :return: the index of the instruction if found, None otherwise
        """
        targetMethodCall = (
            f"{method.class_name}->{method.name}"
            f"{method.descriptor.replace(' ', '')}"
        )

        for idx in range(start, len(instructions)):
            bytecodeStr = instructions[idx].disassembly.decode(
                errors="backslashreplace"
            )
            if (
                bytecodeStr.startswith("invoke")
                and targetMethodCall in bytecodeStr
            ):
                return idx

    def __getDisassembledMethod(
        self, method: MethodObject
    ) -> "dvmdisassembled_method_t":
        """
        Get the disassembled method corresponding to the MethodObject.

        :param method: the method to get disassembled
        :return: the disassembled method
        """
        methodAnalysis = method.cache

        match self.ret_type:
            case "DEX":
                return self.analysis.get_disassembled_method(
                    methodAnalysis.full_name.decode()
                )
            case "APK":
                return self.analysis.get_disassembled_method_from_apk(
                    methodAnalysis.full_name.decode()
                )
            case _:
                raise ValueError("Unsupported File type.")

    def __extractMethodCallDetails(
        self,
        targetMethod: MethodObject,
        instructions: list["hdvminstruction_t"],
        rawBytes: bytes,
        start: int = 0,
    ):
        """
        Extract details about a method call from a list of instructions.

        :param targetMethod: the target method to find
        :param instructions: a list of instructions to search through
        :param rawBytes: the raw bytecode of the method
        :param start: the starting index to search from, defaults to 0
        :return: a dictionary containing:
                - index: the index of the method call instruction
                - smali: the method call instruction
                - hex: the hex string of the instruction bytes
        """
        idx = self.__findMethodCallInstruction(
            targetMethod, instructions, start
        )
        if idx is None:
            idx = self.__findMethodCallInstruction(
                targetMethod, instructions, 0
            )

        smali = self.__parseSmali(
            instructions[idx].disassembly.decode(errors="backslashreplace")
        )

        offset = sum(ins.instruction_length for ins in instructions[:idx])
        hex_bytes = rawBytes[
            offset: offset + instructions[idx].instruction_length
        ].hex(" ")

        return {
            "index": idx,
            "smali": [smali.mnemonic] + smali.registers + [smali.parameter],
            "hex": hex_bytes,
        }

    @functools.lru_cache
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> dict[str, BytecodeObject | str]:
        """
        Inherited from baseapkinfo.py.
        Find the invocations that call two specified methods, first_method
        and second_method, respectively. Then, return a dictionary storing
        the corresponding bytecodes and hex values.

        :param parent_method: a parent method to scan
        :param first_method: the first method called by the parent method
        :param second_method: the second method called by the parent method
        :return: a dictionary storing the corresponding bytecodes and hex
        values.
        """
        disassembledMethod = self.__getDisassembledMethod(parent_method)

        numOfIns = disassembledMethod.n_of_instructions
        instructions = disassembledMethod.instructions[:numOfIns]

        method = disassembledMethod.method_id.contents
        rawBytes = bytes(method.code[: method.code_size])

        firstResult = self.__extractMethodCallDetails(
            first_method, instructions, rawBytes
        )
        secondResult = self.__extractMethodCallDetails(
            second_method,
            instructions,
            rawBytes,
            start=firstResult["index"] + 1,
        )

        return {
            "first": firstResult["smali"],
            "first_hex": firstResult["hex"],
            "second": secondResult["smali"],
            "second_hex": secondResult["hex"],
        }

    def __getClasses(self) -> Iterator["hdvmclass_t"]:
        """
        Get all classes defined in the sample.

        :return: An iterator of the classes
        """
        match self.ret_type:
            case "APK":
                dexList = (
                    self.analysis.get_dex_file_by_index(i)
                    for i in range(self.analysis.get_number_of_dex_files())
                )

                rawClasses = (
                    self.analysis.get_hdvmclass_from_dex_by_index(dex, i)
                    for dex in dexList
                    for i in range(
                        self.analysis.get_number_of_classes_for_dex_file(dex)
                    )
                )

            case "DEX":
                rawClasses = (
                    self.analysis.get_class_by_id(i)
                    for i in range(self.analysis.get_number_of_classes())
                )

            case _:
                raise ValueError("Unsupported File type.")
        return rawClasses

    @property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        """
        Inherited from baseapkinfo.py.
        Return a dictionary holding the inheritance relationship of classes in
        the sample. The dictionary takes a class name as the key and the
        corresponding superclass as the value.

        :return: a dictionary taking a class name as the key and the
        corresponding superclass as the value.
        """
        rawClasses = self.__getClasses()

        hierarchyDict = defaultdict(set)

        for rawClass in rawClasses:
            className = self.__convertClassNameFormat(
                rawClass.class_name.decode()
            )
            superclassName = self.__convertClassNameFormat(
                rawClass.super_class.decode()
            )

            hierarchyDict[className].add(superclassName)

        return hierarchyDict

    @property
    def subclass_relationships(self) -> Dict[str, Set[str]]:
        """
        Inherited from baseapkinfo.py.
        Return a dictionary holding the inheritance relationship of classes in
        the sample. Return a dictionary holding the inheritance relationship
        of classes in the sample. The dictionary takes a class name as the key
        and the corresponding subclasses as the value.

        :return: a dictionary taking a class name as the key and the
        corresponding subclasses as the value.
        """
        rawClasses = self.__getClasses()

        hierarchyDict = defaultdict(set)

        for rawClass in rawClasses:
            className = self.__convertClassNameFormat(
                rawClass.class_name.decode()
            )
            superclassName = self.__convertClassNameFormat(
                rawClass.super_class.decode()
            )

            hierarchyDict[superclassName].add(className)

        return hierarchyDict

    def __convertToMethodObject(
        self,
        methodAnalysis: "hdvmmethodanalysis_t",
    ) -> MethodObject:
        """
        Convert a hdvmmethodanalysis_t object to a MethodObject.

        :param methodAnalysis: a hdvmmethodanalysis_t object
        :return: a MethodObject
        """
        className = self.__convertClassNameFormat(
            methodAnalysis.class_name.decode()
        )

        return MethodObject(
            # access_flags=methodAnalysis.access_flags,
            class_name=className,
            name=methodAnalysis.name.decode(),
            descriptor=descriptor_to_androguard_format(
                methodAnalysis.descriptor.decode()
            ),
            cache=methodAnalysis,
        )

    def __convertClassNameFormat(self, className: str) -> str:
        """
        Convert a class from the Java language format to the Java VM type
        signature format.

        :param className: a class to be converted
        :return: the class in the Java VM type signature format
        """

        if not className.endswith(";"):
            className = "L" + className.replace(".", "/") + ";"

        return className

    def __convertMemberFieldFormat(self, memberField: str) -> str:
        """
        Convert a member field from the Java language format to the Java VM
        type signature format.

        For example, given the member field "a.b.c->fieldA boolean", this
        function converts it to "La/b/c->fieldA Z".

        :param memberField: a member field to be converted
        :return: the member field in the Java VM type signature format
        """

        typeTable = {
            "void": "V",
            "boolean": "Z",
            "byte": "B",
            "short": "S",
            "char": "C",
            "int": "I",
            "long": "J",
            "float": "F",
            "double": "D",
        }
        frontPart, fieldType = memberField.rsplit(maxsplit=1)
        baseType = fieldType.split("[")[0]
        newBaseType = typeTable.get(
            baseType, self.__convertClassNameFormat(baseType)
        )
        fieldTypeArrayDimension = fieldType.count("[")
        newFieldType = "[" * fieldTypeArrayDimension + newBaseType

        className, fieldName = frontPart.split("->")
        className = self.__convertClassNameFormat(className)

        return f"{className}->{fieldName} {newFieldType}"

    def __convertMethodCallFormat(self, methodCall: str) -> str:
        """
        Convert a method call from the original format to the Androguard
        format, which inserts spaces between the arguments in the descriptor.

        :param methodCall: a method call to be converted
        :return: the method call in the Androguard format
        """
        frontPart, rearPart = methodCall.split("(")
        newDescriptor = descriptor_to_androguard_format("(" + rearPart)
        parsedMethodCall = frontPart + newDescriptor

        return parsedMethodCall
