# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
import logging
import os.path
import re
import tempfile
import zipfile
from collections import defaultdict, namedtuple
from os import PathLike
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Union

import r2pipe

from quark.core.axmlreader import AxmlReader
from quark.core.interface.baseapkinfo import BaseApkinfo, XMLElement
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import (
    descriptor_to_androguard_format,
    remove_dup_list,
)

R2Cache = namedtuple("r2_cache", "address is_imported")

PRIMITIVE_TYPE_MAPPING = {
    "void": "V",
    "boolean": "Z",
    "byte": "B",
    "char": "C",
    "short": "S",
    "int": "I",
    "long": "J",
    "float": "F",
    "double": "D",
}

R2_ESCAPE_CHAR_LIST = ["$"]


class R2Imp(BaseApkinfo):
    def __init__(
        self,
        apk_filepath: Union[str, PathLike],
        tmp_dir: Union[str, PathLike] = None,
    ):
        super().__init__(apk_filepath, "radare2")

        if self.ret_type == "DEX":
            self._tmp_dir = None

        elif self.ret_type == "APK":
            self._tmp_dir = tempfile.mkdtemp() if tmp_dir is None else tmp_dir

            if self.isPatched:
                # The APK has been patched to mitigate anti-analysis
                # techniques. Therefore, Radare2 must parse the patched data
                # instead of the original APK.
                self.apk_filepath = os.path.join(self._tmp_dir, "patched.apk")
                with open(self.apk_filepath, "wb") as patchedApk:
                    patchedApk.write(self.data)

                self.data.close()
                self.file.close()

        else:
            raise ValueError("Unsupported File type.")

    @functools.cached_property
    def _r2(self):
        """
        Return a R2 object that opens the specified Dex file.

        :param index: an index indicating which Dex file should the returned
        object open
        :return: a R2 object opening the specified Dex file
        """
        if self.ret_type == "DEX":
            r2 = r2pipe.open(f"{self.apk_filepath}")
        elif self.ret_type == "APK":
            r2 = r2pipe.open(f"apk://{self.apk_filepath}")

        r2.cmd("aa")
        return r2

    def _convert_type_to_type_signature(self, raw_type: str):
        """
        Convert a Java type in the format of the Java language into the
        one in the format of the Java VM type signature.

        For example,
        + `int` will be converted into the Java VM type signature `I`.
        + `long` will be converted into the Java VM type signature `L`.
        + `String...` will be converted into the Java VM type signature
        `[Ljava/lang/String;`.

        :param raw_type: a type in the format of the Java language
        :return: a type in the format of the Java VM type signature
        """
        if not raw_type:
            return raw_type

        if raw_type.endswith("[]"):
            return "[" + self._convert_type_to_type_signature(raw_type[:-2])

        if raw_type.startswith("["):
            return "[" + self._convert_type_to_type_signature(raw_type[1:])

        if "..." in raw_type:
            index = raw_type.index("...")
            return "[" + self._convert_type_to_type_signature(raw_type[:index])

        if raw_type in PRIMITIVE_TYPE_MAPPING:
            return PRIMITIVE_TYPE_MAPPING[raw_type]

        if "." in raw_type or "_" in raw_type:
            raw_type = raw_type.replace(".", "/")
            raw_type = raw_type.replace("_", "$")
            return "L" + raw_type + ";"

        return raw_type + ";"

    @staticmethod
    def _escape_str_in_r2_manner(raw_str: str):
        """
        Convert characters with special meanings in R2 into `_`.
        For now, the character is `$`.

        :param raw_str: a string that may consist of characters with special
        meanings.
        :return: a new string contains no characters with special meanings.
        """
        for c in R2_ESCAPE_CHAR_LIST:
            raw_str = raw_str.replace(c, "_")
        return raw_str

    def _parse_method_from_isj_obj(self, json_obj):
        """
        Parse a JSON object provided by the R2 command `isj` or `is.j` into
        an instance of MethodObject.

        :param json_obj: a JSON object provided by the R2 command `isj` or
        `is.j`
        :param dexindex: an index indicating from which Dex file the JSON
        object is generated
        :return: an instance of MethodObject
        """
        if json_obj.get("type") not in ["FUNC", "METH"]:
            return None

        parse_pattern = re.compile(r"(^[\[|L].*)\.method\.(.*)(\(.*\).*)")

        real_name = json_obj.get("realname")
        if not real_name:
            return None

        class_name, method_name, descriptor = parse_pattern.match(
            real_name).groups()

        # -- Descriptor --
        descriptor = descriptor_to_androguard_format(descriptor)

        # -- Is imported --
        is_imported = json_obj.get("is_imported")

        # -- Method name --
        method_name = self._escape_str_in_r2_manner(method_name)
        if method_name.endswith("_"):
            method_name = method_name[:-1]

        # -- Class name --

        # Exclude start with "imp.["
        if class_name.startswith("["):
            return None

        class_name = self._convert_type_to_type_signature(class_name)

        # Append the method
        method = MethodObject(
            class_name=class_name,
            name=method_name,
            descriptor=descriptor,
            cache=R2Cache(json_obj["vaddr"], is_imported),
        )

        return method

    @functools.lru_cache
    def _get_methods_classified(self):
        """
        Parse all methods in the specified Dex and convert them into a
        dictionary. The dictionary takes their belonging classes as the keys.
        Then, it categorizes them into lists.

        :return: a dictionary taking a class name as the key and a list of
        MethodObject as the corresponding value.
        """
        method_json_list = self._r2.cmdj("isj")
        method_dict = defaultdict(list)
        for json_obj in method_json_list:
            method = self._parse_method_from_isj_obj(json_obj)

            if method:
                method_dict[method.class_name].append(method)

        # Remove duplicates
        for class_name, method_list in method_dict.items():
            method_dict[class_name] = remove_dup_list(method_list)

        return method_dict

    @functools.cached_property
    def permissions(self) -> List[str]:
        """
        Inherited from baseapkinfo.py.
        Return the permissions used by the sample.

        :return: a list of permissions.
        """
        if not self._manifest:
            return []

        axml = AxmlReader(self._manifest, core_library="radare2")
        elm_key_name = "{http://schemas.android.com/apk/res/android}name"
        permission_list = set()
        for elm in axml.get_xml_tree().iter("uses-permission"):
            permission = elm.attrib.get(elm_key_name)
            permission_list.add(permission)

        return permission_list

    @functools.cached_property
    def application(self) -> XMLElement:
        """Get the application element from the manifest file.

        :return: an application element
        """
        if not self._manifest:
            return None

        axml = AxmlReader(self._manifest, core_library="radare2")
        root = axml.get_xml_tree()

        return root.find("application")

    @functools.cached_property
    def activities(self) -> List[XMLElement]:
        """
        Return all activity from given APK.

        :return: a list of all activities
        """
        if not self._manifest:
            return None

        axml = AxmlReader(self._manifest, core_library="radare2")
        root = axml.get_xml_tree()

        return root.findall("application/activity")

    @functools.cached_property
    def receivers(self) -> List[XMLElement]:
        """
        Return all receivers from the given APK.

        :return: a list of all receivers
        """
        if not self._manifest:
            return None

        axml = AxmlReader(self._manifest, core_library="radare2")
        root = axml.get_xml_tree()

        return root.findall("application/receiver")

    @property
    def android_apis(self) -> Set[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Return all Android native APIs used by the sample.

        :return: a set of MethodObjects
        """
        return {
            method
            for method in self.all_methods
            if method.is_android_api() and method.cache.is_imported
        }

    @property
    def custom_methods(self) -> Set[MethodObject]:
        """_
        Inherited from baseapkinfo.py.
        Return all custom methods declared by the sample.

        :return: a set of MethodObjects
        """
        return {
            method
            for method in self.all_methods
            if not method.cache.is_imported
        }

    @functools.cached_property
    def all_methods(self) -> Set[MethodObject]:
        """_
        Inherited from baseapkinfo.py.
        Return all methods including Android native APIs and custom methods
        declared in the sample.

        :return: a set of MethodObjects
        """
        method_set = set()
        for method_list in self._get_methods_classified().values():
            method_set.update(method_list)

        return method_set

    def find_method(
        self,
        class_name: Optional[str] = ".*",
        method_name: Optional[str] = ".*",
        descriptor: Optional[str] = ".*",
    ) -> List[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Find a method with the given class name, method name, and descriptor.

        :param class_name: the class name of the target method. Defaults to
        ".*"
        :param method_name: the method name of the target method. Defaults to
        ".*"
        :param descriptor: the descriptor of the target method. Defaults to
        ".*"
        :return: a list of the target MethodObject
        """
        if not class_name:
            class_name = ".*"

        if not method_name:
            method_name = ".*"

        if method_name != ".*":
            method_name = re.escape(method_name)

        if not descriptor:
            descriptor = ".*"

        if descriptor != ".*":
            descriptor = re.escape(descriptor)

        def method_filter(method):
            return re.match(method_name, method.name) and re.match(
                descriptor, method.descriptor
            )

        filtered_methods = list()

        if class_name != ".*":
            method_dict = self._get_methods_classified()
            filtered_methods += list(
                filter(method_filter, method_dict[class_name])
            )
        else:
            method_dict = self._get_methods_classified()
            for key_name in method_dict:
                filtered_methods += list(
                    filter(method_filter, method_dict[key_name])
                )

        return filtered_methods

    @functools.lru_cache
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Find the xrefs from the specified method.

        :param method_object: a target method which the returned methods
        should call
        :return: a set of MethodObjects
        """
        cache = method_object.cache

        xrefs = self._r2.cmdj(f"axtj @ {cache.address}")
        upperfunc_set = set()
        for xref in xrefs:
            if xref["type"] != "CALL":
                continue

            if "from" in xref:
                matched_method = self._get_method_by_address(xref["from"])
                if not matched_method:
                    logging.debug(
                        f"Cannot identify function at {xref['from']}."
                    )
                    continue

                upperfunc_set.add(matched_method)
            else:
                logging.debug(
                    f"Key from was not found when trying to search"
                    f" upper methods of {method_object}."
                )

        return upperfunc_set

    @functools.lru_cache
    def lowerfunc(
        self, method_object: MethodObject
    ) -> Set[Tuple[MethodObject, int]]:
        """
        Inherited from baseapkinfo.py.
        Find the xrefs to the specified method.

        :param method_object: a target method used to find what methods it
        calls
        :return: a set of tuples consisting of the called method and the
        offset of the invocation
        """
        cache = method_object.cache

        instruct_flow = self._r2.cmdj(f"pdfj @ {cache.address}")["ops"]

        lowerfunc_list = []
        for ins in instruct_flow:
            if "refs" in ins:
                call_xrefs = (
                    xref
                    for xref in ins["refs"]
                    if xref["type"] == "CALL"
                )

                for call_xref in call_xrefs:
                    lowerfunc = self._get_method_by_address(call_xref["addr"])
                    if not lowerfunc:
                        logging.debug(
                            f"Cannot identify function at {call_xref['addr']}."
                        )
                        continue

                    offset = ins["offset"] - cache.address

                    lowerfunc_list.append((lowerfunc, offset))

        return lowerfunc_list

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
        cache = method_object.cache
        if not cache.is_imported:

            instruct_flow = self._r2.cmdj(f"pdfj @ {cache.address}")["ops"]
            if instruct_flow:
                for ins in instruct_flow:
                    if "disasm" not in ins:
                        continue

                    yield self._parse_smali(ins["disasm"])

    def get_strings(self) -> Set[str]:
        """
        Inherited from baseapkinfo.py.
        Return all strings in the sample.

        :return: a set of strings
        """
        strings = set()
        string_detail_list = self._r2.cmdj("izzj")
        strings.update(
            [string_detail["string"] for string_detail in string_detail_list]
        )

        return strings

    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:
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

        def convert_bytecode_to_list(bytecode):
            return [bytecode.mnemonic] + bytecode.registers \
                + [bytecode.parameter]

        cache = parent_method.cache

        result = {
            "first": None,
            "first_hex": None,
            "second": None,
            "second_hex": None,
        }

        search_pattern = "{class_name}.{name}{descriptor}"
        first_method_pattern = search_pattern.format(
            class_name=first_method.class_name[:-1],
            name=first_method.name,
            descriptor=first_method.descriptor,
        )
        second_method_pattern = search_pattern.format(
            class_name=second_method.class_name[:-1],
            name=second_method.name,
            descriptor=second_method.descriptor,
        )

        if cache.is_imported:
            return {}

        instruction_flow = self._r2.cmdj(f"pdfj @ {cache.address}")["ops"]

        if instruction_flow:
            for ins in instruction_flow:
                # Skip the instruction without disam  field.
                if "disam" not in ins:
                    continue

                if ins["disasm"].startswith("invoke"):
                    if ";" in ins["disasm"]:
                        index = ins["disasm"].rindex(";")
                        instrcution_string = ins["disasm"][:index]

                    if first_method_pattern in instrcution_string:
                        result["first"] = convert_bytecode_to_list(
                            self._parse_smali(instrcution_string)
                        )
                        result["first_hex"] = " ".join(
                            map(
                                lambda r: r.group(0),
                                re.finditer(r"\w{2}", ins["bytes"]),
                            )
                        )
                    if second_method_pattern in instrcution_string:
                        result["second"] = convert_bytecode_to_list(
                            self._parse_smali(instrcution_string)
                        )
                        result["second_hex"] = " ".join(
                            map(
                                lambda r: r.group(0),
                                re.finditer(r"\w{2}", ins["bytes"]),
                            )
                        )

        return result

    @functools.cached_property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        """
        Inherited from baseapkinfo.py.
        Return a dictionary holding the inheritance relationship of classes in
        the sample. The dictionary takes a class name as the key and the
        corresponding superclass as the value.

        :return: a dictionary taking a class name as the key and the
        corresponding superclass as the value.
        """
        hierarchy_dict = defaultdict(set)

        class_info_list = self._r2.cmdj("icj")
        for class_info in class_info_list:
            class_name = class_info["classname"]
            class_name = self._convert_type_to_type_signature(class_name)
            super_classes = class_info["super"]

            for super_class in super_classes:
                hierarchy_dict[class_name].add(super_class)

        return hierarchy_dict

    @functools.cached_property
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
        hierarchy_dict = defaultdict(set)

        class_info_list = self._r2.cmdj("icj")
        for class_info in class_info_list:
            class_name = class_info["classname"]
            super_class = class_info["super"]

            hierarchy_dict[super_class].add(class_name)

        return hierarchy_dict

    def _get_method_by_address(self, address: int) -> MethodObject:
        """
        Find a method via a specified address.

        :param address: an address used to find the corresponding method
        :return: the MethodObject of the method in the given address
        """
        json_data = self._r2.cmdj(f"is.j @ {address}")
        json_data = json_data.get("symbols")

        if json_data:
            return self._parse_method_from_isj_obj(json_data)
        else:
            return None

    def _get_string_by_address(self, address: str) -> str:
        """
        Find the content of string via the specified string address.

        :param address: an address used to find the corresponding method
        :return: the content in the given address
        """
        content = self._r2.cmd(f"pfq z @ {int(address, 16)}")
        return content

    @staticmethod
    def _parse_parameter(parameter: str, p_type: str = "int") -> Any:
        """Parse the value of the parameter based on the mnemonic.

        :param mnemonic: the mnemonic of a bytecode
        :param parameter: the parameter of a bytecode
        :return: the value of the parameter
        """
        if p_type == "int":
            try:
                parameter = int(parameter, 16)
            except (TypeError, ValueError):
                return R2Imp._parse_parameter(parameter, "float")

        elif p_type == "float":
            try:
                parameter = float(parameter)
            except (TypeError, ValueError):
                return R2Imp._parse_parameter(parameter, "str")

        elif p_type == "str":
            parameter = re.sub(r"\.", ";->", parameter, count=1)
            # Skip extra parameter. e.g. 0x18a or space
            parameter = parameter.split(" ;")[0]

        return parameter

    def _parse_smali(self, smali: str) -> BytecodeObject:
        """
        Convert a Smali code provided by the R2 command `pdfj` into a
        BytecodeObject.

        :param smali: a Smali code provided by the R2 command `pdfj`
        :raises ValueError: if the Smali code follows an unknown format
        :return: a BytecodeObject
        """
        if smali == "":
            raise ValueError("Argument cannot be empty.")

        if " " not in smali:
            return BytecodeObject(smali, None, None)

        mnemonic, args = smali.split(maxsplit=1)  # Split into twe parts

        args = [arg.strip() for arg in re.split("[{},]+", args) if arg]

        if mnemonic == "const-string" and args[-1][:2] == "0x":
            args[-1] = self._get_string_by_address(args[-1])

        parameter = None
        # Remove the parameter at the last
        if args and not args[-1].startswith("v"):
            parameter = R2Imp._parse_parameter(args[-1])
            args = args[:-1]

        register_list = []
        # Ranged registers
        if len(args) == 1 and (":" in args[0] or ".." in args[0]):
            register_list = args[0]
            register_list = [
                int(reg[1:]) for reg in re.split("[:.]+", register_list) if reg
            ]

            if ".." in args[0]:
                register_list = range(register_list[0], register_list[1] + 1)

        # Simple registers
        elif len(args) != 0:
            try:
                register_list = [int(arg[1:]) for arg in args]
            except ValueError:
                raise ValueError(
                    f"Cannot parse bytecode. Unknown smali {smali}."
                )

        register_list = [f"v{index}" for index in register_list]

        return BytecodeObject(mnemonic, register_list, parameter)
