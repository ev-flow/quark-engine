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

import rzpipe

from quark.core.axmlreader import AxmlReader
from quark.core.interface.baseapkinfo import BaseApkinfo, XMLElement
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import (
    descriptor_to_androguard_format,
    remove_dup_list,
)

RizinCache = namedtuple("rizin_cache", "address is_imported")

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

RIZIN_ESCAPE_CHAR_LIST = ["<", ">", "$"]


class RizinImp(BaseApkinfo):
    def __init__(
        self,
        apk_filepath: Union[str, PathLike],
        tmp_dir: Union[str, PathLike] = None,
    ):
        super().__init__(apk_filepath, "rizin")

        if self.ret_type == "DEX":
            self._tmp_dir = None
            self._dex_list = [apk_filepath]

        elif self.ret_type == "APK":
            self._tmp_dir = tempfile.mkdtemp() if tmp_dir is None else tmp_dir
            
            if self.isPatched:
                # The APK has been patched to mitigate anti-analysis 
                # techniques. Therefore, Rizin must parse the patched data
                # instead of the original APK.
                self.apk_filepath = os.path.join(self._tmp_dir, "patched.apk")
                with open(self.apk_filepath, "wb") as patchedApk:
                    patchedApk.write(self.data)
                    
                self.data.close()
                self.file.close()

        else:
            raise ValueError("Unsupported File type.")

    @functools.cached_property
    def _rz(self):
        """
        Return a Rizin object that opens the specified Dex file or APK file.

        :return: a Rizin object opening the specified Dex file
        """
        if self.ret_type == "DEX":
            rz = rzpipe.open(f"{self.apk_filepath}")
        elif self.ret_type == "APK":
            rz = rzpipe.open(f"apk://{self.apk_filepath}")

        rz.cmd("aa")
        return rz

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

        return "Ljava/lang/" + raw_type + ";"

    @staticmethod
    def _escape_str_in_rizin_manner(raw_str: str):
        """
        Convert characters with special meanings in Rizin into `_`.
        For now, these characters are `<`, `>` and `$`.

        :param raw_str: a string that may consist of characters with special
        meanings.
        :return: a new string contains no characters with special meanings.
        """
        for c in RIZIN_ESCAPE_CHAR_LIST:
            raw_str = raw_str.replace(c, "_")
        return raw_str

    def _parse_method_from_isj_obj(self, json_obj):
        """
        Parse a JSON object provided by the Rizin command `isj` or `is.j` into
        an instance of MethodObject.

        :param json_obj: a JSON object provided by the Rizin command `isj` or
        `is.j`
        :return: an instance of MethodObject
        """
        if json_obj.get("type") not in ["FUNC", "METH"]:
            return None

        # -- Descriptor --
        full_method_name = json_obj["name"]
        # Skip the starting with "imp."
        if full_method_name[:4] == "imp.":
            full_method_name = full_method_name[4:]

        raw_argument_str = next(
            re.finditer("\\(.*\\).*", full_method_name), None
        )
        if raw_argument_str is None:
            return None

        raw_argument_str = raw_argument_str.group(0)

        if raw_argument_str.endswith(")"):
            # Convert Java lauguage type to JVM type signature

            # Parse the arguments
            raw_argument_str = raw_argument_str[1:-1]
            arguments = [
                self._convert_type_to_type_signature(arg)
                for arg in raw_argument_str.split(", ")
            ]

            # Parse the return type
            return_type = next(
                re.finditer(
                    "[A-Za-zL][A-Za-z0-9L/\\;[\\]$.]+ ", full_method_name
                ),
                None,
            )
            if return_type is None:
                print(f"Unresolved method signature: {full_method_name}")
                return None
            return_type = return_type.group(0).strip()

            # Convert
            raw_argument_str = (
                "("
                + " ".join(arguments)
                + ")"
                + self._convert_type_to_type_signature(return_type)
            )

        descriptor = descriptor_to_androguard_format(raw_argument_str)

        # -- Method name --
        method_name = json_obj["realname"]

        # -- Is imported --
        is_imported = json_obj["is_imported"]

        # -- Class name --
        # Test if the class name is truncated
        escaped_method_name = self._escape_str_in_rizin_manner(method_name)
        if escaped_method_name.endswith("_"):
            escaped_method_name = escaped_method_name[:-1]

        flag_name = json_obj["flagname"]

        # sym.imp.clone doesn't belong to a class
        if flag_name == "sym.imp.clone":
            method = MethodObject(
                class_name="",
                name="clone",
                descriptor="()Ljava/lang/Object;",
                cache=RizinCache(json_obj["vaddr"], is_imported),
            )
            return method

        # Drop the method name
        match = None
        for match in re.finditer("_+[A-Za-z]+", flag_name):
            pass
        if match is None:
            logging.warning(f"Skip the damaged flag: {json_obj['flagname']}")
            return None
        match = match.group(0)
        flag_name = flag_name[: flag_name.rfind(match)]

        # Drop the prefixes sym. and imp.
        while flag_name.startswith("sym.") or flag_name.startswith("imp."):
            flag_name = flag_name[4:]

        class_name = self._convert_type_to_type_signature(flag_name)

        # Append the method
        method = MethodObject(
            class_name=class_name,
            name=method_name,
            descriptor=descriptor,
            cache=RizinCache(json_obj["vaddr"], is_imported),
        )

        return method

    @functools.lru_cache
    def _get_methods_classified(self) -> Dict[str, List[MethodObject]]:
        """
        Use command isj to get all the methods and categorize them into
        a dictionary.

        :return: a dict that holds methods categorized by their class name
        """
        method_json_list = self._rz.cmdj("isj")
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

        axml = AxmlReader(self._manifest)
        permission_list = set()

        for tag in axml:
            label = tag.get("Name")
            if label and axml.get_string(label) == "uses-permission":
                attrs = axml.get_attributes(tag)

                if attrs:
                    permission = axml.get_string(attrs[0].value)
                    permission_list.add(permission)

        return permission_list

    @functools.cached_property
    def application(self) -> XMLElement:
        """Get the application element from the manifest file.

        :return: an application element
        """
        if not self._manifest:
            return None

        axml = AxmlReader(self._manifest)
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

        axml = AxmlReader(self._manifest)
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

        axml = AxmlReader(self._manifest)
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
        :return: a MethodObject of the target method
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
            return re.fullmatch(method_name, method.name) and re.fullmatch(
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

        xrefs = self._rz.cmdj(f"axtj @ {cache.address}")
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

        instruct_flow = self._rz.cmdj(f"pdfj @ {cache.address}")["ops"]

        lowerfunc_list = []
        for ins in instruct_flow:
            if "xrefs_from" in ins:
                call_xrefs = (
                    xref
                    for xref in ins["xrefs_from"]
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

            instruct_flow = self._rz.cmdj(f"pdfj @ {cache.address}")["ops"]
            if instruct_flow:
                for ins in instruct_flow:
                    if "disasm" not in ins:
                        continue

                    disasm_split = ins["disasm"].split()

                    # Skip the bytecode that invoke-kind without registers.
                    # e.g. 'invoke-super', 'Lorg/apache/commons/net/ntp/
                    # TimeInfo;->addComment(Ljava/lang/String;)V'
                    if (disasm_split[0][:6] == "invoke" and
                            disasm_split[0][-6:] != "static"):
                        if (len(disasm_split) < 3 or
                                not re.search(r"v\d+", disasm_split[1])):
                            continue

                    # Skip the bytecode that is not analyzed.
                    # e.g. invoke-virtual method+xxxx .
                    if "method+" in disasm_split[-1]:
                        continue

                    # Skip the bytecode that invoke-custom with improper
                    # descriptor
                    # e.g. invoke-custom {v14, v0},   Resetting:
                    if (disasm_split[0] == "invoke-custom" and
                            "(" not in disasm_split[-1]):
                        continue

                    yield self._parse_smali(ins["disasm"])

    def get_strings(self) -> Set[str]:
        """
        Inherited from baseapkinfo.py.
        Return all strings in the sample.

        :return: a set of strings
        """
        strings = set()
        string_detail_list = self._rz.cmdj("izzj")
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
            return [bytecode.mnemonic] + bytecode.registers +\
                [bytecode.parameter]

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

        instruction_flow = self._rz.cmdj(f"pdfj @ {cache.address}")["ops"]

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

        class_info_list = self._rz.cmdj("icj")
        for class_info in class_info_list:
            class_name = class_info["classname"]
            class_name = self._convert_type_to_type_signature(class_name)
            super_class = class_info["super"]
            super_class = self._convert_type_to_type_signature(super_class)

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

        class_info_list = self._rz.cmdj("icj")
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
        json_array = self._rz.cmdj(f"is.j @ {address}")

        if json_array:
            return self._parse_method_from_isj_obj(json_array[0])
        else:
            return None

    def _get_string_by_address(self, address: str) -> str:
        """
        Find the content of string via the specified string address.

        :param address: an address used to find the corresponding method
        :return: the content in the given address
        """
        content = self._rz.cmd(f"pr @ {int(address, 16)}")
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
                return RizinImp._parse_parameter(parameter, "float")

        elif p_type == "float":
            try:
                parameter = float(parameter)
            except (TypeError, ValueError):
                return RizinImp._parse_parameter(parameter, "str")

        elif p_type == "str":
            parameter = re.sub(r"\.", "->", parameter, count=1)
            # 13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk with 00193.json rule
            parameter = "".join([x for x in parameter if ord(x) > 31])

        return parameter

    def _parse_smali(self, smali: str) -> BytecodeObject:
        """
        Convert a Smali code provided by the Rizin command `pdfj` into a
        BytecodeObject.

        :param smali: a Smali code provided by the Rizin command `pdfj`
        :raises ValueError: if the Smali code follows an unknown format
        :return: a BytecodeObject
        """
        if smali == "":
            raise ValueError("Argument cannot be empty.")

        if " " not in smali:
            return BytecodeObject(smali, None, None)

        mnemonic, args = smali.split(maxsplit=1)  # Split into twe parts

        # invoke-kind instruction may left method index at the last
        # if mnemonic.startswith("invoke"):
        #     args = args[: args.rfind(" ;")]

        # 13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk with 00077.json rule
        # and 13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk with 00193.json rule
        while re.search(r";(\w|\[)", args):
            sub_index = re.search(r";(\w|\[)", args).start()
            args = args[:sub_index+1] + " " + args[sub_index+1:]
        args = [arg.strip() for arg in re.split("[{},]+", args) if arg]

        if mnemonic == "const-string" and args[-1][:2] == "0x":
            args[-1] = self._get_string_by_address(args[-1])

        # "const-string", "v4", "str.SMS"
        if mnemonic == "const-string" and "." in args[-1]:
            args[-1] = args[-1].split(".")[-1]

        # invoke-polymorphic/range {v41783..v41784}, method+38423, proto+515
        # in 14d9f1a92dd984d6040cc41ed06e273e.apk
        if mnemonic.startswith("invoke-polymorphic"):
            args = args[:-1]

        parameter = None
        # Remove the parameter at the last
        if args and not re.match(r"v\d+", args[-1]):
            parameter = RizinImp._parse_parameter(args[-1])
            args = args[:-1]

        # registers thar are missing prefix v
        for i, arg in enumerate(args):
            if arg[0] != "v":
                args[i] = f"v{arg}"

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
