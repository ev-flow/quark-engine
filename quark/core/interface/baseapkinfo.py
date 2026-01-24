# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import hashlib
import io
import mmap
import os.path
from abc import abstractmethod
from os import PathLike
import tempfile
from typing import Dict, List, Literal, Optional, Set, Union, Tuple
from xml.etree.ElementTree import Element as XMLElement  # nosec B405
import zipfile

from quark.core.apkpatcher import ApkPatcher, SeekableMMap
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.core.axmlreader.python import PythonImp as AxmlReader


class BaseApkinfo:

    __slots__ = [
        "ret_type",
        "apk_filename",
        "apk_filepath",
        "core_library",
        "file",
        "data",
        "isPatched",
        "_manifest",
    ]

    def __init__(
            self,
            apk_filepath: str | PathLike,
            core_library: str = "None",
            tmp_dir: str | PathLike | None = None
    ):
        self.file = open(apk_filepath, "rb")
        self.data = SeekableMMap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)
        self.ret_type = self._check_file_signature(self.data)

        if self.ret_type == "APK":
            self.isPatched = ApkPatcher.patch(self.data)
            self._manifest = self.__extractAndroidManifest(self.data, tmp_dir)
        else:
            self.isPatched = False
            self._manifest = None

        self.apk_filename = os.path.basename(apk_filepath)
        self.apk_filepath = apk_filepath
        self.core_library = core_library


    def __repr__(self) -> str:
        return f"<Apkinfo-APK:{self.apk_filename}, Imp:{self.core_library}>"

    def __del__(self):
        self.data.close()
        self.file.close()

    def __extractAndroidManifest(
        self, data: SeekableMMap, tmp_dir: str | PathLike | None
    ) -> str | None:
        tmp_dir = tempfile.mkdtemp() if tmp_dir is None else tmp_dir

        with zipfile.ZipFile(data, "r") as apk:  # type: ignore
            apk.extract("AndroidManifest.xml", path=tmp_dir)
            return os.path.join(tmp_dir, "AndroidManifest.xml")

    @property
    def filename(self) -> str:
        """
        Return the filename of apk.

        :return: a string of apk filename
        """
        return os.path.basename(self.apk_filepath)

    @property
    def filesize(self) -> int:
        """
        Return the file size of apk file by bytes.

        :return: a number of size bytes
        """
        return os.path.getsize(self.apk_filepath)

    @property
    def md5(self) -> str:
        """
        Return the md5 checksum of the apk file.

        :return: a string of md5 checksum of the apk file
        """
        md5 = hashlib.md5()
        with open(self.apk_filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()

    @property
    def permissions(self) -> List[str]:
        """
        Return all permissions from given APK.

        :return: a list of all permissions
        """
        if self.ret_type != "APK":
            return []

        with AxmlReader(self._manifest) as axml:
            permissionList = set()

            for tag in axml:
                label = tag.get("Name")
                if label and axml.get_string(label) == "uses-permission":
                    attrs = axml.get_attributes(tag)

                    if attrs:
                        permission = axml.get_string(attrs[0].value)
                        permissionList.add(permission)

            return list(permissionList)

    @property
    def application(self) -> XMLElement | None:
        """Get the application element from the manifest file.

        :return: an application element
        """
        if self.ret_type != "APK":
            return None

        with AxmlReader(self._manifest) as axml:
            root = axml.get_xml_tree()

            return root.find("application")

    @property
    def activities(self) -> List[XMLElement] | None:
        """
        Return all activity from given APK.

        :return: a list of all activities
        """
        if self.ret_type != "APK":
            return None

        with AxmlReader(self._manifest) as axml:
            root = axml.get_xml_tree()

            return root.findall("application/activity")

    @property
    def receivers(self) -> List[XMLElement] | None:
        """
        Return all receivers from the given APK.

        :return: a list of all receivers
        """
        if self.ret_type != "APK":
            return None

        with AxmlReader(self._manifest) as axml:
            root = axml.get_xml_tree()

            return root.findall("application/receiver")

    @property
    def providers(self) -> List[XMLElement] | None:
        """Get provider elements from the manifest file.

        :return: python list containing provider elements
        """
        if self.ret_type != "APK":
            return None

        with AxmlReader(self._manifest) as axml:
            root = axml.get_xml_tree()

            return root.findall("application/provider")

    @property
    @abstractmethod
    def android_apis(self) -> Set[MethodObject]:
        """
        Returns all Android APIs used by the APK/DEX.

        :return: a set of MethodObjects
        """
        pass

    @property
    @abstractmethod
    def custom_methods(self) -> Set[MethodObject]:
        """
        Return all custom methods from given APK.

        :return: a set of all custom methods MethodObject
        """
        pass

    @property
    def all_methods(self) -> Set[MethodObject]:
        """
        Return all methods including Android native API and custom methods
        from given APK.

        :return: a set of all method MethodObject
        """
        pass

    @abstractmethod
    def find_method(
        self,
        class_name: Optional[str] = ".*",
        method_name: Optional[str] = ".*",
        descriptor: Optional[str] = ".*",
    ) -> List[MethodObject]:
        """
        Find method from given class_name, method_name and the descriptor.
        default is find all method.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :param descriptor: the descriptor of the Android API
        :return: a list with MethodObjects
        """
        pass

    @abstractmethod
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the xref from method from given MethodObject instance.

        :param method_object: the MethodObject instance
        :return: a set of all xref from functions
        """
        pass

    @abstractmethod
    def lowerfunc(
        self, method_object: MethodObject
    ) -> list[Tuple[MethodObject, int]]:
        """
        Find the xrefs to the specified method.

        :param method_object: a target method used to find what methods it
        calls
        :return: a set of tuples consisting of the called method and the
        offset of the invocation
        """
        pass

    @abstractmethod
    def get_method_bytecode(self, method_object: MethodObject) \
            -> Set[MethodObject]:
        """
        Return the corresponding bytecode according to the
        given class name and method name.

        :param method_object: the MethodObject instance
        :return: a generator of all bytecode instructions
        """
        pass

    @abstractmethod
    def get_strings(self) -> str:
        pass

    @abstractmethod
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:
        """
        Find the invocations that call two specified methods, first_method
        and second_method, respectively. Then, return a dictionary storing
        the corresponding bytecodes and hex values.

        :param parent_method: a parent method to scan
        :param first_method: the first method called by the parent method
        :param second_method: the second method called by the parent method
        :return: a dictionary storing the corresponding bytecodes and hex
        values.
        """
        pass

    @property
    @abstractmethod
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        pass

    @property
    def get_subclasses(self, class_name) -> Set[str]:
        pass

    @staticmethod
    def _check_file_signature(
        raw: mmap.mmap,
    ) -> Literal["DEX", "APK", "AXML", None]:
        if raw[0:3] == b"dex":
            return "DEX"
        elif raw[0:2] == b"PK":
            return "APK"
        elif raw[0:4] in [b"\x03\x00\x08\x00", b"\x00\x00\x08\x00"]:
            return "AXML"
        else:
            return None
