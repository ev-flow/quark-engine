# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import enum
import functools
import os.path
from collections import namedtuple
from typing import Any, Dict, Iterator, List
from xml.etree.ElementTree import Element as XMLElement  # nosec B405
from xml.etree.ElementTree import ElementTree as XMLElementTree  # nosec B405

import importlib.resources

# Resource Types Definition
# Please reference to
# https://android.googlesource.com/platform/frameworks/base/+/master/libs/androidfw/include/androidfw/ResourceTypes.h

# ResChunk_header types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

# Chunk types in RES_XML_TYPE
RES_XML_FIRST_CHUNK_TYPE = 0x0100
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_LAST_CHUNK_TYPE = 0x017F
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# Chunk types in RES_TABLE_TYPE
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_LIBRARY_TYPE = 0x0203
RES_TABLE_OVERLAYABLE_TYPE = 0x0204
RES_TABLE_OVERLAYABLE_POLICY_TYPE = 0x0205

ResChunkHeader = Dict[str, Any]
ResValue = namedtuple(
    "ResValue", ["namespace", "name", "type", "value", "data"]
)


class Res_value_type(enum.Enum):
    """
    List all possible types of a value in the Android XML binary.
    """

    TYPE_NULL = 0x00
    TYPE_REFERENCE = 0x01
    TYPE_ATTRIBUTE = 0x02
    TYPE_STRING = 0x03
    TYPE_FLOAT = 0x04
    TYPE_DIMENSION = 0x05
    TYPE_FRACTION = 0x06
    TYPE_DYNAMIC_REFERENCE = 0x07
    TYPE_DYNAMIC_ATTRIBUTE = 0x08
    TYPE_FIRST_INT = 0x10
    TYPE_INT_DEC = 0x10
    TYPE_INT_HEX = 0x11
    TYPE_INT_BOOLEAN = 0x12
    TYPE_FIRST_COLOR_INT = 0x1C
    TYPE_INT_COLOR_ARGB8 = 0x1C
    TYPE_INT_COLOR_RGB8 = 0x1D
    TYPE_INT_COLOR_ARGB4 = 0x1E
    TYPE_INT_COLOR_RGB4 = 0x1F
    TYPE_LAST_COLOR_INT = 0x1F
    TYPE_LAST_INT = 0x1F


class AxmlException(Exception):
    """
    A Exception for AxmlReader
    """

    def __init__(self, message):
        super(AxmlException, self).__init__(message)


class AxmlReader:
    """
    A Class that parses the Android XML file using Rizin/Radare2
    """

    def __init__(self, file_path, core_library="rizin", structure_path=None):

        base_path = f"quark.core.axmlreader.{core_library}"
        axmlDefinitionPath = (
            importlib.resources.files(base_path) / "axml_definition"
        )
        with importlib.resources.as_file(
                axmlDefinitionPath) as axmlDefinitionFile:
            if structure_path is None:
                structure_path = axmlDefinitionFile

        if not os.path.isfile(structure_path):
            raise AxmlException(
                f"Cannot find printing format definition file"
                f" of {core_library} in {structure_path}"
            )

        if core_library == "rizin":
            try:
                import rzpipe
            except ModuleNotFoundError:
                raise AxmlException(
                    "--core-library rizin requires the 'rizin' extra:"
                    " pip install quark-engine[rizin]"
                    " (also requires the rizin binary itself)"
                )
            self._core = rzpipe.open(file_path)
        elif core_library == "radare2":
            try:
                import r2pipe
            except ModuleNotFoundError:
                raise AxmlException(
                    "--core-library radare2 requires the 'radare2' extra:"
                    " pip install quark-engine[radare2]"
                    " (also requires the radare2 binary itself)"
                )
            self._core = r2pipe.open(file_path)

        self._core.cmd(f"pfo {structure_path}")

        self._file_size = int(self._core.cmd("i~size[1]"), 16)
        self._ptr = 0

        self._cache = {}

        if self._file_size > 0xFFFF_FFFF:
            raise AxmlException("Filesize exceeds theoretical upper bound.")
        elif self._file_size < 8:
            raise AxmlException("Filesize exceeds theoretical lower bound.")

        # File Header
        header = self._core.cmdj("pfj axml_ResChunk_header @ 0x0")

        self._data_type = header[0]["value"]
        self._axml_size = header[2]["value"]
        header_size = header[1]["value"]

        if self._data_type != RES_XML_TYPE or header_size != 0x8:
            raise AxmlException(
                f"Error parsing first header(type: {self._data_type},"
                f" size: {header_size})."
            )

        if self._axml_size > self._file_size:
            raise AxmlException(
                f"Decleared size ({self._axml_size} bytes) is"
                f" larger than total size({self._file_size})."
            )

        self._ptr += 8
        if self._ptr >= self._axml_size:
            return

        # String Pool
        string_pool_header = self._core.cmdj(
            "pfj axml_ResStringPool_header @ 8"
        )

        string_pool_size = string_pool_header[0]["value"][2]["value"]

        if string_pool_size > self._axml_size - self._ptr:
            raise AxmlException(
                f"Error parsing string pool, there should"
                f" be {string_pool_size}"
                f" bytes but only {self._axml_size - self._ptr} bytes."
            )

        header = string_pool_header[0]["value"]
        header_type = header[0]["value"]
        header_size = header[1]["value"]

        if header_type != RES_STRING_POOL_TYPE:
            raise AxmlException(
                f"Error parsing string pool, expect string pool"
                f" data at {self._ptr} bytes."
            )

        if header_size != 28:
            raise AxmlException(
                f"Error parsing string pool, heardsize should "
                f"be 16 bytes rather than { header_size } bytes."
            )

        self._stringCount = string_pool_header[1]["value"]
        self._isUtf8Used = (string_pool_header[3]["value"] & (1 << 8)) != 0
        stringStart = string_pool_header[4]["value"]

        self._core.cmd(f"f string_pool_header @ 0x8 ")
        string_pool_index = header_size + self._ptr
        self._core.cmd(f"f string_pool_index @ { string_pool_index }")
        string_pool_data = stringStart + self._ptr
        self._core.cmd(f"f string_pool_data @ { string_pool_data }")

        self._ptr += string_pool_size
        if self._ptr >= self._axml_size:
            return

        # Resource Map (Optional)
        header = self._core.cmdj(f"pfj axml_ResChunk_header @ {self._ptr}")

        header_type = header[0]["value"]
        if header_type == RES_XML_RESOURCE_MAP_TYPE:
            map_size = header[2]["value"]

            # Skip all the resource map

            if map_size > self._axml_size - self._ptr:
                raise AxmlException(
                    f"Map size should be {map_size} bytes rather"
                    f" than {self._axml_size - self._ptr} bytes."
                )

            self._ptr += map_size
            if self._ptr >= self._axml_size:
                return

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __iter__(self) -> Iterator[ResChunkHeader]:
        """Get an iterator that walks through the content of the Android XML
         binary.

        :raises AxmlException: if the given file is not a valid Android XML
         binary
        :yield: header of a resource chunk defined in the binary
        """
        while self._axml_size - self._ptr >= 16:
            header = self._core.cmdj(f"pfj axml_ResXMLTree_node @ {self._ptr}")

            node_type = header[0]["value"][0]["value"]
            header_size = header[0]["value"][1]["value"]
            node_size = header[0]["value"][2]["value"]

            if header_size != 16:
                raise AxmlException(
                    f"heardsize should be 16 bytes rather"
                    f" than { header_size } bytes."
                )

            if node_size > self._axml_size - self._ptr:
                raise AxmlException(
                    f"Not enough data left, need {node_size} bytes"
                    f" but {self._axml_size - self._ptr} bytes left."
                )

            ext_ptr = self._ptr + 16

            chunk = {"Address": self._ptr, "Type": node_type}

            if node_type == RES_XML_START_ELEMENT_TYPE:
                ext = self._core.cmdj(
                    f"pfj axml_ResXMLTree_attrExt @ { ext_ptr }"
                )

                chunk["Namespace"] = ext[0]["value"][0]["value"]
                chunk["Name"] = ext[1]["value"][0]["value"]

                # Attributes
                # node['AttrCount'] = ext[4]['value']

            elif node_type == RES_XML_END_ELEMENT_TYPE:
                ext = self._core.cmdj(
                    f"pfj axml_ResXMLTree_endElementExt @ { ext_ptr }"
                )

                chunk["Namespace"] = ext[0]["value"][0]["value"]
                chunk["Name"] = ext[1]["value"][0]["value"]

            elif node_type in [
                RES_XML_START_NAMESPACE_TYPE,
                RES_XML_END_NAMESPACE_TYPE,
            ]:
                ext = self._core.cmdj(
                    f"pfj axml_ResXMLTree_namespaceExt @ { ext_ptr }"
                )

                chunk["Prefix"] = ext[0]["value"][0]["value"]
                chunk["Uri"] = ext[1]["value"][0]["value"]

            elif node_type == RES_XML_CDATA_TYPE:
                ext = self._core.cmdj(
                    f"pfj axml_ResXMLTree_cdataExt @ { ext_ptr }"
                )

                chunk["Data"] = ext[0]["value"][0]["value"]
                # typedData

            else:
                self._ptr = self._ptr + node_size
                continue

            self._ptr = self._ptr + node_size
            yield chunk

    @property
    def file_size(self):
        return self._file_size

    @property
    def axml_size(self):
        return self._axml_size

    @functools.lru_cache()
    def get_string(self, index):
        if index < 0 or index >= self._stringCount:
            return None
        if self._isUtf8Used:
            stringFormat = "z"
            stringKey = "value"
        else:
            stringFormat = "Z"
            stringKey = "string"

        return self._core.cmdj(
            f"pfj {stringFormat} @ string_pool_data + `pfv n4 "
            f"@ string_pool_index+ {index}*4` + 2"
        )[0][stringKey]

    def get_attributes(self, chunk: ResChunkHeader) -> List[ResValue]:
        """Get the attributes of a resource chunk

        :param chunk: header of a resource chunk
        :return: python list that holds attributes
        """
        if chunk["Type"] != RES_XML_START_ELEMENT_TYPE:
            return None
        extAddress = int(chunk["Address"]) + 16

        attrExt = self._core.cmdj(
            f"pfj axml_ResXMLTree_attrExt @ {extAddress}"
        )

        attrAddress = extAddress + attrExt[2]["value"]
        attributeSize = attrExt[3]["value"]
        attributeCount = attrExt[4]["value"]
        attributes = []
        for _ in range(attributeCount):
            attr = self._core.cmdj(
                f"pfj axml_ResXMLTree_attribute @ {attrAddress}"
            )

            value = ResValue(
                namespace=attr[0]["value"][0]["value"],
                name=attr[1]["value"][0]["value"],
                value=attr[2]["value"][0]["value"],
                type=attr[3]["value"][2]["value"],
                data=attr[3]["value"][3]["value"],
            )
            attributes.append(value)

            attrAddress = attrAddress + attributeSize

        return attributes

    def __convert_tag_to_xml_element(
        self, chunk: ResChunkHeader
    ) -> XMLElement:
        """Convert a resource chunk in the Android XML binary into an
         XMLElement instance.

        :param chunk: header of a resource chunk in the Android XML binary
        :return: XMLElement instance
        """
        name = self.get_string(chunk["Name"])

        attributes = {}
        for raw_attribute in self.get_attributes(chunk):
            attr_namespace = self.get_string(raw_attribute.namespace)
            attr_name = self.get_string(raw_attribute.name)

            data_type = raw_attribute.type
            raw_data = raw_attribute.data
            if data_type == Res_value_type.TYPE_STRING.value:
                value = self.get_string(raw_data)
            elif data_type == Res_value_type.TYPE_INT_BOOLEAN.value:
                value = bool(abs(raw_data))
            else:
                value = raw_attribute.data

            if attr_namespace:
                attr_name = "{" + attr_namespace + "}" + attr_name

            attributes[attr_name] = value

        return XMLElement(name, attributes)

    def _find_manifest(
        self, chunk_iterator: Iterator[ResChunkHeader]
    ) -> XMLElement:
        """Find the resource chunk of the first XML label named manifest and
         convert it into an XMLElement instance.

        :param chunk_iterator: iterator of the resource chunk headers
        :return: XMLElement instance
        """
        manifest_chunk = next(
            (
                chunk
                for chunk in chunk_iterator
                if chunk["Type"] == RES_XML_START_ELEMENT_TYPE
                and self.get_string(chunk["Name"]) == "manifest"
            ),
            None,
        )

        if manifest_chunk:
            return self.__convert_tag_to_xml_element(manifest_chunk)

    def get_xml_tree(self) -> XMLElementTree:
        """
        Return the parsed XML corresponding to the AndroidManifest.xml file.

        :return: the content of the file
        """
        file_iterator = iter(self)
        root = self._find_manifest(file_iterator)

        stack = [root]
        for tag in file_iterator:
            tag_type = tag["Type"]

            if tag_type == RES_XML_END_ELEMENT_TYPE:
                stack.pop()

            elif tag_type == RES_XML_START_ELEMENT_TYPE:
                element = self.__convert_tag_to_xml_element(tag)

                parent = stack[-1]
                parent.append(element)

                stack.append(element)

        return XMLElementTree(root)

    def __del__(self):
        try:
            self._core.quit()
        except BaseException:
            pass
