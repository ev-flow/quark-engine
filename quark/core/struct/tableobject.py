# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from collections import defaultdict
from typing import Callable
from quark.core.struct.registerobject import RegisterObject


class TableObject:
    """This table is used to track the usage of variables in the register"""

    __slots__ = ["hash_table"]

    def __init__(self):
        self.hash_table = defaultdict(list)

    def __repr__(self):
        return f"<TableObject-{self.hash_table}>"

    def insert(self, index: int, registerValue: RegisterObject) -> None:
        """
        Insert RegisterObject into the nested list in the hash table.

        :param index: the index to insert to the table
        :param var_obj: instance of RegisterObject
        :return: None
        """
        self.hash_table[index].append(registerValue)

    def getRegValues(self, index: int) -> list[RegisterObject]:
        """
        Return the list which contains the RegisterObject.

        :param index: the index to get the corresponding RegisterObject
        :return: a list containing RegisterObject
        """
        return self.hash_table[index]

    def getTable(self) -> dict[int, list[RegisterObject]]:
        """
        Get the entire hash table.

        :return: a two-dimensional list
        """
        return self.hash_table

    def getLatestRegValue(self, index: int) -> RegisterObject:
        """
        Get the latest RegisterObject for the given index.

        :param index: the index to get the corresponding RegisterObject
        :return: RegisterObject
        """
        return self.hash_table[index][-1]

    def getOrInsertLatestRegValue(
        self,
        index: int,
        defaultRegisterGenerator: Callable[[], RegisterObject]
    ) -> RegisterObject:
        """
        Get the latest RegisterObject for the given index or insert a new one if it is empty.

        :param index: the index to get the corresponding RegisterObject
        :param defaultRegisterGenerator: the function that generates a RegisterObject
        :return: the latest RegisterObject
        """
        targetRegisterList = self.hash_table[index]
        if not targetRegisterList:
            targetRegisterList.append(defaultRegisterGenerator())

        return targetRegisterList[-1]


if __name__ == "__main__":
    pass
