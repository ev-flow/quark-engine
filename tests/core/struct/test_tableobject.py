from typing import Generator
import pytest

from quark.core.struct.tableobject import TableObject


@pytest.fixture()
def table_obj() -> Generator[TableObject, None, None]:
    table_obj = TableObject()

    yield table_obj

    del table_obj


class TestTableObject:
    def test_insert_with_number_once(self, table_obj):
        index, data = 1, "Value"

        table_obj.insert(index, data)

        assert table_obj.getRegValues(index) == [data]

    def test_insert_with_number_twice(self, table_obj):
        table_obj.insert(0, "first")
        table_obj.insert(0, "second")

        assert table_obj.getRegValues(0) == ["first", "second"]

    def test_getRegValues_before_insertion(self, table_obj):
        assert table_obj.getRegValues(3) == []

    def test_getRegValues_after_insertion(self, table_obj):
        table_obj.insert(3, "test_value")

        assert table_obj.getRegValues(3) == ["test_value"]

    def test_getTable(self, table_obj):
        assert table_obj.hash_table == table_obj.getTable()

    def test_getLatestRegValue_none(self, table_obj):
        with pytest.raises(IndexError):
            _ = table_obj.getLatestRegValue(1)

    def test_getLatestRegValue_value(self, table_obj):
        table_obj.insert(4, "one")
        table_obj.insert(4, "two")
        table_obj.insert(4, "three")

        assert table_obj.getLatestRegValue(4) == "three"
        assert table_obj.getRegValues(4) == ["one", "two", "three"]
