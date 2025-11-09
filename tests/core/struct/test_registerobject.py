import pytest

from quark.core.struct.registerobject import RegisterObject


@pytest.fixture()
def standard_register_obj():
    register_obj = RegisterObject("value", "func")
    yield register_obj

    del register_obj


class TestRegisterObject:
    def test_init_without_called_by_func(self):
        register_obj = RegisterObject("value")

        assert register_obj._value == "value"
        assert register_obj._called_by_func == []

    def test_init_with_called_by_func(self):
        register_obj = RegisterObject("value", "func")

        assert register_obj._value == "value"
        assert register_obj._called_by_func == ["func"]

    def test_called_by_func(self, standard_register_obj):
        value = "func1"

        standard_register_obj.called_by_func = value

        assert len(standard_register_obj.called_by_func) == 2
        assert standard_register_obj.called_by_func[-1] == value

    def test_value(self, standard_register_obj):
        value = "value"

        standard_register_obj.value = value

        assert standard_register_obj.value == value

    def test_bears_object(self):
        reg_with_object = RegisterObject("value", value_type="Ljava/lang/String;")
        reg_with_primitive = RegisterObject("value", value_type="I")
        reg_with_none = RegisterObject("value", value_type=None)

        assert reg_with_object.bears_object() is True
        assert reg_with_primitive.bears_object() is False
        assert reg_with_none.bears_object() is False
