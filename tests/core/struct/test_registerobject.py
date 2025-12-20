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

    def test_iterate_involved_calls_returns_nested_calls(self):
        inner_call = MethodCall(
            "Lfoo/Bar;->first()V", (Primitive("alpha", "Ljava/lang/String;"),)
        )
        outer_call = MethodCall(
            "Lfoo/Bar;->second()V", (inner_call, Primitive("beta", "I"))
        )
        register_obj = RegisterObject("value", outer_call)

        calls = list(register_obj.iterateInvolvedCalls())

        assert calls == [outer_call, inner_call]

    def test_iterate_involved_calls_with_multiple_sources(self):
        shared_inner_call = MethodCall(
            "Lfoo/Bar;->shared()V", (Primitive("1", "I"),)
        )
        first_call = MethodCall(
            "Lfoo/Bar;->first()V", (shared_inner_call,)
        )
        second_call = MethodCall(
            "Lfoo/Bar;->second()V", (Primitive("value", "Ljava/lang/String;"),)
        )

        register_obj = RegisterObject("value", first_call)
        register_obj.called_by_func = second_call

        calls = list(register_obj.iterateInvolvedCalls())

        assert calls == [first_call, shared_inner_call, second_call]

    def test_iterate_involved_calls_empty_when_no_history(self):
        register_obj = RegisterObject("value")

        assert list(register_obj.iterateInvolvedCalls()) == []
