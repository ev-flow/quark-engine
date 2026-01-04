# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
import pytest
from quark.core.struct.valuenode import (
    Primitive,
    MethodCall,
    BytecodeOps,
    iteratePriorPrimitives,
    iteratePriorCalls,
    evaluateArgument
)


class TestPrimitive:
    def test_resolve_number_and_string(self):
        assert Primitive(123, "I").resolve() == "123"
        assert Primitive("test", None).resolve() == "test"

    def test_eq_is_identity_based(self):
        value = Primitive(True, "Z")
        assert value == value
        assert Primitive(True, "Z") != Primitive(True, "Z")


class TestMethodCall:
    def test_resolve_simple(self):
        mc = MethodCall(
            "do_something", (Primitive("first", None), Primitive(2, "I"))
        )
        assert mc.resolve() == "do_something(first,2)"

    def test_resolve_nested(self):
        inner_call = MethodCall("inner", (Primitive(True, "Z"),))
        outer_call = MethodCall("outer", (Primitive(1, "I"), inner_call))
        assert outer_call.resolve() == "outer(1,inner(True))"

    def test_getArguments_resolves_primitives_and_calls(self):
        nested = MethodCall("inner", (Primitive("text", None),))
        method_call = MethodCall("outer", (Primitive("10", "I"), nested))
        assert method_call.getArguments() == [10, "inner(text)"]


class TestBytecodeOps:
    def test_resolve_simple(self):
        op = BytecodeOps("const-string {data}", (), "Hello")
        assert op.resolve() == "const-string Hello"
        op_none = BytecodeOps("const {data}", (), None)
        assert op_none.resolve() == "const None"
        op_add = BytecodeOps(
            "add-int({src0}, {src1})",
            (Primitive(5, "I"), Primitive(10, "I")),
            None,
        )
        assert op_add.resolve() == "add-int(5, 10)"

    def test_resolve_nested(self):
        inner_op = BytecodeOps("cast({src0})", (Primitive(1.0, "F"),), "int")
        outer_call = MethodCall("use_val", (inner_op,))
        assert outer_call.resolve() == "use_val(cast(1.0))"


class TestIterators:
    @pytest.fixture
    def complex_structure(self):
        """
        Creates a complex nested structure for testing iterators.
        Structure:
            call1 -> [prim1, call2]
            call2 -> [prim2, op1]
            op1 -> [prim3]
        """
        prim1 = Primitive("p1", None)
        prim2 = Primitive(2, "I")
        prim3 = Primitive(True, "Z")
        op1 = BytecodeOps("op({src0})", (prim3,), None)
        call2 = MethodCall("func2", (prim2, op1))
        call1 = MethodCall("func1", (prim1, call2))
        return call1, call2, op1, prim1, prim2, prim3

    def test_iteratePriorCalls(self, complex_structure):
        call1, call2, op1, _, _, _ = complex_structure
        calls = list(iteratePriorCalls(call1))
        assert len(calls) == 2
        assert call1 in calls
        assert call2 in calls
        assert op1 not in calls

    def test_iteratePriorPrimitives(self, complex_structure):
        call1, _, _, prim1, prim2, prim3 = complex_structure
        primitives = list(iteratePriorPrimitives(call1))
        assert primitives.count(prim1) == 1
        assert primitives.count(prim2) == 1
        assert primitives.count(prim3) == 1

    def test_iteratePriorCalls_deduplicates_reused_nodes(self):
        shared_call = MethodCall("shared", (Primitive("x", None),))
        outer = MethodCall("outer", (shared_call, shared_call))
        calls = list(iteratePriorCalls(outer))
        assert calls.count(shared_call) == 1


@pytest.mark.parametrize(
    "value,type_hint,expected",
    [
        ("42", "I", 42),
        ("1", "Z", True),
        ("1.5", "F", 1.5),
        ("not-a-number", "I", "not-a-number"),
        ("plain", None, "plain"),
    ],
)
def test_evaluateArgument_converts_values(value, type_hint, expected):
    assert evaluateArgument(value, type_hint) == expected
