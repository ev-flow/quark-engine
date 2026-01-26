import itertools
from unittest.mock import patch

import pytest

from quark.core.apkinfo import AndroguardImp
from quark.core.struct.registerobject import RegisterObject
from quark.core.struct.tableobject import TableObject
from quark.evaluator.pyeval import PyEval
from quark.core.struct.valuenode import Primitive, MethodCall


@pytest.fixture()
def instructions():
    ins = [
        "invoke-virtual",
        "invoke-direct",
        "move-result-object",
        "new-instance",
        "const-string",
        "const/4",
        "aget-object",
    ]

    yield ins

    del ins


@pytest.fixture(scope="module")
def apkinfo(SAMPLE_PATH_13667):
    apkinfo = AndroguardImp(SAMPLE_PATH_13667)
    yield apkinfo


@pytest.fixture(scope="function")
def pyeval(apkinfo):
    pyeval = PyEval(apkinfo)

    v4_mock_variable_obj = RegisterObject(
        value=Primitive(
            "Lcom/google/progress/SMSHelper;", "Lcom/google/progress/SMSHelper;"
        ),
        value_type="Lcom/google/progress/SMSHelper;",
    )
    v5_mock_variable_obj = RegisterObject(
        value=MethodCall(
            "java.lang.String.toString", (Primitive("some_number", ""),)
        ),
        value_type="I",
    )
    v6_mock_variable_obj = RegisterObject(
        value=MethodCall(
            "java.lang.Collection.toArray", (Primitive("an_array", ""),)
        ),
        value_type="[I",
    )
    v7_mock_variable_obj = RegisterObject(
        value=Primitive("a_float", "F"), value_type="F"
    )
    v8_mock_variable_obj = RegisterObject(
        value=Primitive(
            "ArrayMap object", "Landroid/support/v4/util/ArrayMap;"
        ),
        value_type="Landroid/support/v4/util/ArrayMap;",
    )
    v9_mock_variable_obj = RegisterObject(
        value=Primitive("some_string", "Ljava/lang/String;"),
        value_type="Ljava/lang/String;",
    )
    v9_mock_variable_obj.called_by_func.append(
        MethodCall("java.io.file.close", tuple())
    )

    pyeval.table_obj.insert(4, v4_mock_variable_obj)
    pyeval.table_obj.insert(5, v5_mock_variable_obj)
    pyeval.table_obj.insert(6, v6_mock_variable_obj)
    pyeval.table_obj.insert(7, v7_mock_variable_obj)
    pyeval.table_obj.insert(8, v8_mock_variable_obj)
    pyeval.table_obj.insert(9, v9_mock_variable_obj)

    yield pyeval

    del pyeval


MOVE_KIND = [
    prefix + postfix
    for prefix, postfix in itertools.product(
        ["move", "move-object"], ["", "/from16", "/16"]
    )
] + ["array-length"]
MOVE_WIDE_KIND = ["move-wide" + postfix for postfix in ["", "/from16", "/16"]]


@pytest.fixture(scope="module", params=MOVE_KIND)
def move_kind(request):
    return request.param


@pytest.fixture(scope="module", params=MOVE_WIDE_KIND)
def move_wide_kind(request):
    return request.param


FILLED_ARRAY_KIND = ("filled-new-array", "filled-new-array/range")


@pytest.fixture(scope="module", params=FILLED_ARRAY_KIND)
def filled_array_kind(request):
    return request.param


AGET_KIND = [
    "aget" + postfix
    for postfix in ("", "-object", "-byte", "-char", "-short", "-boolean")
]
AGET_WIDE_KIND = ["aget-wide"]


@pytest.fixture(scope="module", params=AGET_KIND)
def aget_kind(request):
    return request.param


@pytest.fixture(scope="module", params=AGET_WIDE_KIND)
def aget_wide_kind(request):
    return request.param


APUT_KIND = [
    "aput" + postfix
    for postfix in ("", "-object", "-byte", "-char", "-short", "-boolean")
]
APUT_WIDE_KIND = ("aput-wide",)


@pytest.fixture(scope="module", params=APUT_KIND)
def aput_kind(request):
    return request.param


@pytest.fixture(scope="module", params=APUT_WIDE_KIND)
def aput_wide_kind(request):
    return request.param


NEG_NOT_KIND = [
    prefix + postfix
    for prefix, postfix in itertools.product(
        ["neg-", "not-"], ["int", "long", "float"]
    )
]

NEG_NOT_WIDE_KIND = ("neg-double", "not-double")


@pytest.fixture(scope="module", params=NEG_NOT_KIND)
def neg_not_kind(request):
    return request.param


@pytest.fixture(scope="module", params=NEG_NOT_WIDE_KIND)
def neg_not_wide_kind(request):
    return request.param


ALL_CAST_KIND = list(
    {
        prefix + "-" + postfix
        for prefix, postfix in itertools.product(
            ("int", "long", "float", "double"),
            ("int", "long", "float", "double"),
        )
    }.difference(
        {
            "int-int",
            "long-long",
            "float-float",
            "double-double",
            "double-long",
            "long-double",
        }
    )
)

CAST_KIND = [
    ins for ins in ALL_CAST_KIND if "double" not in ins and "long" not in ins
]
CAST_SIMPLE_TO_WIDE_KIND = [
    ins
    for ins in ALL_CAST_KIND
    if ins.endswith("double") or ins.endswith("long")
]
CAST_WIDE_TO_SIMPLE_KIND = [
    ins
    for ins in ALL_CAST_KIND
    if ins.startswith("double") or ins.startswith("long")
]


@pytest.fixture(scope="module", params=CAST_KIND)
def cast_kind(request):
    return request.param


@pytest.fixture(scope="module", params=CAST_SIMPLE_TO_WIDE_KIND)
def cast_simple_to_wide_kind(request):
    return request.param


@pytest.fixture(scope="module", params=CAST_WIDE_TO_SIMPLE_KIND)
def cast_wide_to_simple_kind(request):
    return request.param


_BINOP_PREFIX = (
    "add",
    "sub",
    "mul",
    "div",
    "rem",
    "and",
    "or",
    "xor",
    "shl",
    "shr",
    "ushr",
)

SIMPLE_BINOP_KIND = [
    prefix + "-" + type_str
    for prefix, type_str in itertools.product(
        _BINOP_PREFIX, ("int", "float", "long")
    )
]

BINOP_WIDE_KIND = [prefix + "-" + "double" for prefix in _BINOP_PREFIX]

BINOP_2ADDR_KIND = [ins + "/2addr" for ins in SIMPLE_BINOP_KIND]
BINOP_LIT_KIND = [
    ins + postfix
    for ins, postfix in itertools.product(
        SIMPLE_BINOP_KIND, ("/lit8", "/lit16")
    )
]


@pytest.fixture(scope="module", params=SIMPLE_BINOP_KIND)
def simple_binop_kind(request):
    return request.param


@pytest.fixture(scope="module", params=BINOP_WIDE_KIND)
def binop_wide_kind(request):
    return request.param


@pytest.fixture(scope="module", params=BINOP_2ADDR_KIND)
def binop_2addr_kind(request):
    return request.param


@pytest.fixture(scope="module", params=BINOP_LIT_KIND)
def binop_lit_kind(request):
    return request.param


class TestPyEval:
    def test_init(self, apkinfo):
        pyeval = PyEval(apkinfo)

        assert isinstance(pyeval.table_obj, TableObject)
        assert pyeval.ret_stack == []

    # Tests for _invoke
    def test_invoke_with_non_list_object(self, pyeval):
        instruction = None

        with pytest.raises(TypeError):
            pyeval._invoke(instruction)

    def test_invoke_with_empty_list(self, pyeval):
        instruction = []

        with pytest.raises(ValueError):
            pyeval._invoke(instruction)

    def test_invoke_with_wrong_types(self, pyeval):
        instruction = [1, 2, 3]

        with pytest.raises(TypeError):
            pyeval._invoke(instruction)

    def test_invoke_with_invalid_value(self, pyeval):
        instruction = ["invoke-kind", "", ""]

        with pytest.raises(ValueError):
            pyeval._invoke(instruction)

    def test_invoke_fills_missing_types_for_instance_calls(self, pyeval):
        instance_idx = 10
        arg_idx = 11

        instance_value = Primitive("instance", "")
        arg_value = Primitive("number", "")

        pyeval.table_obj.insert(
            instance_idx, RegisterObject(instance_value, value_type=None)
        )
        pyeval.table_obj.insert(
            arg_idx, RegisterObject(arg_value, value_type=None)
        )

        instruction = [
            "invoke-virtual",
            f"v{instance_idx}",
            f"v{arg_idx}",
            "Lcom/example/Worker;->run(I)Ljava/lang/String;",
        ]

        pyeval._invoke(instruction)

        assert instance_value.value_type == "Lcom/example/Worker;"
        assert arg_value.value_type == "I"

    def test_invoke_fills_missing_types_for_static_calls(self, pyeval):
        first_arg_idx = 12
        second_arg_idx = 13

        first_arg_value = Primitive("threshold", "")
        second_arg_value = Primitive("payload", "")

        pyeval.table_obj.insert(
            first_arg_idx, RegisterObject(first_arg_value, value_type=None)
        )
        pyeval.table_obj.insert(
            second_arg_idx, RegisterObject(second_arg_value, value_type=None)
        )

        instruction = [
            "invoke-static",
            f"v{first_arg_idx}",
            f"v{second_arg_idx}",
            (
                "Lcom/example/Helpers;"
                "->mix(I Ljava/lang/String;)V"
            ),
        ]

        pyeval._invoke(instruction)

        assert first_arg_value.value_type == "I"
        assert second_arg_value.value_type == "Ljava/lang/String;"

    def test_invoke_with_func_returning_value(self, pyeval):
        instruction = ["invoke-kind", "v4", "v9", "some_function()Lclass;"]

        pyeval._invoke(instruction)

        v4 = pyeval.table_obj.getLatestRegValue(4)
        v9 = pyeval.table_obj.getLatestRegValue(9)

        assert len(v4.called_by_func) == 1
        assert v4.called_by_func[0].resolve() == "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)"

        assert len(v9.called_by_func) == 2
        assert v9.called_by_func[1].resolve() == "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)"

        assert len(pyeval.ret_stack) == 1
        assert pyeval.ret_stack[0].resolve() == "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)"
        assert pyeval.ret_type == "Lclass;"

    def test_invoke_with_func_not_returning_value(self, pyeval):
        instruction = ["invoke-kind", "v4", "v9", "some_function()V"]

        pyeval._invoke(instruction)

        v4 = pyeval.table_obj.getLatestRegValue(4)
        v9 = pyeval.table_obj.getLatestRegValue(9)

        assert len(v4.called_by_func) == 1
        assert v4.called_by_func[0].resolve() == "some_function()V(Lcom/google/progress/SMSHelper;,some_string)"

        assert len(v9.called_by_func) == 2
        assert v9.called_by_func[1].resolve() == "some_function()V(Lcom/google/progress/SMSHelper;,some_string)"

        assert pyeval.ret_stack == []

    def test_invoke_without_registers(self, pyeval):
        instruction = ["invoke-static", "some-func()Lclass;"]

        pyeval._invoke(instruction)

        v9 = pyeval.table_obj.getLatestRegValue(9)

        assert len(v9.called_by_func) == 1
        assert v9.called_by_func[0].resolve() == "java.io.file.close()"
        assert len(pyeval.ret_stack) == 1
        assert pyeval.ret_stack[0].resolve() == "some-func()Lclass;()"

    # Tests for invoke_virtual
    def test_invoke_virtual_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-virtual",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;"
            ),
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_VIRTUAL(instruction)
            mock.assert_called_once_with(instruction, look_up=True)

    def test_invoke_virtual_with_class_inheritance(self, pyeval):
        instruction = [
            "invoke-virtual",
            "v8",
            "Landroid/support/v4/util/ArrayMap;->isEmpty()Z",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert len(pyeval.ret_stack) == 1
        assert pyeval.ret_stack[0].resolve() == "Landroid/support/v4/util/SimpleArrayMap;->isEmpty()Z(ArrayMap object)"
        assert pyeval.ret_type == "Z"

    def test_invoke_virtual_range_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-virtual/range",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;"
            ),
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_VIRTUAL(instruction)
            mock.assert_called_once_with(instruction, look_up=True)

    # Tests for invoke_direct
    def test_invoke_direct_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-direct",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;"
            ),
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_DIRECT(instruction)
            mock.assert_called_once_with(instruction)

    def test_invoke_direct_range_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-direct/range",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;"
            ),
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_DIRECT(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for invoke_static
    def test_invoke_static_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-static",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;"
            ),
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_STATIC(instruction)
            mock.assert_called_once_with(instruction)

    def test_invoke_static_range_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-static/range",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;"
            ),
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_STATIC(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for invoke-interface
    def test_invoke_interface_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-interface",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;"
            ),
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_INTERFACE(instruction)
            mock.assert_called_once_with(instruction, look_up=True)

    def test_invoke_interface_with_class_inheritance(self, pyeval):
        instruction = [
            "invoke-interface",
            "v8",
            "Ljava/util/Map;->entrySet()Ljava/util/Set;",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert len(pyeval.ret_stack) == 1
        assert pyeval.ret_stack[0].resolve() == "Landroid/support/v4/util/ArrayMap;->entrySet()Ljava/util/Set;(ArrayMap object)"
        assert pyeval.ret_type == "Ljava/util/Set;"

    def test_invoke_interface_range_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-interface/range",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;"
            ),
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_INTERFACE(instruction)
            mock.assert_called_once_with(instruction, look_up=True)

    # Tests for invoke-super
    def test_invoke_super_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-super", "v4", "v9", "some_function()V"]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_SUPER(instruction)
            mock.assert_called_once_with(
                instruction, look_up=True, skip_self=True
            )

    def test_invoke_super_with_class_inheritance(self, pyeval):
        instruction = [
            "invoke-super",
            "v8",
            "Landroid/support/v4/app/Fragment;->toString()Ljava/lang/String;",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert len(pyeval.ret_stack) == 1
        assert pyeval.ret_stack[0].resolve() == "Landroid/support/v4/util/SimpleArrayMap;->toString()Ljava/lang/String;(ArrayMap object)"
        assert pyeval.ret_type == "Ljava/lang/String;"

    def test_invoke_super_range_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-super/range", "v4", "v9", "some_function()V"]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_SUPER(instruction)
            mock.assert_called_once_with(
                instruction, look_up=True, skip_self=True
            )

    # Tests for invoke polymorphic
    def test_invoke_polymorphic_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-polymorphic",
            "v4",
            "v9",
            "some_function()V",
            "prototype_idx",
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_POLYMORPHIC(instruction)
            mock.assert_called_once_with(instruction)

    def test_invoke_polymorphic_range_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-polymorphic/range",
            "v4",
            "v9",
            "some_function()V",
            "prototype_idx",
        ]

        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_POLYMORPHIC(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for invoke-custom
    def test_invoke_custom_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-custom", "v4", "v9", "method"]
        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_CUSTOM(instruction)
            mock.assert_called_once_with(instruction)

    def test_invoke_custom_range_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-custom/range", "v4", "v9", "method"]
        with patch("quark.evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_CUSTOM(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for _move_result
    def test_move_with_non_list_object(self, pyeval):
        instruction = None

        with pytest.raises(TypeError):
            pyeval._move_result(instruction)

    def test_move_with_empty_list(self, pyeval):
        instruction = []

        with pytest.raises(IndexError):
            pyeval._move_result(instruction)

    def test_move_with_invalid_instrcution(self, pyeval):
        instruction = ["move-kind", "", ""]

        with pytest.raises(ValueError):
            pyeval._move_result(instruction)

    def test_move_with_valid_instrcution(self, pyeval):
        instruction = ["move-result-object", "v1"]
        expected_return_value = MethodCall(
            "some_function()V",
            (
                Primitive("used_register_1", ""),
                Primitive("used_register_2", ""),
            ),
        )
        expected_return_type = "Lclass;"
        pyeval.ret_stack.append(expected_return_value)
        pyeval.ret_type = expected_return_type

        pyeval._move_result(instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == "some_function()V(used_register_1,used_register_2)"
        )

    # Tests for move_result
    def test_move_result_with_valid_mnemonic(self, pyeval):
        instruction = ["move-result", "v1"]

        with patch("quark.evaluator.pyeval.PyEval._move_result") as mock:
            pyeval.MOVE_RESULT(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for move_result_wide
    def test_move_result_wide_with_valid_mnemonic(self, pyeval):
        instruction = ["move-result-wide", "v1"]
        return_value = Primitive("Return Value", "")
        pyeval.ret_stack.append(return_value)

        pyeval.MOVE_RESULT_WIDE(instruction)

        assert pyeval.table_obj.getLatestRegValue(1).value is return_value
        assert pyeval.table_obj.getLatestRegValue(2).value is return_value

    # Tests for move_result_object
    def test_move_result_object_with_valid_mnemonic(self, pyeval):
        instruction = ["move-result-object", "v1"]

        with patch("quark.evaluator.pyeval.PyEval._move_result") as mock:
            pyeval.MOVE_RESULT_OBJECT(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for new instance
    def test_new_instance(self, pyeval):
        instruction = ["new-instance", "v3", "Lcom/google/progress/SMSHelper;"]

        override_original_instruction = [
            "new-instance",
            "v4",
            "Ljava/lang/Object;",
        ]

        pyeval.NEW_INSTANCE(instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(3).value.resolve()
            == "Lcom/google/progress/SMSHelper;"
        )
        assert (
            pyeval.table_obj.getLatestRegValue(4).value.resolve()
            == "Lcom/google/progress/SMSHelper;"
        )

        pyeval.NEW_INSTANCE(override_original_instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(4).value.resolve()
            == "Ljava/lang/Object;"
        )

    # Tests for const_string
    def test_const_string(self, pyeval):
        instruction = [
            "const-string",
            "v8",
            "https://github.com/quark-engine/quark-engine",
        ]

        pyeval.CONST_STRING(instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(8).value.resolve()
            == "https://github.com/quark-engine/quark-engine"
        )

    def test_const_string_jumbo(self, pyeval):
        instruction = [
            "const-string/jumbo",
            "v8",
            "https://github.com/quark-engine/quark-engine",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(8).value.resolve()
            == "https://github.com/quark-engine/quark-engine"
        )

    def test_const_class(self, pyeval):
        instruction = [
            "const-class",
            "v8",
            "Landroid/telephony/SmsMessage;",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(8).value.resolve()
            == "Landroid/telephony/SmsMessage;"
        )

    # Tests for const
    def test_const(self, pyeval):
        instruction = ["const", "v1", "string value"]

        with patch("quark.evaluator.pyeval.PyEval._assign_value") as mock:
            pyeval.CONST(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for const-four
    def test_const_four(self, pyeval):
        instruction = [
            "const/4",
            "v8",
            "https://github.com/quark-engine/quark-engine",
        ]

        with patch("quark.evaluator.pyeval.PyEval._assign_value") as mock:
            pyeval.CONST_FOUR(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for const-sixteen
    def test_const_sixteen(self, pyeval):
        instruction = ["const/16", "v1", "123"]

        with patch("quark.evaluator.pyeval.PyEval._assign_value") as mock:
            pyeval.CONST_SIXTEEN(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for const-high-sixteen
    def test_const_high_sixteen(self, pyeval):
        instruction = ["const/high16", "v1", "123"]

        with patch("quark.evaluator.pyeval.PyEval._assign_value") as mock:
            pyeval.CONST_HIGHSIXTEEN(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for move-kind
    def test_move_kind(self, pyeval, move_kind):
        instruction = [move_kind, "v1", "v4"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == "Lcom/google/progress/SMSHelper;"
        )

    def test_move_object(self, pyeval):
        instruction = ["move-object", "v1", "v4"]

        pyeval.eval[instruction[0]](instruction)

        assert id(pyeval.table_obj.getLatestRegValue(1)) == id(
            pyeval.table_obj.getLatestRegValue(4)
        )

    def test_move_wide_kind(self, pyeval, move_wide_kind):
        instruction = [move_wide_kind, "v1", "v4"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == "Lcom/google/progress/SMSHelper;"
        )
        assert (
            pyeval.table_obj.getLatestRegValue(2).value.resolve()
            == "java.lang.String.toString(some_number)"
        )

    def test_new_array(self, pyeval):
        instruction = ["new-array", "v1", "v5", "[java/lang/String;"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == "new-array()[(java.lang.String.toString(some_number))"
        )

    def test_filled_array_kind_with_class_type(
        self, pyeval, filled_array_kind
    ):
        instruction = [filled_array_kind, "v1", "[type_idx"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.ret_stack[0].resolve() == "new-array()[type_idx()"
        assert pyeval.ret_type == "[type_idx"

    def test_filled_array_kind_with_primitive_type(
        self, pyeval, filled_array_kind
    ):
        instruction = [filled_array_kind, "v1", "[I"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.ret_stack[0].resolve() == "new-array()[I()"
        assert pyeval.ret_type == "[I"

    # Tests for aget-kind
    def test_aget_kind(self, pyeval, aget_kind):
        v2_mock_variable_obj = RegisterObject(
            value=Primitive("some_list_like[1,2,3,4]", "[Ljava/lang/Integer;"),
            called_by_func=MethodCall("java.io.file.close", tuple()),
            value_type="[Ljava/lang/Integer;",
        )
        v3_mock_variable_obj = RegisterObject(
            value=Primitive("2", "I"), value_type="I"
        )
        pyeval.table_obj.insert(2, v2_mock_variable_obj)
        pyeval.table_obj.insert(3, v3_mock_variable_obj)

        if "-" in aget_kind:
            index = aget_kind.index("-") + 1
            postfix = aget_kind[index:]
            if postfix == "object":
                expected_value_type = "Ljava/lang/Integer;"
            else:
                expected_value_type = pyeval.type_mapping[postfix]
        else:
            expected_value_type = "Ljava/lang/Integer;"

        instruction = [aget_kind, "v1", "v2", "v3"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == "some_list_like[1,2,3,4][2]"
        )
        assert (
            pyeval.table_obj.getLatestRegValue(1).current_type
            == expected_value_type
        )

    def test_aget_wide_kind(self, pyeval, aget_wide_kind):
        instruction = [aget_wide_kind, "v1", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == "java.lang.Collection.toArray(an_array)[java.lang.String.toString(some_number)]"
        )

    # Tests for aput-kind
    def test_aput_kind(self, pyeval, aput_kind):
        instruction = [aput_kind, "v4", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(6).value.resolve()
            == "java.lang.Collection.toArray(an_array)[java.lang.String.toString(some_number)]:Lcom/google/progress/SMSHelper;"
        )
        assert pyeval.table_obj.getLatestRegValue(6).current_type == "[I"

    def test_aput_wide_kind(self, pyeval, aput_wide_kind):
        instruction = [aput_wide_kind, "v4", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(6).value.resolve()
            == "java.lang.Collection.toArray(an_array)[java.lang.String.toString(some_number)]:(Lcom/google/progress/SMSHelper;, java.lang.String.toString(some_number))"
        )
        assert pyeval.table_obj.getLatestRegValue(6).current_type == "[I"

    # Tests for neg-kind and not-kind
    def test_neg_and_not_kind(self, pyeval, neg_not_kind):
        instruction = [neg_not_kind, "v1", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == "java.lang.String.toString(some_number)"
        )
        assert pyeval.table_obj.getLatestRegValue(1).current_type == "I"

    def test_neg_and_not_wide_kind(self, pyeval, neg_not_wide_kind):
        instruction = [neg_not_wide_kind, "v1", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == "java.lang.String.toString(some_number)"
        )
        assert (
            pyeval.table_obj.getLatestRegValue(2).value.resolve()
            == "java.lang.Collection.toArray(an_array)"
        )

    # Tests for type-casting
    def test_type_casting_without_wide_type(self, pyeval, cast_kind):
        instruction = [cast_kind, "v1", "v5"]

        index = cast_kind.index("-") + 1
        postfix = cast_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        v1 = pyeval.table_obj.getLatestRegValue(1)
        assert v1.value.resolve() == "casting(java.lang.String.toString(some_number))"
        assert v1.current_type == pyeval.type_mapping[postfix]

    def test_type_casting_with_wide_type_to_simple_type(
        self, pyeval, cast_wide_to_simple_kind
    ):
        instruction = [cast_wide_to_simple_kind, "v1", "v5"]

        index = cast_wide_to_simple_kind.index("-") + 1
        postfix = cast_wide_to_simple_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        v1 = pyeval.table_obj.getLatestRegValue(1)

        assert v1.value.resolve() == "casting(java.lang.String.toString(some_number), java.lang.Collection.toArray(an_array))"
        assert v1.current_type == pyeval.type_mapping[postfix]

    def test_type_casting_with_simple_type_to_wide_type(
        self, pyeval, cast_simple_to_wide_kind
    ):
        instruction = [cast_simple_to_wide_kind, "v1", "v5"]

        index = cast_simple_to_wide_kind.index("-") + 1
        postfix = cast_simple_to_wide_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        v1 = pyeval.table_obj.getLatestRegValue(1)
        v2 = pyeval.table_obj.getLatestRegValue(2)

        assert v1.value.resolve() == "casting(java.lang.String.toString(some_number))"
        assert v1.current_type == pyeval.type_mapping[postfix]

        assert v2.value.resolve() == "casting(java.lang.String.toString(some_number))"
        assert v2.current_type == pyeval.type_mapping[postfix]

    # Tests for binop-kind
    def test_simple_binop_kind(self, pyeval, simple_binop_kind):
        instruction = [simple_binop_kind, "v1", "v5", "v6"]

        index = simple_binop_kind.index("-") + 1
        postfix = simple_binop_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        v1 = pyeval.table_obj.getLatestRegValue(1)

        assert v1.value.resolve() == "binop(java.lang.String.toString(some_number), java.lang.Collection.toArray(an_array))"
        assert v1.current_type == pyeval.type_mapping[postfix]

    def test_binop_kind_with_wide_type(self, pyeval, binop_wide_kind):
        instruction = [binop_wide_kind, "v1", "v4", "v6"]

        index = binop_wide_kind.index("-") + 1
        postfix = binop_wide_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        v1 = pyeval.table_obj.getLatestRegValue(1)
        v2 = pyeval.table_obj.getLatestRegValue(2)

        assert v1.value.resolve() == "binop(Lcom/google/progress/SMSHelper;, java.lang.Collection.toArray(an_array))"
        assert v1.current_type == pyeval.type_mapping[postfix]

        assert v2.value.resolve() == "binop(java.lang.String.toString(some_number), a_float)"
        assert v2.current_type == pyeval.type_mapping[postfix]

    def test_binop_kind_in_place(self, pyeval, binop_2addr_kind):
        instruction = [binop_2addr_kind, "v4", "v6"]

        l_index = binop_2addr_kind.index("-") + 1
        r_index = binop_2addr_kind.index("/")
        postfix = binop_2addr_kind[l_index:r_index]

        pyeval.eval[instruction[0]](instruction)

        v4 = pyeval.table_obj.getLatestRegValue(4)

        assert v4.value.resolve() == "binop(Lcom/google/progress/SMSHelper;, java.lang.Collection.toArray(an_array))"
        assert v4.current_type == pyeval.type_mapping[postfix]

    def test_binop_kind_with_literal(self, pyeval, binop_lit_kind):
        instruction = [binop_lit_kind, "v1", "v5", "literal_number"]

        l_index = binop_lit_kind.index("-") + 1
        r_index = binop_lit_kind.index("/")
        postfix = binop_lit_kind[l_index:r_index]

        pyeval.eval[instruction[0]](instruction)

        v1 = pyeval.table_obj.getLatestRegValue(1)

        assert v1.value.resolve() == "binop(java.lang.String.toString(some_number), literal_number)"
        assert v1.current_type == pyeval.type_mapping[postfix]

    # Tests for move-exception
    def test_move_exception(self, pyeval):
        instruction = ["move-exception", "v1"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve() == "Exception"
        )

    # Tests for fill-array-data
    def test_fill_array_data(self, pyeval):
        instruction = ["fill-array-data", "v6", "array-data-address"]

        pyeval.eval[instruction[0]](instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(6).value.resolve()
            == "Embedded-array-data()[]"
        )

    def test_show_table(self, pyeval):
        assert len(pyeval.show_table()[4]) == 1
        assert len(pyeval.show_table()[9]) == 1
        assert len(pyeval.show_table()[3]) == 0

        assert isinstance(pyeval.show_table()[4][0], RegisterObject)
        assert isinstance(pyeval.show_table()[9][0], RegisterObject)

    def test_invoke_and_move(self, pyeval):
        v6_mock_variable_obj = RegisterObject(
            value=Primitive("some_string", "Ljava/lang/String;"),
            value_type="Ljava/lang/String;",
        )

        pyeval.table_obj.insert(6, v6_mock_variable_obj)

        assert (
            pyeval.table_obj.getLatestRegValue(6).value.resolve()
            == "some_string"
        )

        first_instruction = [
            "invoke-virtual",
            "v6",
            "Lcom/google/progress/ContactsCollector;->getContactList()Ljava/lang/String;",
        ]

        second_instruction = ["move-result-object", "v1"]

        pyeval.INVOKE_VIRTUAL(first_instruction)
        pyeval.MOVE_RESULT_OBJECT(second_instruction)

        assert (
            pyeval.table_obj.getLatestRegValue(1).value.resolve()
            == (
                "Lcom/google/progress/ContactsCollector;"
                "->getContactList()Ljava/lang/String;(some_string)"
            )
        )

    @pytest.mark.parametrize("instance_type", [None, ""])
    def test_lookup_implement_returns_original_signature_when_instance_missing(
        self, instance_type, pyeval
    ):
        method_full_name = "Lcom/example/Worker;->run()V"

        assert (
            pyeval._lookup_implement(instance_type, method_full_name)
            == method_full_name
        )

    def test_lookup_implement_returns_method_from_instance_class(
        self, pyeval, apkinfo
    ):
        method = next(iter(apkinfo.custom_methods))
        method_full_name = PyEval.get_method_pattern(
            method.class_name, method.name, method.descriptor
        )

        resolved = pyeval._lookup_implement(method.class_name, method_full_name)

        assert resolved == method_full_name

    def test_lookup_implement_walks_superclasses_when_skip_self(
        self, pyeval, apkinfo
    ):
        subclass = (
            "Landroid/support/v4/app/ActionBarDrawerToggle$SlideDrawable;"
        )
        parent_method = apkinfo.find_method(
            "Landroid/graphics/drawable/InsetDrawable;",
            "<init>",
            "(Landroid/graphics/drawable/Drawable; I)V",
        )[0]

        alias_signature = PyEval.get_method_pattern(
            "Lquark/Interface;", parent_method.name, parent_method.descriptor
        )
        expected_signature = PyEval.get_method_pattern(
            parent_method.class_name,
            parent_method.name,
            parent_method.descriptor,
        )

        resolved = pyeval._lookup_implement(
            subclass, alias_signature, skip_self=True
        )

        assert resolved == expected_signature

    def test_lookup_implement_raises_when_method_not_found(self, pyeval):
        instance_type = next(
            cls for cls in pyeval.apkinfo.superclass_relationships if cls
        )
        missing_signature = PyEval.get_method_pattern(
            instance_type, "__quark_missing__", "()V"
        )

        with pytest.raises(ValueError) as excinfo:
            pyeval._lookup_implement(instance_type, missing_signature)

        assert "Instance type" in str(excinfo.value)

    @staticmethod
    def test_get_method_pattern():
        class_name = "Lcom/google/progress/ContactsCollector;"
        method_name = "getContactList"
        descriptor = "()Ljava/lang/String;(some_string)"

        pattern = PyEval.get_method_pattern(
            class_name, method_name, descriptor
        )
        assert pattern == (
            "Lcom/google/progress/ContactsCollector;"
            "->getContactList()Ljava/lang/String;(some_string)"
        )
