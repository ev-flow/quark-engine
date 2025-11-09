import itertools
from unittest.mock import patch

import pytest
import requests

from quark.core.apkinfo import AndroguardImp
from quark.core.struct.registerobject import RegisterObject
from quark.core.struct.tableobject import TableObject
from quark.evaluator.pyeval import MAX_REG_COUNT, PyEval


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

    # mock_hash_table = [...[], [v4_mock_variable_obj], [], [],
    # [v9_mock_variable_obj]....]
    v4_mock_variable_obj = RegisterObject(
        "Lcom/google/progress/SMSHelper;",
        value_type="Lcom/google/progress/SMSHelper;",
    )
    v5_mock_variable_obj = RegisterObject(
        "some_number", "java.lang.String.toString()", value_type="I"
    )
    v6_mock_variable_obj = RegisterObject(
        "an_array", "java.lang.Collection.toArray()", value_type="[I"
    )
    v7_mock_variable_obj = RegisterObject("a_float", value_type="F")
    v8_mock_variable_obj = RegisterObject(
        "ArrayMap object",
        value_type="Landroid/support/v4/util/ArrayMap;",
    )
    v9_mock_variable_obj = RegisterObject(
        "some_string",
        "java.io.file.close()",
        value_type="Ljava/lang/String;",
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

        assert len(pyeval.table_obj.hash_table) == MAX_REG_COUNT
        assert isinstance(pyeval.table_obj, TableObject)
        assert pyeval.ret_stack == []

    # Tests for _invoke
    def test_invoke_with_non_list_object(self, pyeval):
        instruction = None

        with pytest.raises(TypeError):
            pyeval._invoke(instruction)

    def test_invoke_with_empty_list(self, pyeval):
        instruction = []

        with pytest.raises(IndexError):
            pyeval._invoke(instruction)

    def test_invoke_with_wrong_types(self, pyeval):
        instruction = [1, 2, 3]

        with pytest.raises(TypeError):
            pyeval._invoke(instruction)

    def test_invoke_with_invalid_value(self, pyeval):
        instruction = ["invoke-kind", "", ""]

        with pytest.raises(ValueError):
            pyeval._invoke(instruction)

    def test_invoke_with_func_returning_value(self, pyeval):
        instruction = ["invoke-kind", "v4", "v9", "some_function()Lclass;"]

        pyeval._invoke(instruction)

        assert pyeval.table_obj.pop(4).called_by_func == [
            "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)"
        ]
        assert pyeval.table_obj.pop(9).called_by_func == [
            "java.io.file.close()",
            "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)",
        ]
        assert pyeval.ret_stack == [
            "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)"
        ]
        assert pyeval.ret_type == "Lclass;"

    @pytest.mark.skip(reason="discussion needed.")
    def test_invoke_with_func_not_returning_value(self, pyeval):
        instruction = ["invoke-kind", "v4", "v9", "some_function()V"]

        pyeval._invoke(instruction)

        assert pyeval.table_obj.pop(4).called_by_func == [
            "some_function()V(Lcom/google/progress/SMSHelper;,some_string)"
        ]
        assert pyeval.table_obj.pop(9).called_by_func == [
            "java.io.file.close()",
            "some_function()V(Lcom/google/progress/SMSHelper;,some_string)",
        ]
        assert pyeval.ret_stack == []

    def test_invoke_without_registers(self, pyeval):
        instruction = ["invoke-static", "some-func()Lclass;"]

        pyeval._invoke(instruction)

        assert pyeval.table_obj.pop(9).called_by_func == [
            "java.io.file.close()"
        ]
        assert pyeval.ret_stack == ["some-func()Lclass;()"]

    # Tests for invoke_virtual
    def test_invoke_virtual_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-virtual",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
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

        assert pyeval.ret_stack == [
            (
                "Landroid/support/v4/util/SimpleArrayMap;"
                "->isEmpty()Z(ArrayMap object)"
            )
        ]
        assert pyeval.ret_type == "Z"

    def test_invoke_virtual_range_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-virtual/range",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
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
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
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
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
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
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
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
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
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
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
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

        assert pyeval.ret_stack == [
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
            )
        ]
        assert pyeval.ret_type == "Ljava/util/Set;"

    def test_invoke_interface_range_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-interface/range",
            "v4",
            "v9",
            (
                "Landroid/support/v4/util/ArrayMap;"
                "->entrySet()Ljava/util/Set;(ArrayMap object)"
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

        assert pyeval.ret_stack == [
            (
                "Landroid/support/v4/util/SimpleArrayMap;"
                "->toString()Ljava/lang/String;(ArrayMap object)"
            )
        ]
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
        expected_return_value = (
            "some_function()V(used_register_1, used_register_2)"
        )
        expected_return_type = "Lclass;"
        pyeval.ret_stack.append(expected_return_value)
        pyeval.ret_type = expected_return_type

        pyeval._move_result(instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            expected_return_value, None, value_type=expected_return_type
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
        return_value = "Return Value"
        pyeval.ret_stack.append("Return Value")

        pyeval.MOVE_RESULT_WIDE(instruction)

        assert pyeval.table_obj.pop(1).value == return_value
        assert pyeval.table_obj.pop(2).value == return_value

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

        assert pyeval.table_obj.pop(3) == RegisterObject(
            "Lcom/google/progress/SMSHelper;",
            value_type="Lcom/google/progress/SMSHelper;",
        )
        assert pyeval.table_obj.pop(4) == RegisterObject(
            "Lcom/google/progress/SMSHelper;",
            value_type="Lcom/google/progress/SMSHelper;",
        )

        pyeval.NEW_INSTANCE(override_original_instruction)

        assert pyeval.table_obj.pop(4) == RegisterObject(
            "Ljava/lang/Object;", value_type="Ljava/lang/Object;"
        )

    # Tests for const_string
    def test_const_string(self, pyeval):
        instruction = [
            "const-string",
            "v8",
            "https://github.com/quark-engine/quark-engine",
        ]

        pyeval.CONST_STRING(instruction)

        assert pyeval.table_obj.pop(8) == RegisterObject(
            "https://github.com/quark-engine/quark-engine",
            value_type="Ljava/lang/String;",
        )

    def test_const_string_jumbo(self, pyeval):
        instruction = [
            "const-string/jumbo",
            "v8",
            "https://github.com/quark-engine/quark-engine",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(8) == RegisterObject(
            "https://github.com/quark-engine/quark-engine",
            value_type="Ljava/lang/String;",
        )

    def test_const_class(self, pyeval):
        instruction = [
            "const-class",
            "v8",
            "Landroid/telephony/SmsMessage;",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(8) == RegisterObject(
            "Landroid/telephony/SmsMessage;",
            value_type="Ljava/lang/Class;",
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

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "Lcom/google/progress/SMSHelper;",
            value_type="Lcom/google/progress/SMSHelper;",
        )

    def test_move_object(self, pyeval):
        instruction = ["move-object", "v1", "v4"]

        pyeval.eval[instruction[0]](instruction)

        assert id(pyeval.table_obj.pop(1)) == id(pyeval.table_obj.pop(4))

    def test_move_wide_kind(self, pyeval, move_wide_kind):
        instruction = [move_wide_kind, "v1", "v4"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "Lcom/google/progress/SMSHelper;",
            value_type="Lcom/google/progress/SMSHelper;",
        )
        assert pyeval.table_obj.pop(2) == RegisterObject(
            "some_number", value_type="I"
        )

    def test_new_array(self, pyeval):
        instruction = ["new-array", "v1", "v5", "[java/lang/String;"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "new-array()[(some_number)",
            value_type="[java/lang/String;",
        )

    def test_filled_array_kind_with_class_type(
        self, pyeval, filled_array_kind
    ):
        instruction = [filled_array_kind, "v1", "[type_idx"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.ret_stack == ["new-array()[type_idx()"]
        assert pyeval.ret_type == "[type_idx"

    def test_filled_array_kind_with_primitive_type(
        self, pyeval, filled_array_kind
    ):
        instruction = [filled_array_kind, "v1", "[I"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.ret_stack == ["new-array()[I()"]
        assert pyeval.ret_type == "[I"

    # Tests for aget-kind
    def test_aget_kind(self, pyeval, aget_kind):
        v2_mock_variable_obj = RegisterObject(
            "some_list_like[1,2,3,4]",
            "java.io.file.close()",
            value_type="[Ljava/lang/Integer;",
        )
        v3_mock_variable_obj = RegisterObject("2", None, value_type="I")
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

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "some_list_like[1,2,3,4][2]", value_type=expected_value_type
        )

    def test_aget_wide_kind(self, pyeval, aget_wide_kind):
        instruction = [aget_wide_kind, "v1", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "an_array[some_number]", value_type="I"
        )

    # Tests for aput-kind
    def test_aput_kind(self, pyeval, aput_kind):
        instruction = [aput_kind, "v4", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(6) == RegisterObject(
            "an_array[some_number]:Lcom/google/progress/SMSHelper;",
            value_type="[I",
        )

    def test_aput_wide_kind(self, pyeval, aput_wide_kind):
        instruction = [aput_wide_kind, "v4", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(6) == RegisterObject(
            (
                "an_array[some_number]:"
                "(Lcom/google/progress/SMSHelper;, some_number)"
            ),
            value_type="[I",
        )

    # Tests for neg-kind and not-kind
    def test_neg_and_not_kind(self, pyeval, neg_not_kind):
        instruction = [neg_not_kind, "v1", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "some_number", value_type="I"
        )

    def test_neg_and_not_wide_kind(self, pyeval, neg_not_wide_kind):
        instruction = [neg_not_wide_kind, "v1", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "some_number", value_type="I"
        )
        assert pyeval.table_obj.pop(2) == RegisterObject(
            "an_array", value_type="[I"
        )

    # Tests for type-casting
    def test_type_casting_without_wide_type(self, pyeval, cast_kind):
        instruction = [cast_kind, "v1", "v5"]

        index = cast_kind.index("-") + 1
        postfix = cast_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "casting(some_number)",
            value_type=pyeval.type_mapping[postfix],
        )

    def test_type_casting_with_wide_type_to_simple_type(
        self, pyeval, cast_wide_to_simple_kind
    ):
        instruction = [cast_wide_to_simple_kind, "v1", "v5"]

        index = cast_wide_to_simple_kind.index("-") + 1
        postfix = cast_wide_to_simple_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "casting(some_number, an_array)",
            value_type=pyeval.type_mapping[postfix],
        )

    def test_type_casting_with_simple_type_to_wide_type(
        self, pyeval, cast_simple_to_wide_kind
    ):
        instruction = [cast_simple_to_wide_kind, "v1", "v5"]

        index = cast_simple_to_wide_kind.index("-") + 1
        postfix = cast_simple_to_wide_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "casting(some_number)",
            value_type=pyeval.type_mapping[postfix],
        )
        assert pyeval.table_obj.pop(2) == RegisterObject(
            "casting(some_number)",
            value_type=pyeval.type_mapping[postfix],
        )

    # Tests for binop-kind
    def test_simple_binop_kind(self, pyeval, simple_binop_kind):
        instruction = [simple_binop_kind, "v1", "v5", "v6"]

        index = simple_binop_kind.index("-") + 1
        postfix = simple_binop_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "binop(some_number, an_array)",
            value_type=pyeval.type_mapping[postfix],
        )

    def test_binop_kind_with_wide_type(self, pyeval, binop_wide_kind):
        instruction = [binop_wide_kind, "v1", "v4", "v6"]

        index = binop_wide_kind.index("-") + 1
        postfix = binop_wide_kind[index:]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "binop(Lcom/google/progress/SMSHelper;, an_array)",
            value_type=pyeval.type_mapping[postfix],
        )
        assert pyeval.table_obj.pop(2) == RegisterObject(
            "binop(some_number, a_float)",
            value_type=pyeval.type_mapping[postfix],
        )

    def test_binop_kind_in_place(self, pyeval, binop_2addr_kind):
        instruction = [binop_2addr_kind, "v4", "v6"]

        l_index = binop_2addr_kind.index("-") + 1
        r_index = binop_2addr_kind.index("/")
        postfix = binop_2addr_kind[l_index:r_index]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(4) == RegisterObject(
            "binop(Lcom/google/progress/SMSHelper;, an_array)",
            value_type=pyeval.type_mapping[postfix],
        )

    def test_binop_kind_with_literal(self, pyeval, binop_lit_kind):
        instruction = [binop_lit_kind, "v1", "v5", "literal_number"]

        l_index = binop_lit_kind.index("-") + 1
        r_index = binop_lit_kind.index("/")
        postfix = binop_lit_kind[l_index:r_index]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "binop(some_number, literal_number)",
            value_type=pyeval.type_mapping[postfix],
        )

    # Tests for move-exception
    def test_move_exception(self, pyeval):
        instruction = ["move-exception", "v1"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "Exception", value_type="Ljava/lang/Throwable;"
        )

    # Tests for fill-array-data
    def test_fill_array_data(self, pyeval):
        instruction = ["fill-array-data", "v6", "array-data-address"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(6) == RegisterObject(
            "Embedded-array-data()[", value_type="[I"
        )

    def test_show_table(self, pyeval):
        assert len(pyeval.show_table()[4]) == 1
        assert len(pyeval.show_table()[9]) == 1
        assert len(pyeval.show_table()[3]) == 0

        assert isinstance(pyeval.show_table()[4][0], RegisterObject)
        assert isinstance(pyeval.show_table()[9][0], RegisterObject)

    def test_invoke_and_move(self, pyeval):
        v6_mock_variable_obj = RegisterObject(
            "some_string", None, value_type="Ljava/lang/String;"
        )

        pyeval.table_obj.insert(6, v6_mock_variable_obj)

        assert pyeval.table_obj.pop(6) == RegisterObject(
            "some_string", value_type="Ljava/lang/String;"
        )

        first_instruction = [
            "invoke-virtual",
            "v6",
            "Lcom/google/progress/ContactsCollector;->getContactList()Ljava/lang/String;",
        ]

        second_instruction = ["move-result-object", "v1"]

        pyeval.INVOKE_VIRTUAL(first_instruction)
        pyeval.MOVE_RESULT_OBJECT(second_instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            (
                "Lcom/google/progress/ContactsCollector;"
                "->getContactList()Ljava/lang/String;(some_string)"
            ),
            value_type="Ljava/lang/String;",
        )

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
