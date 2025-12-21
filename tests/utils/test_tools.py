import pytest
from quark.utils.tools import (
    contains,
    descriptor_to_androguard_format,
    remove_dup_list,
)


def test_remove_dup_list_with_invalid_arg():
    with pytest.raises(TypeError):
        remove_dup_list(123)


def test_remove_dup_list_with_empty_list():
    assert remove_dup_list([]) == []


def test_remove_dup_list_with_numbers():
    assert remove_dup_list([1, 2, 3, 4, 3, 4, 2]) == [1, 2, 3, 4]


def test_remove_dup_list_with_strings():
    assert set(remove_dup_list(["hello", "test", "test"])) == {
        "hello",
        "test",
    }


def test_remove_dup_list_with_floats():
    assert remove_dup_list([2.0, 30, 4.0, 2.0]) == [2.0, 4.0, 30]


def test_contains_with_mutually_exclusive_list():
    subset = ["getCellLocation", "sendTextMessage"]
    target = ["put", "query"]

    result = contains(subset, target)

    assert result is False


def test_contains_with_superset():
    subset = ["put", "getCellLocation", "query", "sendTextMessage"]
    target = ["put", "query"]

    result = contains(subset, target)

    assert result is False


def test_contains_with_incorrect_sequence():
    subset = ["getCellLocation", "sendTextMessage"]
    target = ["sendTextMessage", "put", "getCellLocation", "query"]

    result = contains(subset, target)

    assert result is False


def test_contains_with_correct_sequence():
    subset = ["getCellLocation", "sendTextMessage"]
    target = ["put", "getCellLocation", "query", "sendTextMessage"]

    result = contains(subset, target)

    assert result is True


def test_descriptor_to_androguard_format_with_invalid_str():
    descriptor = "Z"

    with pytest.raises(ValueError):
        _ = descriptor_to_androguard_format(descriptor)


def test_descriptor_to_androguard_format_with_formatted_str():
    descriptor = "(I Ljava/lang/String; [B J)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == descriptor


def test_descriptor_to_androguard_format_with_primitive():
    descriptor = "(ZBCSIJFD)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == "(Z B C S I J F D)"


def test_descriptor_to_androguard_format_with_class():
    descriptor = "(Ljava/lang/String;)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == "(Ljava/lang/String;)"


def test_descriptor_to_androguard_format_with_array():
    descriptor = "([Ljava/lang/String;)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == "([Ljava/lang/String;)"


def test_descriptor_to_androguard_format_with_combination():
    descriptor = "(ILjava/lang/String;[BJ)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == "(I Ljava/lang/String; [B J)"
