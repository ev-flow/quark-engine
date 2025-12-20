# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from abc import ABC, abstractmethod
import collections
from dataclasses import dataclass
from typing import Any, Generator, Type, TypeVar


@dataclass()
class ValueNode(ABC):
    """Abstract base class for value node."""

    def resolve(self, evaluateArgs: bool = True) -> str:
        """Resolve the value into a string representation.

        :param evaluateArgs: True to evaluate argument base on its type,
        default to True
        :return: a string representation of the value
        """
        return self._recursiveResolve(set(), evaluateArgs)

    @abstractmethod
    def _recursiveResolve(self, visited: set[int], evaluateArgs: bool) -> str:
        """The internal resolving logic for resolve().
        `visited` is used to detect and prevent infinite recursion cycles.

        :param visited: a set of visited ValueNode ids
        :param evaluateArgs: True to evaluate argument base on its type
        :return: a string representation of the value
        """
        pass

    def __eq__(self, value: object) -> bool:
        return id(self) == id(value)


@dataclass(slots=True, eq=False)
class Primitive(ValueNode):
    """A ValueNode that wraps a primitive type (str, int, etc.)."""

    value: Any
    value_type: str | None

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return f"Primitive({self.value!r})"

    def _recursiveResolve(self, _, evaluateArgs: bool) -> Any:
        return (
            evaluateArgument(self.value, self.value_type)
            if evaluateArgs
            else self.value
        )


@dataclass(slots=True, eq=False)
class MethodCall(ValueNode):
    """A ValueNode that represents a method call."""

    method: str
    argumentNodes: tuple[ValueNode, ...]

    def __str__(self):
        return f"<invoke:{self.method}, {self.argumentNodes!r}>"

    def __repr__(self):
        return f"MethodCall({self.method!r}, {self.argumentNodes!r})"

    def _recursiveResolve(self, visited: set[int], evaluateArgs: bool) -> str:
        if id(self) in visited:
            return "<...recursion...>"
        visited.add(id(self))

        try:
            valueStrs = []
            for arg in self.argumentNodes:
                value = arg._recursiveResolve(visited, evaluateArgs)
                valueStrs.append(str(value))
            return f"{self.method}({','.join(valueStrs)})"
        finally:
            visited.remove(id(self))

    def getArguments(self, evaluateArgs: bool = True) -> list[Any]:
        return [
            (
                evaluateArgument(rawArg.value, rawArg.value_type)
                if evaluateArgs and isinstance(rawArg, Primitive)
                else rawArg.resolve(evaluateArgs)
            )
            for rawArg in self.argumentNodes
        ]


@dataclass(slots=True, eq=False)
class BytecodeOps(ValueNode):
    """A ValueNode that represents a bytecode operation (e.g., binop, cast)."""

    str_format: str
    operands: tuple[ValueNode, ...]
    data: Any

    def __str__(self):
        op_name = self.str_format.split("(")[0]
        return f"<op:{op_name}>"

    def __repr__(self):
        return f"BytecodeOps({self.str_format!r}, {self.operands!r}, {self.data!r})"

    def _recursiveResolve(self, visited: set[int], evaluateArgs: bool) -> str:
        if id(self) in visited:
            return "<...recursion...>"
        visited.add(id(self))

        try:
            value_dict = {
                f"src{index}": p._recursiveResolve(visited, evaluateArgs)
                for index, p in enumerate(self.operands)
            }
            value_dict["data"] = str(self.data)
            return self.str_format.format(**value_dict)
        finally:
            visited.remove(id(self))


T = TypeVar("T", bound=ValueNode)


def iteratePriorNodes(
    node: ValueNode, nodeType: Type[T]
) -> Generator[T, None, None]:
    """Yield all prior ValueNodes that contribute to the given ValueNode,
    including itself.

    :param node: root node to start
    :param nodeType: node type to yield
    :yield: value nodes of given node types
    """
    visited = set()
    queue = collections.deque([node])

    while queue:
        node = queue.popleft()
        if id(node) in visited:
            continue
        visited.add(id(node))

        if isinstance(node, nodeType):
            yield node

        match node:
            case MethodCall():
                queue.extend(node.argumentNodes)
            case BytecodeOps():
                queue.extend(node.operands)


def iteratePriorCalls(
    methodCall: MethodCall,
) -> Generator[MethodCall, None, None]:
    """Yield all prior calls that supply arguments to the given method call,
    including itself.

    :param methodCall: root method call to iterate
    :yield: method calls that supply arguments to the given method call
    """
    yield from iteratePriorNodes(methodCall, nodeType=MethodCall)


def iteratePriorPrimitives(
    valueNode: ValueNode,
) -> Generator[Primitive, None, None]:
    """Yield all prior Primitive nodes that contribute to the given ValueNode.

    :param valueNode: root node to iterate
    :yield: primitives that contribute to the given node
    """
    yield from iteratePriorNodes(valueNode, nodeType=Primitive)


def evaluateArgument(
    argument: str, typeHint: str | None
) -> int | float | bool | str:
    """Evaluate the argument based on the given type hint.
    If the type hint is missing or None, no evaluation is performed.

    :param argument: argument to be evaluated
    :param typeHint: type hint suggesting how the argument should be evaluated
    :return: evaluated argument
    """
    try:
        if typeHint in ["I", "B", "S", "J"]:
            return int(argument)
        elif typeHint == "Z":
            return bool(int(argument))
        elif typeHint in ["F", "D"]:
            return float(argument)
    except ValueError:
        pass

    return argument
