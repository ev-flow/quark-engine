# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from abc import ABC, abstractmethod
import collections
from dataclasses import dataclass
from typing import Any, Generator, Type, TypeVar
from weakref import WeakValueDictionary


@dataclass()
class ValueNode(ABC):
    """Abstract base class for value node."""

    def resolve(self, evaluateArgs: bool = True) -> str:
        """Resolve the value into a string representation.

        :param evaluateArgs: True to evaluate argument base on its type,
        default to True
        :return: a string representation of the value
        """
        return iterativeResolve(self, evaluateArgs=evaluateArgs)

    @abstractmethod
    def _getChildren(self) -> tuple["ValueNode", ...]:
        """Get the child ValueNodes of this node.

        :return: a tuple of child ValueNodes
        """
        pass

    @abstractmethod
    def _assembleResolvedString(
        self, childStrs: tuple[str, ...], evaluateArgs: bool
    ) -> str:
        """Assemble the resolved string from child strings.

        :param childStrs: a tuple of resolved child strings
        :param evaluateArgs: True to evaluate argument base on its type,
        default to True
        :return: the assembled resolved string
        """
        pass

    def __eq__(self, value: object) -> bool:
        return self is value

    def __hash__(self):
        return id(self)


@dataclass(slots=True, eq=False)
class Primitive(ValueNode):
    """A ValueNode that wraps a primitive type (str, int, etc.)."""

    value: Any
    value_type: str | None

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return f"Primitive({self.value!r})"

    def _getChildren(self) -> tuple["ValueNode", ...]:
        return ()

    def _assembleResolvedString(self, _, evaluateArgs: bool) -> str:
        return (
            str(evaluateArgument(self.value, self.value_type))
            if evaluateArgs
            else str(self.value)
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

    def _getChildren(self) -> tuple["ValueNode", ...]:
        return self.argumentNodes

    def _assembleResolvedString(self, argStrs: tuple[str, ...], _) -> str:
        return f"{self.method}({','.join(argStrs)})"

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

    strFormat: str
    operands: tuple[ValueNode, ...]
    data: Any

    def __str__(self):
        return f"<op:{self.strFormat}>"

    def __repr__(self):
        return (
            f"BytecodeOps({self.strFormat!r}, {self.operands!r}, {self.data!r})"
        )

    def _getChildren(self) -> tuple[ValueNode, ...]:
        return self.operands

    def _assembleResolvedString(self, operandStrs: tuple[str, ...], _) -> str:
        value_dict = {
            f"src{index}": value for index, value in enumerate(operandStrs)
        }
        value_dict["data"] = str(self.data)
        return self.strFormat.format(**value_dict)


T = TypeVar("T", bound=ValueNode)

__resolvedCache: WeakValueDictionary[int, "StringWrapper"] = (
    WeakValueDictionary()
)


@dataclass(frozen=True)
class StringWrapper:
    value: str


def iterativeResolve(node: ValueNode, evaluateArgs: bool) -> str:
    """Resolve the value node into a string representation.

    :param node: value node to resolve
    :param evaluateArgs: True to evaluate argument base on its type
    :return: a string representation of the value
    """
    stack = [(node, [])]

    while stack:
        current, childStrs = stack[-1]
        children = current._getChildren()

        if len(childStrs) < len(children):
            # Still has children to process
            child = children[len(childStrs)]

            cachedValue = __resolvedCache.get(id(child))
            if cachedValue is not None:
                # Use cached resolved value
                childStrs.append(cachedValue.value)
                continue

            # Update current node to continue with next child later
            stack.append((child, []))
            continue

        result = current._assembleResolvedString(
            tuple(childStrs), evaluateArgs
        )
        __resolvedCache[id(current)] = StringWrapper(result)

        # Current node is fully processed, pop from stack
        stack.pop()

        if not stack:
            # No parent, this is the root node
            return result

        # Append result to parent's list
        _, parentProcessedChildren = stack[-1]
        parentProcessedChildren.append(result)

    raise RuntimeError("Unreachable code reached in iterativeResolve")


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
