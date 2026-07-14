# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
import pytest

from unittest.mock import Mock, patch

from quark.core.struct.methodobject import MethodObject
from quark.script import Method
from quark.script.objection import Objection, convertMethodToString, Instance


@pytest.fixture(scope="function")
def mockedRequestPost():
    with patch("requests.post") as mock:
        yield mock


@pytest.fixture(scope="function")
def mockedGetInstances():
    with patch("quark.script.objection.Objection.getInstances") as mock:
        yield mock


@pytest.fixture(scope="function")
def mockedGetCurrentActivity():
    with patch("quark.script.objection.Objection._getCurrentActivity") as mock:
        yield mock


@pytest.fixture(scope="function")
def responseForGetInstancesSuccess():
    response = Mock()
    response.status_code.return_value = 200
    response.json.return_value = [{"hashcode": 11111111}]

    yield response


@pytest.fixture(scope="function")
def responseForGatInstancesFail():
    response = Mock()
    response.status_code.return_value = 200
    response.json.return_value = {"message": "Error"}

    yield response


def testCovertMethodToStringWithClasses():
    method = Method(
        quarkResultInstance=None,
        methodObj=MethodObject(
            "Lcustom/class/name$subclass;",
            "method_name",
            "(Ljava/lang/String; Ljava/lang/Object;)V",
        ),
    )

    result = convertMethodToString(method)

    assert result == (
        "custom.class.name$subclass.method_name",
        "java.lang.String,java.lang.Object",
    )


def testCovertMethodToStringWithPrimitives():
    method = Method(
        quarkResultInstance=None,
        methodObj=MethodObject(
            "Lcustom/class/name;", "method_name", "(I [B J)V"
        ),
    )

    result = convertMethodToString(method)

    assert result == ("custom.class.name.method_name", "I,[B,J")


def testCovertMethodToStringWithArrays():
    method = Method(
        quarkResultInstance=None,
        methodObj=MethodObject(
            "Lcustom/class/name;",
            "method_name",
            "([Ljava/lang/String; [Ljava/lang/Object;)V",
        ),
    )

    result = convertMethodToString(method)

    assert result == (
        "custom.class.name.method_name",
        "[Ljava.lang.String;,[Ljava.lang.Object;",
    )


def testCovertMethodToStringWithArrayAndClass():
    method = Method(
        quarkResultInstance=None,
        methodObj=MethodObject(
            "Lcustom/class/name;",
            "method_name",
            "([Ljava/lang/String; Ljava/lang/Object;)V",
        ),
    )

    result = convertMethodToString(method)

    assert result == (
        "custom.class.name.method_name",
        "[Ljava.lang.String;,java.lang.Object",
    )


class TestObjection:
    @staticmethod
    def testGetInstancesSuccess(
        mockedRequestPost, responseForGetInstancesSuccess
    ):
        mockedRequestPost.return_value = responseForGetInstancesSuccess
        obj = Objection("127.0.0.1:8888")
        clazz = "Lcom/google/progress/WifiCheckTask;"

        instances = obj.getInstances(clazz)

        assert instances == [Instance(11111111)]

    @staticmethod
    def testGetInstancesFail(mockedRequestPost, responseForGatInstancesFail):
        mockedRequestPost.return_value = responseForGatInstancesFail
        obj = Objection("127.0.0.1:8888")
        clazz = "Lcom/google/progress/WifiCheckTask;"

        instances = obj.getInstances(clazz)

        assert instances == []

    @staticmethod
    def testHookMethodWithMethodObject(mockedRequestPost: Mock):
        obj = Objection("127.0.0.1:8888")
        method = Method(
            None,
            MethodObject(
                "Lcom/google/progress/WifiCheckTask;",
                "checkWifiCanOrNotConnectServer",
                "([Ljava/lang/String;)Z",
            ),
        )

        obj.hookMethod(
            method, watchArgs=True, watchBacktrace=True, watchRet=True
        )

        expectedJson = {
            "pattern": (
                "com.google.progress.WifiCheckTask"
                ".checkWifiCanOrNotConnectServer"
            ),
            "overloadFilter": "[Ljava.lang.String;",
            "watchArgs": True,
            "watchBacktrace": True,
            "watchRet": True,
        }

        mockedRequestPost.assert_called_once_with(
            "http://127.0.0.1:8888/rpc/invoke/androidHookingWatchMethod",
            json=expectedJson,
            headers={"Content-type": "application/json"},
        )

    @staticmethod
    def testExecuteWithAnInstance(mockedRequestPost, mockedGetInstances):
        mockedGetInstances.return_value = [Instance(11111111)]
        obj = Objection("127.0.0.1:8888")
        method = Method(
            None,
            MethodObject(
                "La/b/clazz;",
                "methodName",
                "()Z",
            ),
        )

        obj.execute(method)

        expectedJson = {
            "handle": 11111111,
            "js": (
                'let clz = Java.use("a.b.clazz");\n'
                'let method = clz["methodName"];\n'
                "const result = method.call(clazz);\n"
                "console.log(result);"
            ),
        }

        mockedRequestPost.assert_called_once_with(
            "http://127.0.0.1:8888/rpc/invoke/androidHeapEvaluateHandleMethod",
            json=expectedJson,
            headers={"Content-type": "application/json"},
        )

    @staticmethod
    def testExecuteWithoutAnInstance(
        mockedRequestPost, mockedGetInstances, mockedGetCurrentActivity
    ):
        mockedGetCurrentActivity.return_value = "activity"
        mockedGetInstances.side_effect = [[], [Instance(22222222)]]
        obj = Objection("127.0.0.1:8888")
        method = Method(
            None,
            MethodObject(
                "La/b/clazz;",
                "methodName",
                "()Z",
            ),
        )

        obj.execute(method)

        expectedJson = {
            "handle": 22222222,
            "js": (
                'let clz = Java.use("a.b.clazz");\n'
                'let method = clz["methodName"];\n'
                "const result = method.call(clz);\n"
                "console.log(result);"
            ),
        }

        mockedRequestPost.assert_called_once_with(
            "http://127.0.0.1:8888/rpc/invoke/androidHeapEvaluateHandleMethod",
            json=expectedJson,
            headers={"Content-type": "application/json"},
        )

    @staticmethod
    def testExecuteWithArguments(mockedRequestPost, mockedGetInstances):
        mockedGetInstances.return_value = [Instance(11111111)]
        obj = Objection("127.0.0.1:8888")
        method = Method(
            None,
            MethodObject(
                "La/b/clazz;",
                "methodName",
                "(Ljava/lang/String; Ljava/lang/String)Z",
            ),
        )

        obj.execute(method, ["Arg1", "Arg2"])

        expectedJson = {
            "handle": 11111111,
            "js": (
                'let clz = Java.use("a.b.clazz");\n'
                'let method = clz["methodName"]'
                '.overload("java.lang.String","java.lang.String");\n'
                'const result = method.call(clazz,"Arg1","Arg2");\n'
                "console.log(result);"
            ),
        }

        mockedRequestPost.assert_called_once_with(
            "http://127.0.0.1:8888/rpc/invoke/androidHeapEvaluateHandleMethod",
            json=expectedJson,
            headers={"Content-type": "application/json"},
        )
