# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import pytest
from quark.core.quark import Quark
from quark.core.struct.methodobject import MethodObject
from quark.script import (
    Behavior,
    DefaultRuleset,
    Method,
    QuarkResult,
    Ruleset,
    checkMethodCalls,
    getActivities,
    getReceivers,
    getApplication,
    getProviders,
    runQuarkAnalysis,
    findMethodInAPK,
    findMethodImpls,
    isMethodReturnAlwaysTrue,
)

RULE_FOLDER_PATH = "tests/script/rules"
RULE_68_FILENAME = "00068.json"
RULE_193_FILENAME = "00193.json"


@pytest.fixture(scope="class")
def QUARK_ANALYSIS_RESULT_FOR_RULE_68(SAMPLE_PATH_14d9f):
    ruleset = Ruleset(RULE_FOLDER_PATH)
    return runQuarkAnalysis(SAMPLE_PATH_14d9f, ruleset[RULE_68_FILENAME])


@pytest.fixture(scope="class")
def QUARK_ANALYSIS_RESULT_FOR_RULE_193(SAMPLE_PATH_14d9f):
    ruleset = Ruleset(RULE_FOLDER_PATH)
    return runQuarkAnalysis(SAMPLE_PATH_14d9f, ruleset[RULE_193_FILENAME])


class TestRuleset:
    @staticmethod
    def testInitWithFolder():
        _ = Ruleset(RULE_FOLDER_PATH)

    @staticmethod
    def testGetExistentRule():
        ruleset = Ruleset(RULE_FOLDER_PATH)

        rule = ruleset[RULE_68_FILENAME]

        assert rule.crime == "Executes the specified string Linux command"

    @staticmethod
    def testGetNonexistentRule():
        NONEXISTENT_RULE = "NONEXISTENT_RULE.json"
        ruleset = Ruleset(RULE_FOLDER_PATH)

        with pytest.raises(KeyError):
            _ = ruleset[NONEXISTENT_RULE]


class TestDefaultRuleset:
    @staticmethod
    def testGetExistentRuleByNumber():
        ruleset = DefaultRuleset(RULE_FOLDER_PATH)

        rule = ruleset[68]

        assert rule.crime == "Executes the specified string Linux command"

    @staticmethod
    def testGetNonexistentRuleByNumber():
        ruleset = DefaultRuleset(RULE_FOLDER_PATH)

        with pytest.raises(KeyError):
            _ = ruleset[1]


class TestApplication:
    @staticmethod
    def testIsNotDebuggable(SAMPLE_PATH_Ahmyth):
        application = getApplication(SAMPLE_PATH_Ahmyth)
        assert application.isDebuggable() is False

    @staticmethod
    def testIsDebuggable(SAMPLE_PATH_13667):
        application = getApplication(SAMPLE_PATH_13667)
        assert application.isDebuggable() is True


class TestActivity:
    @staticmethod
    def testHasNoIntentFilter(SAMPLE_PATH_14d9f):
        activity = getActivities(SAMPLE_PATH_14d9f)[0]
        assert activity.hasIntentFilter() is False

    @staticmethod
    def testHasIntentFilter(SAMPLE_PATH_13667):
        activity = getActivities(SAMPLE_PATH_13667)[0]
        assert activity.hasIntentFilter() is True

    @staticmethod
    def testIsNotExported(SAMPLE_PATH_14d9f):
        activity = getActivities(SAMPLE_PATH_14d9f)[0]
        assert activity.isExported() is False

    @staticmethod
    def testIsExported(SAMPLE_PATH_13667):
        activity = getActivities(SAMPLE_PATH_13667)[0]
        assert activity.isExported() is True


class TestReceiver:
    @staticmethod
    def testHasNoIntentFilter(SAMPLE_PATH_13667):
        receiver = getReceivers(SAMPLE_PATH_13667)[2]
        assert receiver.hasIntentFilter() is False

    @staticmethod
    def testHasIntentFilter(SAMPLE_PATH_13667):
        receiver = getReceivers(SAMPLE_PATH_13667)[0]
        assert receiver.hasIntentFilter() is True

    @staticmethod
    def testIsNotExported(SAMPLE_PATH_13667):
        receiver = getReceivers(SAMPLE_PATH_13667)[2]
        assert receiver.isExported() is False

    @staticmethod
    def testIsExported(SAMPLE_PATH_13667):
        receiver = getReceivers(SAMPLE_PATH_13667)[0]
        assert receiver.isExported() is True

class TestProvider:
    @staticmethod
    def testIsNotExported(SAMPLE_PATH_Vuldroid):
        provider = getProviders(SAMPLE_PATH_Vuldroid)[0]
        assert provider.isExported() is False

    @staticmethod
    def testIsExported(SAMPLE_PATH_pivaa):
        provider = getProviders(SAMPLE_PATH_pivaa)[0]
        assert provider.isExported() is True

class TestMethod:
    @staticmethod
    def testInit(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        methodObj = MethodObject(
            class_name="Lcom/google/progress/WifiCheckTask;",
            name="checkWifiCanOrNotConnectServer",
            descriptor="()Z",
        )

        method = Method(QUARK_ANALYSIS_RESULT_FOR_RULE_68, methodObj)

        assert (
            method.fullName == "Lcom/google/progress/WifiCheckTask;"
            " checkWifiCanOrNotConnectServer ()Z"
        )

    @staticmethod
    def testGetXrefTo(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        methodObj = (
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark.apkinfo.find_method(
                "Lcom/google/progress/WifiCheckTask;",
                "checkWifiCanOrNotConnectServer",
                "()Z",
            )[0]
        )
        method = Method(QUARK_ANALYSIS_RESULT_FOR_RULE_68, methodObj)

        expectedMethod = Method(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68,
            MethodObject(
                "Landroid/util/Log;",
                "e",
                "(Ljava/lang/String; Ljava/lang/String;)I",
            ),
        )
        expectedOffset = 116

        callee_list = method.getXrefTo()

        assert (expectedMethod, expectedOffset) in callee_list

    @staticmethod
    def testGetXrefFrom(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        methodObj = (
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark.apkinfo.find_method(
                "Lcom/google/progress/WifiCheckTask;",
                "checkWifiCanOrNotConnectServer",
                "([Ljava/lang/String;)Z",
            )[0]
        )
        method = Method(QUARK_ANALYSIS_RESULT_FOR_RULE_68, methodObj)

        expectedMethod = Method(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68,
            MethodObject("Lcom/google/progress/WifiCheckTask;", "test", "()V"),
        )

        caller_list = method.getXrefFrom()

        assert expectedMethod in caller_list

    @staticmethod
    def testGetArguments(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        def __getMethod(
            quarkResult: QuarkResult,
            className: str,
            methodName: str,
            descriptor: str,
        ) -> Method:
            methodObj = quarkResult.quark.apkinfo.find_method(
                className, methodName, descriptor
            )[0]
            return Method(quarkResult, methodObj)

        def __getMethodWithTarget(
            quark: Quark,
            methodObj: MethodObject,
            targetMethod: Method
        ) -> Method:
            return Method(
                quark=quark,
                methodObj=methodObj,
                targetMethod=targetMethod
            )

        methodCaller = __getMethod(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68,
            "Lcom/google/progress/AndroidClientService;",
            "onCreate",
            "()V",
        )
        firstAPI = __getMethod(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68,
            "Ljava/lang/Class;",
            "getDeclaredMethod",
            "(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;",
        )
        secondAPI = __getMethod(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68,
            "Ljava/lang/reflect/Method;",
            "setAccessible",
            "(Z)V",
        )
        behavior = Behavior(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68,
            methodCaller,
            firstAPI,
            secondAPI,
        )

        targetMethod = \
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark.apkinfo.find_method(
                class_name="Landroid/util/Log;",
                method_name="e",
                descriptor="(Ljava/lang/String; Ljava/lang/String;)I",
            )[0]

        callerMethodObj = \
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark.apkinfo.find_method(
                class_name="Lcom/google/progress/WifiCheckTask;",
                method_name="CloseWifi",
                descriptor="()V",
            )[0]

        targetMethod = Method(methodObj=targetMethod)
        callerMethodInstance = __getMethodWithTarget(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark,
            callerMethodObj,
            targetMethod
        )

        arguments = behavior.secondAPI.getArguments()
        argumentsOfTargetMethod = callerMethodInstance.getArguments()
        assert arguments[1:] == [True]
        assert argumentsOfTargetMethod[0] == "wifi"

    @staticmethod
    def testFindSuperclassHierarchy(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        methodObj = MethodObject(
            class_name="Lcom/google/progress/WifiCheckTask;",
            name="checkWifiCanOrNotConnectServer",
            descriptor="()Z",
        )

        method = Method(QUARK_ANALYSIS_RESULT_FOR_RULE_68,
                        methodObj, QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark)

        assert (
            ["Ljava/util/TimerTask;"] == method.findSuperclassHierarchy()
        )


class TestBehavior:
    @staticmethod
    def testHasString(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        behaviorOccurList = QUARK_ANALYSIS_RESULT_FOR_RULE_68.behaviorOccurList
        behavior = next(
            filter(
                lambda b: "checkWifiCanOrNotConnectServer"
                in b.methodCaller.fullName,
                behaviorOccurList,
            )
        )

        result = behavior.hasString("ping")

        assert result

    @staticmethod
    def testHasUrl(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        behaviorOccurList = QUARK_ANALYSIS_RESULT_FOR_RULE_68.behaviorOccurList
        behavior = next(
            filter(
                lambda b: "checkWifiCanOrNotConnectServer"
                in b.methodCaller.fullName,
                behaviorOccurList,
            )
        )

        result = behavior.hasUrl()

        assert "www.baidu.com" in result

    @staticmethod
    def testGetParamValues(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        behaviorOccurList = QUARK_ANALYSIS_RESULT_FOR_RULE_68.behaviorOccurList
        behavior = next(
            filter(
                lambda b: "checkWifiCanOrNotConnectServer"
                in b.methodCaller.fullName,
                behaviorOccurList,
            )
        )

        assert behavior.getParamValues()[1] == "ping www.baidu.com"

    @staticmethod
    def testIsArgFromMethod(QUARK_ANALYSIS_RESULT_FOR_RULE_193):
        behaviorOccurList = (
            QUARK_ANALYSIS_RESULT_FOR_RULE_193.behaviorOccurList
        )
        behavior = behaviorOccurList[0]

        expectedMethod = [
            "Landroid/app/PendingIntent;",
            "getBroadcast",
            "(Landroid/content/Context; I Landroid/content/Intent;"
            " I)Landroid/app/PendingIntent;",
        ]

        assert behavior.isArgFromMethod(expectedMethod)

    @staticmethod
    def testGetMethodsInArgs(QUARK_ANALYSIS_RESULT_FOR_RULE_193):
        behaviorOccurList = (
            QUARK_ANALYSIS_RESULT_FOR_RULE_193.behaviorOccurList
        )
        behavior = behaviorOccurList[0]
        method = behavior.getMethodsInArgs()[0].fullName

        assert method == "Landroid/telephony/SmsManager;" + \
            " getDefault ()Landroid/telephony/SmsManager;"


class TestQuarkReuslt:
    @staticmethod
    def testMethodGetXrefTo(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        methodObj = (
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark.apkinfo.find_method(
                "Lcom/google/progress/WifiCheckTask;",
                "checkWifiCanOrNotConnectServer",
                "()Z",
            )[0]
        )
        method = Method(QUARK_ANALYSIS_RESULT_FOR_RULE_68, methodObj)

        expectedMethod = Method(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68,
            MethodObject(
                "Landroid/util/Log;",
                "e",
                "(Ljava/lang/String; Ljava/lang/String;)I",
            ),
        )
        expectedOffset = 116

        callee_list = QUARK_ANALYSIS_RESULT_FOR_RULE_68.getMethodXrefTo(method)

        assert (expectedMethod, expectedOffset) in callee_list

    @staticmethod
    def testMethodGetXrefFrom(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        methodObj = (
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark.apkinfo.find_method(
                "Lcom/google/progress/WifiCheckTask;",
                "checkWifiCanOrNotConnectServer",
                "([Ljava/lang/String;)Z",
            )[0]
        )
        method = Method(QUARK_ANALYSIS_RESULT_FOR_RULE_68, methodObj)

        expectedMethod = Method(
            QUARK_ANALYSIS_RESULT_FOR_RULE_68,
            MethodObject("Lcom/google/progress/WifiCheckTask;", "test", "()V"),
        )

        caller_list = QUARK_ANALYSIS_RESULT_FOR_RULE_68.getMethodXrefFrom(
            method
        )

        assert expectedMethod in caller_list

    @staticmethod
    def testGetAllStrings(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        assert len(QUARK_ANALYSIS_RESULT_FOR_RULE_68.getAllStrings()) == 1005

    @staticmethod
    def testIsHardCoded(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        assert QUARK_ANALYSIS_RESULT_FOR_RULE_68.isHardcoded("gps") is True

    @staticmethod
    def testIsNotHardCoded(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        assert QUARK_ANALYSIS_RESULT_FOR_RULE_68.isHardcoded(
            "Quark") is False

    @staticmethod
    def testFindMethodInCallerWithListOfStr(QUARK_ANALYSIS_RESULT_FOR_RULE_68):
        callerMethod = [
            "Lcom/google/progress/WifiCheckTask;",
            "checkWifiCanOrNotConnectServer",
            "([Ljava/lang/String;)Z",
        ]
        targetMethod = [
            "Landroid/util/Log;",
            "e",
            "(Ljava/lang/String; Ljava/lang/String;)I",
        ]

        assert QUARK_ANALYSIS_RESULT_FOR_RULE_68.findMethodInCaller(
            callerMethod, targetMethod
        )

    @staticmethod
    def testFindMethodInCallerWithMethodInstance(
        QUARK_ANALYSIS_RESULT_FOR_RULE_68,
    ):
        callerObj = (
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark.apkinfo.find_method(
                "Lcom/google/progress/WifiCheckTask;",
                "checkWifiCanOrNotConnectServer",
                "([Ljava/lang/String;)Z",
            )[0]
        )
        caller = Method(QUARK_ANALYSIS_RESULT_FOR_RULE_68, callerObj)

        targetObj = (
            QUARK_ANALYSIS_RESULT_FOR_RULE_68.quark.apkinfo.find_method(
                "Landroid/util/Log;",
                "e",
                "(Ljava/lang/String; Ljava/lang/String;)I",
            )[0]
        )
        target = Method(QUARK_ANALYSIS_RESULT_FOR_RULE_68, targetObj)

        assert QUARK_ANALYSIS_RESULT_FOR_RULE_68.findMethodInCaller(
            caller, target
        )


def testRunQuarkAnalysis(SAMPLE_PATH_14d9f):
    ruleset = Ruleset(RULE_FOLDER_PATH)
    ruleObj = ruleset[RULE_68_FILENAME]

    analysisResult = runQuarkAnalysis(SAMPLE_PATH_14d9f, ruleObj)

    assert len(analysisResult.behaviorOccurList) == 1


def testGetActivities(SAMPLE_PATH_14d9f) -> None:
    activities = getActivities(SAMPLE_PATH_14d9f)

    assert len(activities) == 1
    assert str(activities[0]) == "com.google.progress.BackGroundActivity"


def testGetReceivers(SAMPLE_PATH_14d9f) -> None:
    receivers = getReceivers(SAMPLE_PATH_14d9f)

    assert len(receivers) == 1
    assert str(receivers[0]) == "com.google.progress.BootReceiver"


def testfindMethodInAPK(SAMPLE_PATH_14d9f) -> None:

    method = findMethodInAPK(SAMPLE_PATH_14d9f, [
        "Lcom/google/progress/WifiCheckTask;",
        "checkWifiCanOrNotConnectServer",
        "([Ljava/lang/String;)Z"]
    )

    assert len(method) == 2


def testCheckMethodCalls(SAMPLE_PATH_14d9f) -> None:
    targetMethod = [
        "Lcom/google/progress/WifiCheckTask;",
        "checkWifiCanOrNotConnectServer",
        "([Ljava/lang/String;)Z"
    ]

    checkMethods  = []
    checkMethods.append(tuple([
        "Landroid/util/Log;",
        "e",
        "(Ljava/lang/String; Ljava/lang/String;)I"
    ]))

    assert checkMethodCalls(SAMPLE_PATH_14d9f, targetMethod, checkMethods) is True


def testFindMethodImpls(SAMPLE_PATH_pivaa) -> None:
    abstractMethod = [
        "Ljavax/net/ssl/HostnameVerifier;",
        "verify",
        "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
    ]
    methodImpls = findMethodImpls(SAMPLE_PATH_pivaa, abstractMethod)
    assert len(methodImpls) == 1
    assert methodImpls[0].className == "Lcom/htbridge/pivaa/handlers/API$1;"
    assert methodImpls[0].methodName == abstractMethod[1]
    assert methodImpls[0].descriptor == abstractMethod[2]


def testIsMethodReturnAlwaysTrue(SAMPLE_PATH_pivaa) -> None:
    targetMethod = [
        "Lcom/htbridge/pivaa/handlers/API$1;",
        "verify",
        "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
    ]
    assert isMethodReturnAlwaysTrue(SAMPLE_PATH_pivaa, targetMethod) is True
