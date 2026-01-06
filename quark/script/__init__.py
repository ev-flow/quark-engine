# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import re
import functools
from os import PathLike
from os.path import abspath, isfile, join
from typing import Any, Iterable, List, Tuple, Union
from collections import deque

from quark.config import DIR_PATH as QUARK_RULE_PATH
from quark.core.analysis import QuarkAnalysis
from quark.core.interface.baseapkinfo import XMLElement
from quark.core.quark import Quark
from quark.core.struct.methodobject import MethodObject
from quark.core.struct.ruleobject import RuleObject as Rule
from quark.core.struct.valuenode import iteratePriorCalls
from quark.evaluator.pyeval import PyEval
from quark.utils.regex import URL_REGEX

@functools.lru_cache
def _getQuark(apk: PathLike) -> Quark:
    return Quark(apk)


class Ruleset:
    def __init__(self, ruleFolder: PathLike) -> None:
        self.ruleFolder = ruleFolder

        # Apply cache
        self._loadRule = functools.lru_cache()(self._loadRuleWithoutCache)

    def __getitem__(self, key: str) -> Rule:
        return self._loadRule(key)

    def _loadRuleWithoutCache(self, key: str):
        absoluteRulePath = abspath(join(self.ruleFolder, key))

        if isfile(absoluteRulePath) and absoluteRulePath.endswith(".json"):
            return Rule(absoluteRulePath)
        else:
            raise KeyError(f"Unable to find file {absoluteRulePath}")


class DefaultRuleset(Ruleset):
    def __getitem__(self, key: Union[str, int]) -> Rule:
        return super().__getitem__(f"{key:05}.json")


DEFAULT_RULESET = DefaultRuleset(join(QUARK_RULE_PATH, "rules"))


class Application:
    def __init__(self, xml: XMLElement) -> None:
        self.xml: XMLElement = xml

    def __str__(self) -> str:
        return str(self._getAttribute("label"))

    def _getAttribute(
        self, attributeName: str, defaultValue: Any = None
    ) -> Any:
        realAttributeName = (
            f"{{http://schemas.android.com/apk/res/android}}{attributeName}"
        )
        return self.xml.get(realAttributeName, defaultValue)

    def isDebuggable(self) -> bool:
        """Check if the application element sets `android:debuggable=true`.

        :return: True/False
        """
        debuggable = self._getAttribute("debuggable")
        if debuggable is None:
            return False

        return str(debuggable).lower() == "true"


class Activity:
    def __init__(self, xml: XMLElement) -> None:
        self.xml: XMLElement = xml

    def __str__(self) -> str:
        return self._getAttribute("name")

    def _getAttribute(
        self, attributeName: str, defaultValue: Any = None
    ) -> Any:
        realAttributeName = (
            f"{{http://schemas.android.com/apk/res/android}}{attributeName}"
        )
        return self.xml.get(realAttributeName, defaultValue)

    def hasIntentFilter(self) -> bool:
        """Check if the activity has an intent filter.

        :return: True/False
        """
        return self.xml.find("intent-filter") is not None

    def isExported(self) -> bool:
        """Check if the activity is exported.

        :return: True/False
        """
        exported = self._getAttribute("exported", self.hasIntentFilter())
        return exported


class Receiver:
    def __init__(self, xml: XMLElement) -> None:
        self.xml: XMLElement = xml

    def __str__(self) -> str:
        return self._getAttribute("name")

    def _getAttribute(
        self, attributeName: str, defaultValue: Any = None
    ) -> Any:
        realAttributeName = (
            f"{{http://schemas.android.com/apk/res/android}}{attributeName}"
        )
        return self.xml.get(realAttributeName, defaultValue)

    def hasIntentFilter(self) -> bool:
        """Check if the receiver has an intent filter.

        :return: True/False
        """
        return self.xml.find("intent-filter") is not None

    def isExported(self) -> bool:
        """Check if the receiver is exported.

        According to the documentation from Android Developer guide.
        "
        If the attribute exported is unspecified, the default value depends on whether
        the broadcast receiver contains intent filters.
        If the receiver contains at least one intent filter,
        then the default value is "true".
        Otherwise, the default value is "false".
        "

        :return: True/False
        """
        exported = self._getAttribute("exported", self.hasIntentFilter())
        return str(exported).lower() == 'true'


class Provider:
    def __init__(self, xml: XMLElement) -> None:
        self.xml: XMLElement = xml

    def __str__(self) -> str:
        return self._getAttribute("name")

    def _getAttribute(self, attributeName: str) -> Any:
        realAttributeName = (
            f"{{http://schemas.android.com/apk/res/android}}{attributeName}"
        )
        return self.xml.get(realAttributeName, None)

    def isExported(self) -> bool:
        """Check if the provider element set ``android:exported=true``.

        :return: True/False
        """
        exported = self._getAttribute("exported")
        return exported


class Method:
    def __init__(
        self,
        quarkResultInstance: "QuarkResult" = None,
        methodObj: MethodObject = None,
        quark: "Quark" = None,
        behavior: "Behavior" = None,
        targetMethod: "Method" = None
    ) -> None:
        self.quark = quark
        self.quarkResult = quarkResultInstance
        self.innerObj = methodObj
        self.behavior = behavior
        self.targetMethod = targetMethod

    def __getattr__(self, name) -> Any:
        return getattr(self.innerObj, name)

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, Method):
            return __o.innerObj == self.innerObj

        return False

    def getXrefTo(self) -> List[Tuple["Method", int]]:
        """Find out who this method called.

        :return: python list containing tuples (callee methods, index)
        """
        return self.quarkResult.getMethodXrefTo(self)

    def getXrefFrom(self) -> List["Method"]:
        """Find out who call this method.

        :return: python list containing caller methods
        """
        return self.quarkResult.getMethodXrefFrom(self)

    def getArguments(self) -> List[Any]:
        """Get arguments from method.

        :return: python list containing arguments
        """

        if self.behavior is None or self.quarkResult is None:

            usageTable = self.quark._evaluate_method(
                self.innerObj
            )

            methodCalls = (
                methodCall
                for register in usageTable.values()
                for register_value in register
                for methodCall in register_value.iterateInvolvedCalls()
            )

            methodPattern = PyEval.get_method_pattern(
                self.targetMethod.innerObj.class_name,
                self.targetMethod.innerObj.name,
                self.targetMethod.innerObj.descriptor,
            )

            matchedCall = next(
                (
                    priorCall
                    for call in methodCalls
                    for priorCall in iteratePriorCalls(call)
                    if priorCall.method == methodPattern
                ),
                None,
            )

            return matchedCall.getArguments() if matchedCall else []

        firstAPI, secondAPI = self.behavior.firstAPI, self.behavior.secondAPI
        firstAPICall, secondAPICall = next(
            Quark.findMethodCallPairs(
                self.quarkResult.quark._evaluate_method(
                    self.behavior.methodCaller.innerObj
                ),
                (
                    firstAPI.className,
                    firstAPI.methodName,
                    firstAPI.descriptor),
                (
                    secondAPI.className,
                    secondAPI.methodName,
                    secondAPI.descriptor,
                ),
            ),
            (None, None),
        )

        apiCall = (
            firstAPICall if self == self.behavior.firstAPI else secondAPICall
        )
        return apiCall.getArguments() if apiCall else []

    def findSuperclassHierarchy(self) -> List[str]:
        """Find all superclasses of this method object.

        :return: Python list contains all superclass names of this method.
        """

        parentsHierarchy = list()
        targetClassAnalysis = self.quark.apkinfo.analysis.get_class_analysis(
            self.class_name)

        while targetClassAnalysis and "Ljava/lang/Object;" != targetClassAnalysis.extends:
            parentsHierarchy.append(targetClassAnalysis.extends)
            targetClassAnalysis = self.quark.apkinfo.analysis.get_class_analysis(
                targetClassAnalysis.extends)

        return parentsHierarchy

    @property
    def fullName(self) -> str:
        """Show the name of the method.

        :return: the name of the method
        """
        return self.innerObj.full_name

    @property
    def className(self) -> str:
        """Show the class name of the method.

        :return: the string of the method class name
        """
        return self.innerObj.class_name

    @property
    def methodName(self) -> str:
        """Show the method name of the method.

        :return: the string of the method name
        """
        return self.innerObj.name

    @property
    def descriptor(self) -> str:
        """Show the descriptor of the method.

        :return: the string of the method descriptor
        """
        return self.innerObj.descriptor


class Behavior:
    def __init__(
        self,
        quarkResultInstance: "QuarkResult",
        methodCaller: Method,
        firstAPI: Method,
        secondAPI: Method,
    ) -> None:
        self.quarkResult = quarkResultInstance
        self.methodCaller = methodCaller
        self.firstAPI = firstAPI
        self.secondAPI = secondAPI

        self.methodCaller.behavior = self
        self.firstAPI.behavior = self
        self.secondAPI.behavior = self

    def hasString(self, pattern: str, isRegex=False) -> List[str]:
        """Check if the arguments of the two APIs contain the string.

        :param pattern: string that may appear in the arguments
        :param isRegex: consider the string as a regular expression if True,
         defaults to False
        :return: the matched string
        """
        usageTable = self.quarkResult.quark._evaluate_method(
            self.methodCaller.innerObj
        )

        result_generator = (
            self.quarkResult.quark.checkParameterOnSingleMethod(
                usageTable=usageTable,
                firstMethod=self.firstAPI.innerObj,
                secondMethod=self.secondAPI.innerObj,
                firstMethodKeywords=(pattern,),
                secondMethodKeywords=(pattern,),
                regex=isRegex,
            )
        )

        found_keywords = {
            keyword
            for _, keyword_list in result_generator
            for keyword in keyword_list
        }

        return list(found_keywords)

    def hasUrl(self) -> List[str]:
        """Check if the behavior contains urls.

        :return: python list containing all detected urls
        """
        return self.hasString(URL_REGEX, True)

    def getParamValues(self) -> List[Any]:
        """Get parameter values from behavior.

        :return: python list containing parameter values
        """
        usageTable = self.quarkResult.quark._evaluate_method(self.methodCaller.innerObj)

        firstAPI, secondAPI = self.firstAPI, self.secondAPI
        _, secondAPI = next(
            Quark.findMethodCallPairs(
                usageTable,
                (firstAPI.className, firstAPI.methodName, firstAPI.descriptor),
                (secondAPI.className, secondAPI.methodName, secondAPI.descriptor),
            )
        )
        
        return secondAPI.getArguments()

    def isArgFromMethod(self, targetMethod: List[str]) -> bool:
        """Check if there are any argument from the target method.

        :param targetMethod: python list contains class name, method name, and
         descriptor of target method
        :return: True/False
        """
        usageTable = self.quarkResult.quark._evaluate_method(
            self.methodCaller.innerObj
        )

        firstAPI, secondAPI = self.firstAPI, self.secondAPI
        apiPairs = Quark.findMethodCallPairs(
            usageTable,
            (firstAPI.className, firstAPI.methodName, firstAPI.descriptor),
            (secondAPI.className, secondAPI.methodName, secondAPI.descriptor),
        )
        
        methodCallsInArgs = (
            call
            for _, secondApiCall in apiPairs
            for call in iteratePriorCalls(secondApiCall)
        )
        
        targetMethodPattern = PyEval.get_method_pattern(*targetMethod)
        return any(
            methodCall.method == targetMethodPattern
            for methodCall in methodCallsInArgs
        )

    def getMethodsInArgs(self) -> List[str]:
        """Get the methods which the arguments in API2 has passed through.

        :return: python list containing method instances
        """
        methodCalled = []
        usageTable = self.quarkResult.quark._evaluate_method(self.methodCaller.innerObj)

        firstAPI, secondAPI = self.firstAPI, self.secondAPI
        _, secondAPICall = next(
            Quark.findMethodCallPairs(
                usageTable,
                (firstAPI.className, firstAPI.methodName, firstAPI.descriptor),
                (secondAPI.className, secondAPI.methodName, secondAPI.descriptor),
            )
        )

        for methodCall in iteratePriorCalls(secondAPICall):
            result = methodCall.method
            className = result.split("->")[0]
            methodName = re.findall(r"->(.*?)\(", result)[0]
            descriptor = result.split(methodName)[-1]

            methodObj_list = self.quarkResult.quark.apkinfo.find_method(
                class_name=className,
                method_name=methodName,
                descriptor=descriptor
            )

            for methodObj in methodObj_list:
                methodCalled.append(Method(methodObj=methodObj))

        return methodCalled


class QuarkResult:
    def __init__(self, quark: Quark, ruleInstance: Rule) -> None:
        self.quark = quark
        self.quark.run(ruleInstance)
        self.rule = ruleInstance

        # Reset the Quark object
        self.innerObj = self.quark.quark_analysis
        self.quark.quark_analysis = QuarkAnalysis()

    @functools.cached_property
    def behaviorOccurList(self):
        """List that stores instances of detected behavior in different part of
         the target file.

        :return: detected behavior instance
        """
        occurList = [
            Behavior(
                quarkResultInstance=self,
                methodCaller=self._wrapMethodObject(
                    methodObj=call_graph_analysis["parent"],
                    quark=self.quark
                ),
                firstAPI=self._wrapMethodObject(
                    call_graph_analysis["first_call"],
                    quark=self.quark
                ),
                secondAPI=self._wrapMethodObject(
                    call_graph_analysis["second_call"],
                    quark=self.quark
                ),
            )
            for call_graph_analysis in self.innerObj.call_graph_analysis_list
        ]
        return occurList

    def getMethodXrefTo(self, method: Method) -> List[Tuple[Method, int]]:
        apkinfo = self.quark.apkinfo
        methodObj = method.innerObj

        callee_info = [
            (self._wrapMethodObject(callee), offset)
            for callee, offset in list(apkinfo.lowerfunc(methodObj))
        ]
        return callee_info

    def getMethodXrefFrom(self, method: Method) -> List[Method]:
        apkinfo = self.quark.apkinfo
        methodObj = method.innerObj

        caller_set = apkinfo.upperfunc(methodObj)
        return [self._wrapMethodObject(caller) for caller in list(caller_set)]

    def _wrapMethodObject(self, methodObj: MethodObject, quark: Quark = None,  targetMethod: Method = None) -> Method:
        return Method(self, methodObj=methodObj, quark=quark, targetMethod=targetMethod)

    def getAllStrings(self) -> List[str]:
        """
        List all strings inside the target APK.

        :return: python list containing all defined strings.
        """
        apkinfo = self.quark.apkinfo
        return apkinfo.get_strings()

    def isHardcoded(self, argument: str) -> bool:
        """
        Check if the argument is hardcoded into the APK.

        :params argument: string value that is passed in when a method is
         invoked
        :return: True/False
        """
        return argument in self.getAllStrings()

    def findMethodInCaller(
        self,
        callerMethod: Union[List[str], Method],
        targetMethod: Union[List[str], Method],
    ) -> List[Method]:
        """
        Find target method in caller method.

        :params callerMethod: python list or Method instance containing class
         name, method name and descriptor of caller method.
        :params targetMethod: python list or Method instance containing class
         name, method name and descriptor of target method.
        :return: python list contains target method instances.
        """

        def __convertMethodToListOfStr(method: Method) -> List[str]:
            return [method.className, method.methodName, method.descriptor]

        if isinstance(callerMethod, Method):
            callerMethod = __convertMethodToListOfStr(callerMethod)
        if isinstance(targetMethod, Method):
            targetMethod = __convertMethodToListOfStr(targetMethod)

        apkinfo = self.quark.apkinfo

        callerMethodObj = apkinfo.find_method(
            class_name=callerMethod[0],
            method_name=callerMethod[1],
            descriptor=callerMethod[2],
        )[0]

        if not callerMethodObj:
            print("Caller method not Found!")
            raise ValueError

        callerMethodInstance = Method(self, callerMethodObj)

        matchedMethods = []
        for calleeMethod, _ in callerMethodInstance.getXrefTo():
            if (
                calleeMethod.innerObj.class_name == targetMethod[0]
                and calleeMethod.innerObj.name == targetMethod[1]
                and calleeMethod.innerObj.descriptor == targetMethod[2]
            ):
                matchedMethods.append(calleeMethod)

        return [self._wrapMethodObject(
            callerMethodObj, self.quark, matchedMethod
        ) for matchedMethod in matchedMethods]


def runQuarkAnalysis(samplePath: PathLike, ruleInstance: Rule) -> QuarkResult:
    """Given detection rule and target sample, this instance runs the basic
     Quark.

    :param samplePath: Target file
    :param ruleInstance: Quark rule object
    :return: QuarkResult instance
    """
    quark = _getQuark(samplePath)
    analysis = QuarkResult(quark, ruleInstance)

    return analysis


def getActivities(samplePath: PathLike) -> List[Activity]:
    """Get activities from a target sample.

    :param samplePath: target file
    :return: python list containing activities
    """
    quark = _getQuark(samplePath)
    apkinfo = quark.apkinfo

    return [Activity(xml) for xml in apkinfo.activities]


def getReceivers(samplePath: PathLike) -> List[Receiver]:
    """Get receivers from a target sample.

    :param samplePath: target file
    :return: python list containing receivers
    """
    quark = _getQuark(samplePath)
    apkinfo = quark.apkinfo

    return [Receiver(xml) for xml in apkinfo.receivers]


def getApplication(samplePath: PathLike) -> Application:
    """Get the application element from the manifest file of the target sample.

    :param samplePath: the file path of the target sample
    :return: the application element of the target sample
    """
    quark = _getQuark(samplePath)
    apkinfo = quark.apkinfo

    return Application(apkinfo.application)


def getProviders(samplePath: PathLike) -> List[Provider]:
    """Get provider elements from the manifest file of the target sample.

    :param samplePath: the file path of target sample
    :return: python list containing provider elements
    """
    quark = _getQuark(samplePath)
    apkinfo = quark.apkinfo

    return [Provider(xml) for xml in apkinfo.providers]


def findMethodInAPK(
    samplePath: PathLike,
    targetMethod: Union[List[str], Method]
) -> List[Method]:
    """Find the target method in APK.

    :param samplePath: target file
    :param targetMethod: python list contains class name,
                         method name, and descriptor of target method
    :return: python list contains caller methods
    """

    def _wrapMethodObject(
        quark: Quark,
        methodObj: MethodObject,
        targetMethod: Method
    ) -> Method:
        if methodObj:
            return Method(
                quark=quark,
                methodObj=methodObj,
                targetMethod=targetMethod)
        else:
            return None

    quark = _getQuark(samplePath)
    match_methods = quark.apkinfo.find_method(
        class_name=targetMethod[0],
        method_name=targetMethod[1],
        descriptor=targetMethod[2],
    )

    if not match_methods:
        return []

    caller_methods = list()
    for method in match_methods:
        methodInstance = Method(methodObj=method)
        caller_set = quark.apkinfo.upperfunc(method)
        caller_methods += [
            _wrapMethodObject(quark, caller, methodInstance)
            for caller in list(caller_set)
        ]
    return caller_methods


def checkMethodCalls(
        samplePath: PathLike,
        targetMethod: Union[Tuple[str, str, str], MethodObject],
        checkMethods: List[Tuple[str, str, str]]) -> bool:
    """Check any of the specific methods shown in the target method.

    :param samplePath: target file
    :param targetMethod: python list contains the class name,
                         method name, and descriptor of the target method
                         or a Method Object
    :param checkMethods: python list contains the class name,
                         method name, and descriptor of the target method

    :return: bool that indicates if the specific methods are called or
             defined within a target method or not
    """
    targetMethodSet = set()
    checkMethodSet = set()
    targetLowerFuncSet = set()

    quark = _getQuark(samplePath)
    if isinstance(targetMethod, Iterable):
        # Find the method in the APK with the given class name, method name, and descriptor
        targetMethodSet.update(quark.apkinfo.find_method(*targetMethod))
    else:
        # targetMethod is already a Method object
        targetMethodSet.add(MethodObject)

    if not targetMethodSet:
        return False

    for candidate in checkMethods:
        checkMethodSet.update(quark.apkinfo.find_method(*candidate))

    targetLowerFuncSet = {i for i, _ in quark.apkinfo.lowerfunc(targetMethodSet.pop())}

    return any(checkMethodSet.intersection(targetLowerFuncSet))


def findMethodImpls(
    samplePath: PathLike,
    targetMethod: List[str]
) -> List[Method]:
    """Find all implementations of a specified method in the APK.

    :param samplePath: target file
    :param targetMethod: python list contains the class name,
                         method name, and descriptor of the target method

    :return: python list contains the method implementations of the
             target method
    """
    quark = _getQuark(samplePath)

    toVisitClassName = [targetMethod[0]]
    descendantClassNames = {targetMethod[0]}
    while toVisitClassName:
        currentClassName = toVisitClassName.pop()
        subclassNames = (quark.apkinfo.subclass_relationships
                         .get(currentClassName, []))
        for subclassName in subclassNames:
            if subclassName not in descendantClassNames:
                descendantClassNames.add(subclassName)
                toVisitClassName.append(subclassName)

    matchedMethods = []
    for className in descendantClassNames:
        methods = quark.apkinfo.find_method(
            class_name=className,
            method_name=targetMethod[1],
            descriptor=targetMethod[2],
        )
        for method in methods:
            matchedMethods.append(Method(methodObj=method))

    return matchedMethods


def isMethodReturnAlwaysTrue(
    samplePath: PathLike,
    targetMethod: List[str]
) -> bool:
    """Check if a method always returns True.

    :param samplePath: target file
    :param targetMethod: python list contains the class name,
                         method name, and descriptor of the target method

    :return: True/False
    """
    if targetMethod[2].split(")")[-1] != "Z":
        return False

    quark = _getQuark(samplePath)

    targetMethodObject = quark.apkinfo.find_method(
        targetMethod[0],
        targetMethod[1],
        targetMethod[2]
    )[0]

    instructions = deque(
        quark.apkinfo.get_method_bytecode(targetMethodObject), maxlen=2)

    returnTimes = 0
    for instruction in instructions:
        if instruction.mnemonic == "return":
            returnTimes += 1

    if returnTimes != 1:
        return False

    isSecondToLastInsAssignedRegisterToTrue = (
        (instructions[-2].mnemonic == "const/4") &
        (instructions[-2].parameter == 1)
    )
    isMethodReturnTrue = (
        isSecondToLastInsAssignedRegisterToTrue &
        (instructions[-1].registers == instructions[-2].registers) &
        (instructions[-1].mnemonic == "return") &
        (instructions[-1].parameter is None)
    )

    return isMethodReturnTrue
