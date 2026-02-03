# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from collections import namedtuple
import re
from typing import List, Tuple, Union

import requests
from quark.script import Method

SupportedTypes = [int, float, str]
Instance = namedtuple("Instance", ["hashCode"])


def convertMethodToString(method: Union[Method, List[str]]):
    def convertArgumentsToObjectionFormat(arguments: str):
        argList = arguments.split()
        argList = map(
            lambda a: a.replace("/", ".")
            if a.startswith("[L")
            else re.sub("(^L)|;", "", a).replace("/", "."),
            argList,
        )

        return ",".join(argList)

    # Convert method to a list of string if method is Method type
    if isinstance(method, Method):
        method = [method.class_name, method.name, method.descriptor]

    str_mapping = {
        "class_name": method[0][1:-1].replace("/", "."),
        "method_name": method[1],
        "arguments": convertArgumentsToObjectionFormat(
            method[2][1: method[2].index(")")]
        ),
    }
    return (
        "{class_name}.{method_name}".format_map(str_mapping),
        str_mapping["arguments"],
    )


class Objection:
    def __init__(self, host: str) -> None:
        """Create an instance for Objection (dynamic analysis tool).

        :param host: Monitoring IP:port
        """
        self.host = host

    def _sendRequest(
        self, rpcEndpoint: str, data: dict = None
    ) -> Tuple[int, dict]:
        url = f"http://{self.host}/rpc/invoke/{rpcEndpoint}"

        if data:
            response = requests.post(
                url, json=data, headers={"Content-type": "application/json"}
            )
        else:
            response = requests.get(url)

        return (response.status_code, response.json())

    def _getCurrentActivity(self) -> str:
        ENDPOINT = "androidHookingGetCurrentActivity"

        _, response = self._sendRequest(ENDPOINT)

        if response:
            return response["activity"]
        else:
            return None

    def getInstances(self, clazz: str) -> List[Instance]:
        """Get instances of the specified class.

        :param clazz: the target class
        :return: a list of instances
        """
        ENDPOINT = "androidHeapGetLiveClassInstances"
        data = {
            "clazz": clazz,
        }

        _, response = self._sendRequest(ENDPOINT, data)

        if response and isinstance(response, list):
            return [
                Instance(hashCode=jsonObj["hashcode"]) for jsonObj in response
            ]
        else:
            return []

    def hookMethod(
        self,
        method: Union[Method, str],
        overloadFilter: str = "",
        watchArgs: bool = False,
        watchBacktrace: bool = False,
        watchRet: bool = False,
    ):
        """Hook the target method with Objection.

        :param method: the target API
        :param overloadFilter: _description_, defaults to ""
        :param watchArgs: Return Args information if True, defaults to False
        :param watchBacktrace: Return backtrace information if True, defaults
         to False
        :param watchRet: Return the return information of the target API if
         True, defaults to False
        """

        # Convert Method object to a string
        if isinstance(method, Method):
            method, overloadFilter = convertMethodToString(method)

        ENDPOINT = "androidHookingWatchMethod"
        data = {
            "pattern": method,
            "overloadFilter": overloadFilter,
            "watchArgs": watchArgs,
            "watchBacktrace": watchBacktrace,
            "watchRet": watchRet,
        }

        self._sendRequest(ENDPOINT, data)

    def execute(
        self,
        method: Union[Method, List[str], str],
        arguments: List[object] = None,
    ) -> None:
        """Execute the target method.

        :param method: the target method
        :param arguments: the arguments passing to the method, defaults to []
        """
        if arguments is None:
            arguments = []

        if isinstance(method, (Method, List)):
            method, overloadFilter = convertMethodToString(method)
        else:
            overloadFilter = ""

        clazz, methodName = method.rsplit(".", 1)
        instance = next(iter(self.getInstances(clazz)), None)

        argStrs = []
        for arg in arguments:
            if isinstance(arg, str):
                argStrs.append(f'"{arg}"')
            elif isinstance(arg, Instance):
                argStrs.append(f"getInstance({arg.hashCode})")
            else:
                argStrs.append(str(arg))

        if overloadFilter:
            overloadFilterStr = ",".join(
                [
                    f'"{argType.strip()}"'
                    for argType in overloadFilter.split(",")
                ]
            )
        else:
            overloadFilterStr = None

        js = []

        js.append(f'let clz = Java.use("{clazz}");')

        if overloadFilterStr:
            js.append(
                (
                    f'let method = clz["{methodName}"]'
                    f".overload({overloadFilterStr});"
                )
            )
        else:
            js.append(f'let method = clz["{methodName}"];')

        if argStrs:
            js.append(
                f"const result = method.call"
                f'({"clazz" if instance is not None else "clz"},'
                f'{",".join(argStrs)});'
            )
        else:
            js.append(
                f"const result = method.call"
                f'({"clazz" if instance is not None else "clz"});'
            )

        js.append("console.log(result);")

        ENDPOINT = "androidHeapEvaluateHandleMethod"

        if instance:
            data = {
                "handle": instance.hashCode,
                "js": "\n".join(js),
            }

        else:
            currentActivity = self._getCurrentActivity()
            activityInstance = self.getInstances(currentActivity)[0]

            data = {
                "handle": activityInstance.hashCode,
                "js": "\n".join(js),
            }

        self._sendRequest(ENDPOINT, data)
