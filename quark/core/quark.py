# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from itertools import product
import operator
import os
import re
from typing import Any, Generator, List, Mapping, Sequence, Tuple

import numpy as np
import csv

from quark.core.analysis import QuarkAnalysis
from quark.core.shurikenapkinfo import ShurikenImp
from quark.core.apkinfo import AndroguardImp
from quark.core.rzapkinfo import RizinImp
from quark.core.r2apkinfo import R2Imp
from quark.core.struct.methodobject import MethodObject
from quark.core.struct.registerobject import RegisterObject
from quark.evaluator.pyeval import PyEval
from quark.core.struct.valuenode import MethodCall, iteratePriorCalls, iteratePriorPrimitives
from quark.utils import tools
from quark.utils.colors import (
    colorful_report,
    green,
    lightblue,
    lightyellow,
    magenta,
    red,
    yellow,
)
from quark.utils.graph import call_graph
from quark.utils.output import (
    get_rule_classification_data,
    output_parent_function_graph,
    output_parent_function_json,
    output_parent_function_table,
)
from quark.utils.pprint import print_info, print_success, print_warning
from quark.utils.weight import Weight

MAX_SEARCH_LAYER = 3


class Quark:
    """Quark module is used to check quark's five-stage theory"""

    def __init__(self, apk, core_library="androguard"):
        """

        :param apk: the filename of the apk.
        """
        core_library = core_library.lower()
        if core_library == "shuriken":
            self.apkinfo = ShurikenImp(apk)
        elif core_library == "rizin":
            self.apkinfo = RizinImp(apk)
        elif core_library == "radare2":
            self.apkinfo = R2Imp(apk)
        elif core_library == "androguard":
            self.apkinfo = AndroguardImp(apk)
        else:
            raise ValueError(
                f"Unsupported core library for Quark: {core_library}"
            )

        self.quark_analysis = QuarkAnalysis()

    def find_previous_method(
        self, base_method, parent_function, wrapper, visited_methods=None
    ):
        """
        Find the method under the parent function, based on base_method before to parent_function.
        This will append the method into wrapper.

        :param base_method: the base function which needs to be searched.
        :param parent_function: the top-level function which calls the basic function.
        :param wrapper: list is used to track each function.
        :param visited_methods: set with tested method.
        :return: None
        """
        if visited_methods is None:
            visited_methods = set()

        method_set = self.apkinfo.upperfunc(base_method)
        visited_methods.add(base_method)

        if method_set is not None:

            if parent_function in method_set:
                wrapper.append(base_method)
            else:
                for item in method_set:
                    # prevent to test the tested methods.
                    if item in visited_methods:
                        continue
                    self.find_previous_method(
                        item, parent_function, wrapper, visited_methods
                    )

    def find_intersection(self, first_method_set, second_method_set, depth=1):
        """
        Find the first_method_list ∩ second_method_list.
        [MethodAnalysis, MethodAnalysis,...]

        :param first_method_set: first list that contains each MethodAnalysis.
        :param second_method_set: second list that contains each MethodAnalysis.
        :param depth: maximum number of recursive search functions.
        :return: a set of first_method_list ∩ second_method_list or None.
        """
        # Check both lists are not null

        if not first_method_set or not second_method_set:
            raise ValueError("Set is Null")
        # find ∩
        result = first_method_set & second_method_set
        if result:
            return result
        else:
            return self.method_recursive_search(
                depth, first_method_set, second_method_set
            )

    def method_recursive_search(
        self, depth, first_method_set, second_method_set
    ):
        # Not found same method usage, try to find the next layer.
        depth += 1
        if depth > MAX_SEARCH_LAYER:
            return None

        # Append first layer into next layer.
        next_level_set_1 = first_method_set.copy()
        next_level_set_2 = second_method_set.copy()

        # Extend the xref from function into next layer.
        for method in first_method_set:
            method_caller = self.apkinfo.upperfunc(method)
            if method_caller:
                next_level_set_1 = (
                    method_caller | next_level_set_1
                )
        for method in second_method_set:
            method_caller = self.apkinfo.upperfunc(method)
            if method_caller:
                next_level_set_2 = (
                    method_caller | next_level_set_2
                )

        return self.find_intersection(
            next_level_set_1, next_level_set_2, depth
        )

    def check_sequence(
        self, mutual_parent, first_method_list, second_method_list
    ):
        """
        Check if the first function appeared before the second function.

        :param mutual_parent: function that call the first function and second functions at the same time.
        :param first_method_list: the first show up function, which is a MethodAnalysis
        :param second_method_list: the second show up function, which is a MethodAnalysis
        :return: True or False
        """
        state = False

        for first_call_method in first_method_list:
            for second_call_method in second_method_list:

                seq_table = [
                    (call, number)
                    for call, number in self.apkinfo.lowerfunc(mutual_parent)
                    if call in (first_call_method, second_call_method)
                ]

                # sorting based on the value of the number
                if len(seq_table) < 2:
                    # Not Found sequence in same_method
                    continue
                seq_table.sort(key=operator.itemgetter(1))
                # seq_table would look like: [(getLocation, 1256), (sendSms, 1566), (sendSms, 2398)]

                method_list_need_check = [x[0] for x in seq_table]
                sequence_pattern_method = [
                    first_call_method,
                    second_call_method,
                ]

                if tools.contains(
                    sequence_pattern_method, method_list_need_check
                ):
                    state = True

                    # Record the mapping between the parent function and the wrapper method
                    self.quark_analysis.parent_wrapper_mapping[
                        mutual_parent.full_name
                    ] = self.apkinfo.get_wrapper_smali(
                        mutual_parent, first_call_method, second_call_method
                    )

        return state

    def _evaluate_method(self, method) -> List[List[str]]:
        """
        Evaluate the execution of the opcodes in the target method and return
         the usage of each involved register.

        :param method: Method to be evaluated
        :return: Matrix that holds the usage of the registers
        """
        pyeval = PyEval(self.apkinfo)

        for bytecode_obj in self.apkinfo.get_method_bytecode(method):
            # ['new-instance', 'v4', Lcom/google/progress/SMSHelper;]
            instruction = [bytecode_obj.mnemonic]
            if bytecode_obj.registers is not None:
                instruction.extend(bytecode_obj.registers)
            if bytecode_obj.parameter is not None:
                instruction.append(bytecode_obj.parameter)

            # for the case of MUTF8String
            instruction = [str(x) for x in instruction]

            if instruction[0] in pyeval.eval.keys():
                pyeval.eval[instruction[0]](instruction)

        return pyeval.show_table()

    def checkParameterOnSingleMethod(
        self,
        usageTable: Mapping[int, Sequence[RegisterObject]],
        firstMethod: MethodObject,
        secondMethod: MethodObject,
        firstMethodKeywords: Sequence | None = None,
        secondMethodKeywords: Sequence | None = None,
        regex: bool = False,
    ) -> Generator[Tuple[Tuple[MethodCall, MethodCall], List[str]], None, None]:
        """Check the usage of the same parameter between two methods.

        :param usageTable: a table that records the usage of each register
        :param firstMethod: the first API or a method calling the first API
        :param secondMethod: the second API or a method calling the second API
        :param firstMethodKeywords: keywords to match for the first method,
        defaults to None
        :param secondMethodKeywords: keywords to match for the second method,
        defaults to None
        :param regex: treat keywords as regular expressions, defaults to False
        :yield: a tuple of matched method call pairs and matched keywords
        """
        # Find the first and second method call that share same register
        matchedCallPairs = self.findMethodCallPairs(
            usageTable,
            (
                firstMethod.class_name,
                firstMethod.name,
                firstMethod.descriptor,
            ),
            (
                secondMethod.class_name,
                secondMethod.name,
                secondMethod.descriptor,
            ),
        )

        # Skip if no keywords provided for both methods.
        if not firstMethodKeywords and not secondMethodKeywords:
            for matchedCallPair in matchedCallPairs:
                yield (matchedCallPair, [])
            return

        # Do keyword matching
        for firstCall, secondCall in matchedCallPairs:
            matchedKeywords = []
            if firstMethodKeywords is not None:
                # Check if arguments of the first call match any keywords.
                first_matched = self.getMatchedKeywords(
                    firstCall, firstMethodKeywords, regex=regex
                )
                matchedKeywords.extend(first_matched)

            if secondMethodKeywords is not None:
                # Check if arguments of the second call match any keywords.
                second_matched = self.getMatchedKeywords(
                    secondCall, secondMethodKeywords, regex=regex
                )
                matchedKeywords.extend(second_matched)

            # Pass only if at least one keyword was matched.
            if len(matchedKeywords) > 0:
                yield ((firstCall, secondCall), matchedKeywords)

    def check_parameter(
        self,
        parent_method: MethodObject,
        first_method_list: Sequence[MethodObject],
        second_method_list: Sequence[MethodObject],
        first_method_keywords: Sequence[Any] | None = None,
        second_method_keywords: Sequence[Any] | None = None,
        regex: bool = False,
    ) -> bool:
        """Check the usage of the same parameter between two method.

        :param parent_method: the method to do the check
        :param first_method_list: a list of first API and methods that calls
        the first API
        :param second_method_list: a list of second API and methods that calls
        the second API
        :param first_method_keywords: keywords to match for the first method,
        defaults to None
        :param second_method_keywords: keywords to match for the second method,
        defaults to None
        :param regex: treat keywords as regular expressions, defaults to False
        :return: True or False
        """
        if parent_method is None:
            raise TypeError("Parent function is None.")

        if first_method_list is None or second_method_list is None:
            raise TypeError("First or second method list is None.")

        # Evaluate the opcode in the parent function
        usage_table = self._evaluate_method(parent_method)

        # Check if any of the target methods (the first and second methods)
        #  used the same registers.
        state = False
        for first_method, second_method in product(
            first_method_list, second_method_list
        ):
            results = self.checkParameterOnSingleMethod(
                usage_table,
                first_method,
                second_method,
                first_method_keywords,
                second_method_keywords,
                regex,
            )

            found = next(results, None) is not None

            if not found:
                continue

            # Build for the call graph
            call_graph_analysis = {
                "parent": parent_method,
                "first_call": first_method,
                "second_call": second_method,
                "apkinfo": self.apkinfo,
                "first_api": self.quark_analysis.first_api,
                "second_api": self.quark_analysis.second_api,
                "crime": self.quark_analysis.crime_description,
            }
            self.quark_analysis.call_graph_analysis_list.append(
                call_graph_analysis
            )

            # Record the mapping between the parent function and the
            #  wrapper method
            self.quark_analysis.parent_wrapper_mapping[
                parent_method.full_name
            ] = self.apkinfo.get_wrapper_smali(
                parent_method,
                first_method,
                second_method,
            )

            state = True

        return state

    @staticmethod
    def getMatchedKeywords(
        methodCall: MethodCall, keywords: Sequence, regex: bool
    ) -> List[str]:
        """Get matched keywords from the parameters of a method call.

        :param method_call: the method call to be checked
        :param keywords: keywords to be matched
        :param regex: whether to treat keywords as regular expressions
        :yield: a list of matched keywords
        """
        matchedStrSet = set()
        primitiveValues = {
            str(primitive.value)
            for primitive in iteratePriorPrimitives(methodCall)
        }

        if not regex:
            return [
                value
                for value in primitiveValues
                if any(kw in value for kw in keywords)
            ]

        for keyword in keywords:
            regexPattern = re.compile(keyword)

            for value in primitiveValues:
                matchedStrings = regexPattern.findall(value)
                if not any(matchedStrings):
                    continue

                # Filter out empty strings from tuples in the result
                if isinstance(matchedStrings[0], tuple):
                    for matchTuple in matchedStrings:
                        matchedStrSet.update(filter(bool, matchTuple))
                else:
                    matchedStrSet.update(filter(bool, matchedStrings))

        return [e for e in list(matchedStrSet) if bool(e)]

    def find_api_usage(self, class_name, method_name, descriptor_name):
        method_list = []

        # Source method
        source_method = self.apkinfo.find_method(
            class_name, method_name, descriptor_name
        )
        if source_method:
            return source_method

        # Potential Method
        potential_method_list = [
            method
            for method in self.apkinfo.all_methods
            if method.name == method_name
            and method.descriptor == descriptor_name
        ]

        potential_method_list = [
            method
            for method in potential_method_list
            if not next(self.apkinfo.get_method_bytecode(method), None)
        ]

        # Check if each method's class is a subclass of the given class
        for method in potential_method_list:
            current_class_set = {method.class_name}

            while current_class_set and not current_class_set.intersection(
                {class_name, "Ljava/lang/Object;"}
            ):
                next_class_set = set()
                for clazz in current_class_set:
                    next_class_set.update(
                        self.apkinfo.superclass_relationships[clazz]
                    )

                current_class_set = next_class_set

            current_class_set.discard("Ljava/lang/Object;")
            if current_class_set:
                method_list.append(method)

        return method_list

    def run(self, rule_obj):
        """
        Run the five levels check to get the y_score.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        self.quark_analysis.clean_result()
        self.quark_analysis.crime_description = rule_obj.crime

        # Level 1: Permission Check
        if self.apkinfo.ret_type == "DEX":
            rule_obj.check_item[0] = True
        elif set(rule_obj.permission).issubset(set(self.apkinfo.permissions)):
            rule_obj.check_item[0] = True
        else:
            # Exit if the level 1 stage check fails.
            return

        # Level 2: Single Native API Check
        api_1_method_name = rule_obj.api[0]["method"]
        api_1_class_name = rule_obj.api[0]["class"]
        api_1_descriptor = rule_obj.api[0]["descriptor"]

        api_2_method_name = rule_obj.api[1]["method"]
        api_2_class_name = rule_obj.api[1]["class"]
        api_2_descriptor = rule_obj.api[1]["descriptor"]

        first_api_list = self.find_api_usage(
            api_1_class_name, api_1_method_name, api_1_descriptor
        )
        second_api_list = self.find_api_usage(
            api_2_class_name, api_2_method_name, api_2_descriptor
        )

        if not first_api_list and not second_api_list:
            # Exit if the level 2 stage check fails.
            return

        else:
            rule_obj.check_item[1] = True

        if first_api_list:
            self.quark_analysis.level_2_result.append(first_api_list[0])
        if second_api_list:
            self.quark_analysis.level_2_result.append(second_api_list[0])

        # Level 3: Both Native API Check
        if not (first_api_list and second_api_list):
            # Exit if the level 3 stage check fails.
            return

        self.quark_analysis.first_api = first_api_list[0]
        self.quark_analysis.second_api = second_api_list[0]
        rule_obj.check_item[2] = True

        self.quark_analysis.level_3_result = [set(), set()]

        # Level 4: Sequence Check
        for first_api in first_api_list:
            for second_api in second_api_list:
                # Looking for the first layer of the upper function
                first_api_xref_from = self.apkinfo.upperfunc(first_api)
                second_api_xref_from = self.apkinfo.upperfunc(second_api)

                self.quark_analysis.level_3_result[0].update(
                    first_api_xref_from
                )
                self.quark_analysis.level_3_result[1].update(
                    second_api_xref_from
                )

                if not first_api_xref_from:
                    print_warning(
                        f"Unable to find the upperfunc of {first_api}"
                    )
                    continue
                if not second_api_xref_from:
                    print_warning(
                        f"Unable to find the upperfunc of{second_api}"
                    )
                    continue

                mutual_parent_function_list = self.find_intersection(
                    first_api_xref_from, second_api_xref_from
                )

                if mutual_parent_function_list is None:
                    # Exit if the level 4 stage check fails.
                    return
                for parent_function in mutual_parent_function_list:
                    first_wrapper = []
                    second_wrapper = []

                    self.find_previous_method(
                        first_api, parent_function, first_wrapper
                    )
                    self.find_previous_method(
                        second_api, parent_function, second_wrapper
                    )
                    if self.check_sequence(
                        parent_function, first_wrapper, second_wrapper
                    ):
                        rule_obj.check_item[3] = True
                        self.quark_analysis.level_4_result.append(
                            parent_function
                        )

                        # Level 5: Handling The Same Register Check
                        if self.check_parameter(
                            parent_function,
                            first_wrapper,
                            second_wrapper,
                            rule_obj.firstApiKeywords,
                            rule_obj.secondApiKeywords,
                        ):
                            rule_obj.check_item[4] = True
                            self.quark_analysis.level_5_result.append(
                                parent_function
                            )

    def get_json_report(self):
        """
        Get quark report including summary and detail with json format.

        :return: json report
        """

        w = Weight(
            self.quark_analysis.score_sum, self.quark_analysis.weight_sum
        )
        warning = w.calculate()

        # Filter out color code in threat level
        for level in ["Low Risk", "Moderate Risk", "High Risk"]:
            if level in warning:
                warning = level

        return {
            "md5": self.apkinfo.md5,
            "apk_filename": self.apkinfo.filename,
            "size_bytes": self.apkinfo.filesize,
            "threat_level": warning,
            "total_score": int(self.quark_analysis.score_sum + 0.5),
            "crimes": self.quark_analysis.json_report,
        }

    def generate_json_report(self, rule_obj):
        """
        Show the json report.

        :param rule_obj: the instance of the RuleObject
        :return: None
        """
        # Count the confidence
        confidence = str(rule_obj.check_item.count(True) * 20) + "%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.score

        # Assign level 1 examine result
        permissions = rule_obj.permission if rule_obj.check_item[0] else []

        # Assign level 2 examine result
        api = []
        if rule_obj.check_item[1]:
            for item2 in self.quark_analysis.level_2_result:
                api.append(
                    {
                        "class": str(item2.class_name),
                        "method": str(item2.name),
                        "descriptor": str(item2.descriptor),
                    }
                )

        # Assign level 3 examine result
        combination = []
        if rule_obj.check_item[2]:
            combination = rule_obj.api

        # Assign level 4 - 5 examine result if exist
        sequnce_show_up = []
        same_operation_show_up = []

        # Check examination has passed level 4
        if self.quark_analysis.level_4_result and rule_obj.check_item[3]:
            for item4 in self.quark_analysis.level_4_result:
                sequnce_show_up.append(
                    {
                        item4.full_name: self.quark_analysis.parent_wrapper_mapping[
                            item4.full_name
                        ]
                    }
                )

            # Check examination has passed level 5
            if self.quark_analysis.level_5_result and rule_obj.check_item[4]:
                for item5 in self.quark_analysis.level_5_result:
                    same_operation_show_up.append(
                        {
                            item5.full_name: self.quark_analysis.parent_wrapper_mapping[
                                item5.full_name
                            ]
                        }
                    )

        crime = {
            "rule": rule_obj.rule_filename,
            "crime": rule_obj.crime,
            "label": rule_obj.label,
            "score": score,
            "weight": weight,
            "confidence": confidence,
            "permissions": permissions,
            "native_api": api,
            "combination": combination,
            "sequence": sequnce_show_up,
            "register": same_operation_show_up,
        }
        self.quark_analysis.json_report.append(crime)

        # add the weight
        self.quark_analysis.weight_sum += weight
        # add the score
        self.quark_analysis.score_sum += score

    def add_table_row(self, name, rule_obj, confidence, score, weight):

        self.quark_analysis.summary_report_table.add_row(
            [
                name,
                green(rule_obj.crime),
                yellow(confidence),
                score,
                red(weight),
            ]
        )

    def show_summary_report(self, rule_obj, threshold=None):
        """
        Show the summary report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        # Count the confidence
        confidence = f"{rule_obj.check_item.count(True) * 20}%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.score
        name = rule_obj.rule_filename

        if threshold:

            if rule_obj.check_item.count(True) * 20 >= int(threshold):
                self.add_table_row(name, rule_obj, confidence, score, weight)

        else:
            self.add_table_row(name, rule_obj, confidence, score, weight)

        # add the weight
        self.quark_analysis.weight_sum += weight
        # add the score
        self.quark_analysis.score_sum += score

    def show_label_report(self, rule_path, all_labels, table_version):
        """
        Show the report based on label, last column represents max confidence for that label
        :param rule_path: the path where may be present the file label_desc.csv.
        :param all_labels: dictionary containing label:<array of confidence values associated to that label>
        :return: None
        """
        label_desc = {}
        # clear table to manage max/detail version
        self.quark_analysis.label_report_table.clear()
        if os.path.isfile(
            os.path.join(
                os.path.dirname(rule_path), "label_desc.csv"
            )
        ):
            # associate each label to a description

            # csv file on form <label,description>
            # put this file in the folder of rules (it must not be a json file since it could create conflict with management of rules)

            with open(
                os.path.join(
                    os.path.dirname(rule_path), "label_desc.csv"
                ), 'r'
            ) as labelFile:
                label_desc = {
                        row["label"]: row["description"]
                        for row in csv.DictReader(labelFile)
                }

        for label_name in all_labels:
            confidences = np.array(all_labels[label_name])

            if table_version == "max":
                self.quark_analysis.label_report_table.field_names = [
                    "Label",
                    "Description",
                    "Number of rules",
                    "MAX Confidence %",
                ]
                self.quark_analysis.label_report_table.add_row(
                    [
                        green(label_name),
                        yellow(label_desc.get(label_name, "-")),
                        (len(confidences)),
                        red(np.max(confidences)),
                    ]
                )
            else:
                self.quark_analysis.label_report_table.field_names = [
                    "Label",
                    "Description",
                    "Number of rules",
                    "MAX Confidence %",
                    "AVG Confidence",
                    "Std Deviation",
                    "# of Rules with Confidence >= 80%",
                ]
                self.quark_analysis.label_report_table.add_row(
                    [
                        green(label_name),
                        yellow(label_desc.get(label_name, "-")),
                        (len(confidences)),
                        red(np.max(confidences)),
                        magenta(round(np.mean(confidences), 2)),
                        lightblue(round(np.std(confidences), 2)),
                        lightyellow(np.count_nonzero(confidences >= 80)),
                    ]
                )

    def show_detail_report(self, rule_obj):
        """
        Show the detail report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """

        # Count the confidence
        print("")
        print(f"Confidence: {rule_obj.check_item.count(True) * 20}%")
        print("")

        if rule_obj.check_item[0]:

            colorful_report("1.Permission Request")
            for permission in rule_obj.permission:
                print(f"\t\t {permission}")
        if rule_obj.check_item[1]:
            colorful_report("2.Native API Usage")
            for api in self.quark_analysis.level_2_result:
                print(f"\t\t {api.full_name}")
        if rule_obj.check_item[2]:
            colorful_report("3.Native API Combination")
            for numbered_api, method_list in zip(
                ("First API", "Second API"), self.quark_analysis.level_3_result
            ):
                print(f"\t\t {numbered_api} show up in:")
                if method_list:
                    for comb_method in method_list:
                        print(f"\t\t {comb_method.full_name}")
                else:
                    print("\t\t None")

        if rule_obj.check_item[3]:

            colorful_report("4.Native API Sequence")
            print("\t\t Sequence show up in:")
            for seq_method in self.quark_analysis.level_4_result:
                print(f"\t\t {seq_method.full_name}")
        if rule_obj.check_item[4]:

            colorful_report("5.Native API Use Same Parameter")
            for seq_operation in self.quark_analysis.level_5_result:
                print(f"\t\t {seq_operation.full_name}")

    def show_call_graph(self, output_format=None):
        print_info("Creating Call Graph...")
        for (
            call_graph_analysis
        ) in self.quark_analysis.call_graph_analysis_list:
            call_graph(call_graph_analysis, output_format)
        print_success("Call Graph Completed")

    def show_rule_classification(self):
        print_info("Rules Classification")

        data_bundle = get_rule_classification_data(
            self.quark_analysis.call_graph_analysis_list, MAX_SEARCH_LAYER
        )

        output_parent_function_table(data_bundle)
        output_parent_function_json(data_bundle)
        output_parent_function_graph(data_bundle)

    @staticmethod
    def findMethodCallPairs(
        usageTable: Mapping[int, Sequence[RegisterObject]],
        firstMethodInfo: tuple[str, str, str],
        secondMethodInfo: tuple[str, str, str],
    ) -> Generator[tuple[MethodCall, MethodCall], None, None]:

        allRegisterValues = (
            registerValue
            for register in usageTable.values()
            for registerValue in register
        )

        secondMethodPattern = PyEval.get_method_pattern(*secondMethodInfo)

        secondAPICalls = (
            call
            for registerValue in allRegisterValues
            for call in registerValue.iterateInvolvedCalls()
            if call.method == secondMethodPattern
        )

        firstMethodPattern = PyEval.get_method_pattern(*firstMethodInfo)

        matchedCallPairs = (
            (firstCall, secondCall)
            for secondCall in secondAPICalls
            for firstCall in iteratePriorCalls(secondCall)
            if firstCall.method == firstMethodPattern
        )

        yield from matchedCallPairs


if __name__ == "__main__":
    pass
