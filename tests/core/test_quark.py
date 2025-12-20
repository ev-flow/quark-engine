import base64
import json
import os
from unittest.mock import patch

import pytest
import requests

from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject
from quark.core.struct.registerobject import RegisterObject
from quark.core.struct.valuenode import MethodCall, Primitive
from quark.evaluator.pyeval import PyEval

APK_SOURCE = (
    "https://github.com/quark-engine/apk-samples"
    "/raw/master/malware-samples/14d9f1a92dd984d6040cc41ed06e273e.apk"
)
APK_FILENAME = "14d9f1a92dd984d6040cc41ed06e273e.apk"


APK_SOURCE_2 = (
    "https://github.com/quark-engine/apk-samples"
    "/raw/master/malware-samples/Ahmyth.apk"
)
APK_FILENAME_2 = "Ahmyth.apk"


LABEL_DECS_SOURCE = (
    "https://raw.githubusercontent.com/quark-engine/"
    "quark-rules/master/label_desc.csv"
)

LABEL_DECS_FILENAME = "label_desc.csv"


@pytest.fixture(scope="function")
def simple_quark_obj() -> Quark:
    r = requests.get(APK_SOURCE, allow_redirects=True)
    open(APK_FILENAME, "wb").write(r.content)

    apk_file = APK_FILENAME
    return Quark(apk_file)


@pytest.fixture(scope="function")
def simple_quark_obj_2():
    r = requests.get(APK_SOURCE_2, allow_redirects=True, timeout=5)
    open(APK_FILENAME_2, "wb").write(r.content)

    apk_file = APK_FILENAME_2
    return Quark(apk_file)


@pytest.fixture(scope="function")
def quark_obj(simple_quark_obj):
    data = simple_quark_obj
    # rule
    rules = "quark/rules"
    rules_list = os.listdir(rules)
    for single_rule in rules_list:
        if single_rule.endswith("json"):
            rulepath = os.path.join(rules, single_rule)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)
            data.generate_json_report(rule_checker)

    yield data


@pytest.fixture(scope="function")
def rule_without_keyword(tmp_path):
    rule_file = tmp_path / "rule_without_keyword.json"

    data = base64.b64decode(
        """eyAiY3JpbWUiOiAiUmVhZCBzZW5zaXRpdmUgZGF0YShTTVMsIENBTExMT0csIGV0YykiLCAicGVy
bWlzc2lvbiI6IFtdLCAiYXBpIjogWyB7ICJkZXNjcmlwdG9yIjogIigpTGFuZHJvaWQvY29udGVu
dC9Db250ZW50UmVzb2x2ZXI7IiwgImNsYXNzIjogIkxhbmRyb2lkL2NvbnRlbnQvQ29udGV4dDsi
LCAibWV0aG9kIjogImdldENvbnRlbnRSZXNvbHZlciIgfSwgeyAiZGVzY3JpcHRvciI6ICIoTGFu
ZHJvaWQvbmV0L1VyaTsgW0xqYXZhL2xhbmcvU3RyaW5nOyBMamF2YS9sYW5nL1N0cmluZzsgW0xq
YXZhL2xhbmcvU3RyaW5nOyBMamF2YS9sYW5nL1N0cmluZzspTGFuZHJvaWQvZGF0YWJhc2UvQ3Vy
c29yOyIsICJjbGFzcyI6ICJMYW5kcm9pZC9jb250ZW50L0NvbnRlbnRSZXNvbHZlcjsiLCAibWV0
aG9kIjogInF1ZXJ5IiB9IF0sICJzY29yZSI6IDEsICJsYWJlbCI6IFsgImNvbGxlY3Rpb24iLCAi
c21zIiwgImNhbGxsb2ciLCAiY2FsZW5kYXIiIF0gfQ=="""
    ).decode()

    rule_file.write_text(data)
    return rule_file


@pytest.fixture(scope="function")
def rule_with_one_keyword(tmp_path):
    rule_file = tmp_path / "rule_with_one_keyword.json"

    data = requests.get(
            "https://raw.githubusercontent.com/quark-engine/quark-rules/"
            "master/rules/00192.json",
            timeout=5
            )

    rule_file.write_text(data.text)
    return rule_file


@pytest.fixture(scope="function")
def label_desc_csv(tmp_path):
    r = requests.get(LABEL_DECS_SOURCE, allow_redirects=True, timeout=5)
    open(
        os.path.join(
            os.path.dirname(tmp_path), LABEL_DECS_FILENAME
        ),
        "wb"
        ).write(r.content)


class TestQuark:
    @pytest.mark.skip(reason="discussion needed.")
    def test_find_previous_method_with_invalid_types(self, quark_obj):
        with pytest.raises(TypeError):
            quark_obj.find_previous_method(None, None, None)

    def test_find_previous_method_without_result(self, quark_obj):
        parent_function = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList",
            "()Ljava/lang/String;",
        )[0]
        base_method = quark_obj.apkinfo.find_method(
            "Landroid/telephony/TelephonyManager",
            "getCellLocation",
            "()Landroid/telephony/CellLocation;",
        )[0]
        wrapper = []

        quark_obj.find_previous_method(base_method, parent_function, wrapper)

        assert wrapper == list()

    def test_find_previous_method_with_result(self, quark_obj):
        parent_function = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )[0]

        wrapper = []

        base_method = quark_obj.apkinfo.find_method(
            "Landroid/telephony/TelephonyManager",
            "getCellLocation",
            "()Landroid/telephony/CellLocation;",
        )[0]

        expect_method_analysis = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;"
        )[0]

        expected_list = [expect_method_analysis]

        quark_obj.find_previous_method(base_method, parent_function, wrapper=wrapper)

        assert wrapper == expected_list

    def test_find_intersection_with_invalid_type(self, quark_obj):
        with pytest.raises(ValueError):
            quark_obj.find_intersection(None, None)

    def test_find_intersection_with_empty_set(self, quark_obj):
        first_method_set = set()
        second_method_set = set()

        with pytest.raises(ValueError):
            quark_obj.find_intersection(first_method_set, second_method_set)

    @pytest.mark.skip(reason="discussion needed.")
    def test_find_intersection_with_set_containing_invalid_type(self, quark_obj):
        first_method_set = {1, 2, 3}
        second_method_set = {4, 5, 6}

        with pytest.raises(TypeError):
            quark_obj.find_intersection(first_method_set, second_method_set)

    def test_find_intersection_with_result(self, quark_obj):
        location_api = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;"
        )[0]
        location_api_upper = quark_obj.apkinfo.upperfunc(location_api)

        sms_api = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/SMSHelper;",
            "sendSms",
            "(Ljava/lang/String; Ljava/lang/String;)I",
        )[0]
        sms_api_upper = quark_obj.apkinfo.upperfunc(sms_api)

        with pytest.raises(ValueError, match="Set is Null"):
            quark_obj.find_intersection(set(), set())
            quark_obj.find_intersection(set(), {1})
            quark_obj.find_intersection({1}, set())

        assert len(location_api_upper & sms_api_upper) == 3

        # When there is no intersection in first layer, it will try to enter
        # the second layer to check the intersection.

        # Send Location via SMS
        expected_result_location = {
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService;", "doByte", "([B)V"
            )[0],
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
            )[0],
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService$2;", "run", "()V"
            )[0],
        }

        assert (
            quark_obj.find_intersection(location_api_upper, sms_api_upper)
            == expected_result_location
        )

    @pytest.mark.skip(reason="discussion needed.")
    def test_check_sequence_with_invalid_type(self, quark_obj):
        mutual_parent = None
        first_method_list = None
        second_method_list = None

        with pytest.raises(TypeError):
            quark_obj.check_sequence(
                mutual_parent, first_method_list, second_method_list
            )

    @pytest.mark.skip(reason="discussion needed.")
    def test_check_sequence_with_lists_containing_invalid_type(self, quark_obj):
        mutual_parent = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )[0]
        first_method_list = [1, 2, 3]
        second_method_list = [4, 5, 6]

        with pytest.raises(TypeError):
            quark_obj.check_sequence(
                mutual_parent, first_method_list, second_method_list
            )

    def test_check_sequence_is_true(self, quark_obj):
        # Send Location via SMS

        location_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;"
        )[0]
        sendSms_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/SMSHelper;",
            "sendSms",
            "(Ljava/lang/String; Ljava/lang/String;)I",
        )[0]

        mutual_parent_true = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )[0]

        result = quark_obj.check_sequence(
            mutual_parent_true,
            [location_method],
            [sendSms_method],
        )

        assert result is True

    def test_check_sequence_with_contact_method(self, quark_obj):
        sendSms_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/SMSHelper;",
            "sendSms",
            "(Ljava/lang/String; Ljava/lang/String;)I",
        )[0]

        mutual_parent_true = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )[0]

        contact_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList",
            "()Ljava/lang/String;",
        )[0]

        result = quark_obj.check_sequence(
            mutual_parent_true,
            [contact_method],
            [sendSms_method],
        )

        assert result is True

    def test_check_sequence_is_false(self, quark_obj):
        # Send Location via SMS
        sendSms_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService$2;", "run", "()V"
        )[0]

        mutual_parent_false = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService$2;", "run", "()V"
        )[0]

        # # Send contact via SMS

        contact_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList",
            "()Ljava/lang/String;",
        )[0]

        result = quark_obj.check_sequence(
            mutual_parent_false,
            [contact_method],
            [sendSms_method],
        )

        assert result is False

    def test_check_parameter_with_invalid_type(self, quark_obj):
        mutual_parent = None
        first_method_list = None
        second_method_list = None

        with pytest.raises(TypeError):
            quark_obj.check_parameter(
                mutual_parent, first_method_list, second_method_list
            )

    @pytest.mark.skip(reason="discussion needed.")
    def test_check_parameter_with_lists_containing_invalid_type(self, quark_obj):
        mutual_parent = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )[0]
        first_method_list = [1, 2, 3]
        second_method_list = [4, 5, 6]

        with pytest.raises(TypeError):
            quark_obj.check_sequence(
                mutual_parent, first_method_list, second_method_list
            )

    def test_check_parameter_is_True(self, quark_obj):
        second_method = [
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/SMSHelper;",
                "sendSms",
                "(Ljava/lang/String; Ljava/lang/String;)I",
            )[0]
        ]
        first_method = [
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;"
            )[0]
        ]
        mutual_parent = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )[0]

        assert (
            quark_obj.check_parameter(mutual_parent, first_method, second_method)
            == True
        )

    def test_check_parameter_is_False(self, quark_obj):
        first_method_list = [
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService$2;", "run", "()V"
            )[0]
        ]

        second_method_list = [
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/ContactsCollecter;",
                "getContactList",
                "()Ljava/lang/String;",
            )[0]
        ]
        mutual_parent = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )[0]

        result = quark_obj.check_parameter(
            mutual_parent, first_method_list, second_method_list
        )

        assert result is False

    def test_getMatchedKeywords_with_no_keyword_rule(
        self, simple_quark_obj, rule_without_keyword
    ):
        rule_object = RuleObject(rule_without_keyword)

        with patch("quark.core.quark.Quark.getMatchedKeywords") as mock:
            simple_quark_obj.run(rule_object)
            mock.assert_not_called()

    def test_getMatchedKeywords_with_one_keyword_rule(
        self, simple_quark_obj_2, rule_with_one_keyword
    ):
        rule_object = RuleObject(rule_with_one_keyword)

        with patch("quark.core.quark.Quark.getMatchedKeywords") as mock:
            simple_quark_obj_2.run(rule_object)
            mock.assert_called()

    def test_getMatchedKeywords_without_matched_str(self, simple_quark_obj: Quark):
        method_call = MethodCall(
            "Landroid/content/ContentResolver;->query"
            "(Landroid/net/Uri;)Landroid/database/Cursor;",
            (
                MethodCall(
                    "Landroid/net/Uri;->parse(Ljava/lang/String;)",
                    (Primitive("URL_FOR_TEST", "Ljava/lang/String;"),)
                ),
                Primitive(1, "I")
            )
        )

        result = simple_quark_obj.getMatchedKeywords(
            method_call, ("KW_NOT_MATCHING",), False
        )

        assert result == []

    def test_getMatchedKeywords_with_matched_str(self, simple_quark_obj):
        method_call = MethodCall(
            "Landroid/content/ContentResolver;->query"
            "(Landroid/net/Uri;)Landroid/database/Cursor;",
            (
                MethodCall(
                    "Landroid/net/Uri;->parse(Ljava/lang/String;)",
                    (Primitive("content://call_log/calls", "Ljava/lang/String;"),)
                ),
                Primitive(1, "I")
            )
        )

        result = simple_quark_obj.getMatchedKeywords(
            method_call, ("content://call_log/calls",), False
        )

        assert result == ["content://call_log/calls"]

    def test_get_json_report(self, quark_obj):
        json_report = quark_obj.get_json_report()
        # Check if proper dict object
        assert isinstance(json_report, dict)
        assert json_report.get("md5") == "14d9f1a92dd984d6040cc41ed06e273e"

    def test_json_report_format(self, quark_obj):
        # Inner function for comparing two json objects
        def sorting(item):
            if isinstance(item, dict):
                return sorted((key, sorting(values)) for key, values in item.items())
            if isinstance(item, list):
                return sorted(sorting(x) for x in item)
            else:
                return item

        json_report = quark_obj.get_json_report()

        with open("tests/core/json_report_sample.json") as json_file:
            sample_json = json.loads(json_file.read())

            assert sorting(sample_json) == sorting(json_report)

    def testLabelReportWithMaxTable(
        self,
        quark_obj,
        tmp_path,
        label_desc_csv
    ):
        scoreForLabelSms = {
            "sms":
            [
                40, 20, 20, 40, 100, 100, 40, 80, 80, 60, 40,
                20, 80, 80, 100, 40, 20, 40, 100, 20, 40, 100,
                40, 20, 40, 100, 40, 40, 40, 40, 20, 20, 100
            ]
        }

        quark_obj.show_label_report(
             tmp_path,
             scoreForLabelSms,
             "max"
        )

        correctTableRow = [
            '\x1b[92msms\x1b[0m',
            '\x1b[33mRead/Write/Send sms content\x1b[0m',
            33,
            '\x1b[91m100\x1b[0m'
        ]

        assert (quark_obj.quark_analysis
                .label_report_table.rows[0]) == correctTableRow

    def testLabelReportWithDetailedTable(
        self,
        quark_obj,
        tmp_path,
        label_desc_csv
    ):
        scoreForLabelSms = {
            "sms":
            [
                40, 20, 20, 40, 100, 100, 40, 80, 80, 60, 40,
                20, 80, 80, 100, 40, 20, 40, 100, 20, 40, 100,
                40, 20, 40, 100, 40, 40, 40, 40, 20, 20, 100
            ]
        }

        quark_obj.show_label_report(
             tmp_path,
             scoreForLabelSms,
             "detailed"
        )

        correctTableRow = [
            '\x1b[92msms\x1b[0m',
            '\x1b[33mRead/Write/Send sms content\x1b[0m',
            33,
            '\x1b[91m100\x1b[0m',
            '\x1b[35m53.33\x1b[0m',
            '\x1b[94m29.81\x1b[0m',
            '\x1b[93m11\x1b[0m'
        ]

        assert (quark_obj.quark_analysis
                .label_report_table.rows[0]) == correctTableRow

    @staticmethod
    def _registerWithCall(call: MethodCall) -> RegisterObject:
        register = RegisterObject(value=Primitive("0", "I"))
        register.called_by_func = call
        return register

    def testReturnsSinglePairWhenFirstCallFeedsSecond(self):
        firstMethodInfo = ("Lfoo;", "first", "()V")
        secondMethodInfo = ("Lfoo;", "second", "()V")

        firstCall = MethodCall(
            method=PyEval.get_method_pattern(*firstMethodInfo),
            argumentNodes=(Primitive("input", "Ljava/lang/String;"),),
        )

        secondCall = MethodCall(
            method=PyEval.get_method_pattern(*secondMethodInfo),
            argumentNodes=(firstCall,),
        )

        usageTable = {0: [self._registerWithCall(secondCall)]}

        result = list(
            Quark.findMethodCallPairs(
                usageTable, firstMethodInfo, secondMethodInfo
            )
        )

        assert result == [(firstCall, secondCall)]

    def testReturnsMultiplePairsWhenSecondUsesMultipleFirstCalls(self):
        firstMethodInfo = ("Lfoo;", "first", "()V")
        secondMethodInfo = ("Lfoo;", "second", "()V")

        firstCallOne = MethodCall(
            method=PyEval.get_method_pattern(*firstMethodInfo),
            argumentNodes=(Primitive("alpha", "Ljava/lang/String;"),),
        )
        firstCallTwo = MethodCall(
            method=PyEval.get_method_pattern(*firstMethodInfo),
            argumentNodes=(Primitive("beta", "Ljava/lang/String;"),),
        )

        secondCall = MethodCall(
            method=PyEval.get_method_pattern(*secondMethodInfo),
            argumentNodes=(firstCallOne, firstCallTwo),
        )

        usageTable = {0: [self._registerWithCall(secondCall)]}

        result = list(
            Quark.findMethodCallPairs(
                usageTable, firstMethodInfo, secondMethodInfo
            )
        )

        assert result == [
            (firstCallOne, secondCall),
            (firstCallTwo, secondCall),
        ]

    def testReturnsEmptyWhenSecondCallLacksMatchingPriorCall(self):
        firstMethodInfo = ("Lfoo;", "first", "()V")
        secondMethodInfo = ("Lfoo;", "second", "()V")

        second_call = MethodCall(
            method=PyEval.get_method_pattern(*secondMethodInfo),
            argumentNodes=(Primitive("gamma", "Ljava/lang/String;"),),
        )

        usageTable = {0: [self._registerWithCall(second_call)]}

        result = list(
            Quark.findMethodCallPairs(
                usageTable, firstMethodInfo, secondMethodInfo
            )
        )

        assert result == []
