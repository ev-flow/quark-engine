import os

import pytest

from quark.core.struct.ruleobject import RuleObject


def build_rule_json(first_keywords=None, second_keywords=None):
    api_entries = [
        {
            "class": "Landroid/telephony/TelephonyManager",
            "method": "getDeviceId",
            "descriptor": "()Ljava/lang/String;",
        },
        {
            "class": "Landroid/telephony/SmsManager",
            "method": "sendTextMessage",
            "descriptor": "()V",
        },
    ]

    if first_keywords is not None:
        api_entries[0]["match_keywords"] = first_keywords

    if second_keywords is not None:
        api_entries[1]["match_keywords"] = second_keywords

    return {
        "crime": "Send Location via SMS",
        "permission": [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
        "api": api_entries,
        "score": 4,
        "label": ["location", "collection"],
    }


@pytest.fixture()
def rule_obj(scope="function"):
    rule_json = """
    {
        "crime": "Send Location via SMS",
        "permission": [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION"
        ],
        "api": [
            {
                "class": "Landroid/telephony/TelephonyManager",
                "method": "getCellLocation",
                "descriptor": "(I Ljava/lang/String; [B J)V"
            },
            {
                "class": "Landroid/telephony/SmsManager",
                "method": "sendTextMessage",
                "descriptor": "(ILjava/lang/String;[BJ)V"
            }
        ],
        "score": 4,
        "label": [
        "location",
        "collection"
    ]
    }
    """

    with open("sendLocation.json", "w") as f:
        f.write(rule_json)

    print("setup() begin")

    rule_obj = RuleObject("sendLocation.json")

    yield rule_obj

    del rule_obj
    os.remove("sendLocation.json")


@pytest.fixture(scope="function")
def invalid_file(tmp_path):
    invalid_file = tmp_path / "invalid_file.txt"
    invalid_file.write_text("Not a json")

    yield invalid_file


@pytest.fixture(scope="function")
def incomplete_rule(tmp_path):
    incomplete_rule = tmp_path / "incomplete_rule.txt"
    incomplete_rule.write_text("{}")

    yield incomplete_rule


@pytest.fixture(scope="function")
def complete_rule():
    return "quark/rules/sendLocation_SMS.json"


class TestRuleObject:
    def test_init_with_invalid_path(self):
        with pytest.raises(TypeError):
            _ = RuleObject(["Not", "a", "file"])

    def test_init_with_non_exist_file(self):
        with pytest.raises(FileNotFoundError):
            _ = RuleObject("NON_EXIST_FILE")

    def test_init_with_invalid_file(self, invalid_file):
        with pytest.raises(BaseException):
            _ = RuleObject(invalid_file)

    def test_init_with_incomplete_rule(self, incomplete_rule):
        with pytest.raises(KeyError):
            _ = RuleObject(incomplete_rule)

    def test_init_with_complete_rule(self, complete_rule):
        rule = RuleObject(complete_rule)

        assert all(rule.check_item) is False
        assert rule.crime == "Send Location via SMS"
        assert rule.permission == [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
        ]
        assert rule.api == [
            {
                "class": "Landroid/telephony/TelephonyManager",
                "method": "getCellLocation",
                "descriptor": "()Landroid/telephony/CellLocation;",
            },
            {
                "class": "Landroid/telephony/SmsManager",
                "method": "sendTextMessage",
                "descriptor": (
                    "(Ljava/lang/String; Ljava/lang/String;"
                    " Ljava/lang/String; Landroid/app/PendingIntent;"
                    " Landroid/app/PendingIntent;)V"
                ),
            },
        ]
        assert rule.score == 4
        assert rule.rule_filename == "sendLocation_SMS.json"
        assert rule.label == ["location", "collection"]

    def test_get_score(self, rule_obj):
        confidence = [1, 2, 3, 4, 5]
        expected_value = [0.25, 0.5, 1.0, 2.0, 4.0]
        for idx, value in enumerate(expected_value):
            assert rule_obj.get_score(confidence[idx]) == value

    @staticmethod
    def test_androguard_format_api(rule_obj):
        assert rule_obj.api[0]["descriptor"] == "(I Ljava/lang/String; [B J)V"

    @staticmethod
    def test_java_format_api(rule_obj):
        assert rule_obj.api[1]["descriptor"] == "(I Ljava/lang/String; [B J)V"

    @staticmethod
    def test_first_api_keywords_returns_list():
        rule = RuleObject(
            "dummy.json",
            jsonData=build_rule_json(first_keywords=["imei", "iccid"]),
        )

        assert rule.firstApiKeywords == ["imei", "iccid"]

    @staticmethod
    def test_first_api_keywords_returns_none_when_missing():
        rule = RuleObject(
            "dummy.json", jsonData=build_rule_json(first_keywords=[])
        )

        assert rule.firstApiKeywords is None

    @staticmethod
    def test_second_api_keywords_returns_list():
        rule = RuleObject(
            "dummy.json",
            jsonData=build_rule_json(second_keywords=["sms", "send"]),
        )

        assert rule.secondApiKeywords == ["sms", "send"]

    @staticmethod
    def test_second_api_keywords_returns_none_when_not_a_list():
        rule = RuleObject(
            "dummy.json", jsonData=build_rule_json(second_keywords="sms")
        )

        assert rule.secondApiKeywords is None
