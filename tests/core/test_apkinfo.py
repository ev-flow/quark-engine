import os
from typing import Literal, Tuple
import zipfile

import pytest

from quark.core.apkinfo import AndroguardImp
from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.rzapkinfo import RizinImp
from quark.core.r2apkinfo import R2Imp
from quark.core.shurikenapkinfo import ShurikenImp
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject

try:
    import shuriken  # noqa: F401

    _HAS_SHURIKEN = True
except ModuleNotFoundError:
    _HAS_SHURIKEN = False


@pytest.fixture(scope="session")
def dex_file(SAMPLE_PATH_13667):
    APK_NAME = SAMPLE_PATH_13667
    DEX_NAME = "classes.dex"

    with zipfile.ZipFile(APK_NAME, "r") as zip:
        zip.extract(DEX_NAME)

    yield DEX_NAME

    if os.path.exists(DEX_NAME):
        os.remove(DEX_NAME)

    if os.path.exists(APK_NAME):
        os.remove(APK_NAME)


@pytest.fixture(scope="session")
def dex_file_pivaa(tmp_path_factory, SAMPLE_PATH_pivaa):
    APK_NAME = SAMPLE_PATH_pivaa
    DEX_NAME = "classes.dex"
    DEX_DIR = tmp_path_factory.mktemp("dex_pivaa")
    DEX_PATH = str(os.path.join(DEX_DIR, "classes.dex"))

    with zipfile.ZipFile(APK_NAME, "r") as zip:
        zip.extract(DEX_NAME, path=DEX_DIR)

    yield DEX_PATH

    if os.path.exists(DEX_PATH):
        os.remove(DEX_PATH)

    if os.path.exists(DEX_PATH):
        os.remove(DEX_PATH)


def __generateTestIDs(testInput: Tuple[BaseApkinfo, Literal["DEX", "APK"]]):
    return f"{testInput[0].__name__} with {testInput[1]}"


@pytest.fixture(
    scope="function",
    params=(
        (AndroguardImp, "DEX"),
        (AndroguardImp, "APK"),
        (RizinImp, "DEX"),
        (RizinImp, "APK"),
        (R2Imp, "DEX"),
        (R2Imp, "APK"),
        (ShurikenImp, "DEX"),
        (ShurikenImp, "APK"),
    ),
    ids=__generateTestIDs,
)
def apkinfo(request, SAMPLE_PATH_13667, dex_file):
    apkinfoClass, fileType = request.param

    if apkinfoClass is ShurikenImp and not _HAS_SHURIKEN:
        pytest.skip("Shuriken-Analyzer is not installed")

    fileToBeAnalyzed = SAMPLE_PATH_13667
    if fileType == "DEX":
        fileToBeAnalyzed = dex_file

    apkinfo = apkinfoClass(fileToBeAnalyzed)

    yield apkinfo


@pytest.fixture(
    scope="function",
    params=(
        (R2Imp, "DEX"),
        (R2Imp, "APK"),
    ),
)
def apkinfo_with_R2Imp_only(request, SAMPLE_PATH_13667, dex_file):
    """For testcases involved with R2 core lib."""
    apkinfoClass, fileType = request.param

    fileToBeAnalyzed = SAMPLE_PATH_13667
    if fileType == "DEX":
        fileToBeAnalyzed = dex_file

    apkinfo = apkinfoClass(fileToBeAnalyzed)

    yield apkinfo


@pytest.fixture(
    scope="function",
    params=(
        (AndroguardImp, "DEX"),
        (AndroguardImp, "APK"),
        (RizinImp, "DEX"),
        (RizinImp, "APK"),
        (R2Imp, "DEX"),
        (R2Imp, "APK"),
        (ShurikenImp, "DEX"),
        (ShurikenImp, "APK"),
    ),
    ids=__generateTestIDs,
)
def apkinfoPivaa(request, SAMPLE_PATH_pivaa, dex_file_pivaa):
    apkinfoClass, fileType = request.param

    if apkinfoClass is ShurikenImp and not _HAS_SHURIKEN:
        pytest.skip("Shuriken-Analyzer is not installed")

    fileToBeAnalyzed = SAMPLE_PATH_pivaa
    if fileType == "DEX":
        fileToBeAnalyzed = dex_file_pivaa

    apkinfo = apkinfoClass(fileToBeAnalyzed)

    yield apkinfo


class TestApkinfo:
    def test_init_with_invalid_type(self):
        filepath = None

        with pytest.raises(TypeError):
            _ = BaseApkinfo(filepath)

    def test_init_with_non_exist_file(self):
        filepath = "PATH_TO_NON_EXIST_FILE"

        with pytest.raises(FileNotFoundError):
            _ = BaseApkinfo(filepath)

    def test_init_with_apk(self, SAMPLE_PATH_13667):
        apkinfo = BaseApkinfo(SAMPLE_PATH_13667)

        assert apkinfo.ret_type == "APK"

    def test_init_with_dex(self, dex_file):
        apkinfo = BaseApkinfo(dex_file)

        assert apkinfo.ret_type == "DEX"

    def test_filename(self, apkinfo):
        match apkinfo.ret_type:
            case "DEX":
                assert apkinfo.filename == "classes.dex"
            case "APK":
                assert (
                    apkinfo.filename
                    == "13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
                )

    def test_filesize(self, apkinfo):
        match apkinfo.ret_type:
            case "DEX":
                assert apkinfo.filesize == 717940
            case "APK":
                assert apkinfo.filesize == 266155

    def test_md5(self, apkinfo):
        match apkinfo.ret_type:
            case "DEX":
                assert apkinfo.md5 == "65c616c49c7eeb065ac5c06e15192398"
            case "APK":
                assert apkinfo.md5 == "1e80ac341a665e8984f07bec7f351e18"

    def test_permissions(self, apkinfo):
        match apkinfo.ret_type:
            case "DEX":
                assert apkinfo.permissions == []
            case "APK":
                ans = [
                    "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                    "android.permission.WRITE_SMS",
                    "android.permission.READ_SMS",
                    "android.permission.INTERNET",
                    "android.permission.READ_PHONE_STATE",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.READ_CONTACTS",
                ]
                assert set(apkinfo.permissions) == set(ans)

    @staticmethod
    def test_application(apkinfo):
        match apkinfo.ret_type:
            case "DEX":
                assert apkinfo.application is None
            case "APK":
                application = apkinfo.application
                label = str(
                    application.get(
                        "{http://schemas.android.com/apk/res/android}label"
                    )
                )
                assert label == "@7F050001" or label == "2131034113"

    @staticmethod
    def test_activities(apkinfo):
        match apkinfo.ret_type:
            case "DEX":
                assert apkinfo.activities is None
            case "APK":
                activities = apkinfo.activities

                assert len(activities) == 1
                assert (
                    activities[0].get(
                        "{http://schemas.android.com/apk/res/android}name"
                    )
                    == "com.example.google.service.MainActivity"
                )

    @staticmethod
    def test_receivers(apkinfo):
        match apkinfo.ret_type:
            case "DEX":
                assert apkinfo.receivers is None
            case "APK":
                receivers = apkinfo.receivers

                assert len(receivers) == 4
                assert (
                    receivers[0].get(
                        "{http://schemas.android.com/apk/res/android}name"
                    )
                    == "com.example.google.service.SMSServiceBootReceiver"
                )
                assert (
                    receivers[1].get(
                        "{http://schemas.android.com/apk/res/android}name"
                    )
                    == "com.example.google.service.SMSReceiver"
                )
                assert (
                    receivers[2].get(
                        "{http://schemas.android.com/apk/res/android}name"
                    )
                    == "TaskRequest"
                )
                assert (
                    receivers[3].get(
                        "{http://schemas.android.com/apk/res/android}name"
                    )
                    == "com.example.google.service.MyDeviceAdminReceiver"
                )

    @staticmethod
    def test_providers(apkinfoPivaa):
        match apkinfoPivaa.ret_type:
            case "DEX":
                assert apkinfoPivaa.providers is None
            case "APK":
                providers= apkinfoPivaa.providers

                assert len(providers) == 1
                assert (
                    providers[0].get(
                        "{http://schemas.android.com/apk/res/android}name"
                    )
                    == "com.htbridge.pivaa.handlers.VulnerableContentProvider"
                )

    def test_android_apis(self, apkinfo):
        api = {
            MethodObject(
                "Landroid/telephony/SmsMessage;",
                "getDisplayOriginatingAddress",
                "()Ljava/lang/String;",
            ),
            MethodObject(
                "Ljava/io/File;",
                "mkdir",
                "()Z",
            ),
        }

        if apkinfo.core_library == "androguard":
            assert len(apkinfo.android_apis) == 1270
        elif apkinfo.core_library == "rizin":
            assert len(apkinfo.android_apis) > 0
        elif apkinfo.core_library == "shuriken":
            assert len(apkinfo.android_apis) == 1438
            return

        assert api.issubset(apkinfo.android_apis)

    def test_custom_methods(self, apkinfo):
        test_custom_method = {
            MethodObject(
                "Lcom/example/google/service/ContactsHelper;",
                "getPhoneContacts",
                "()V",
            ),
            MethodObject(
                "Lcom/example/google/service/ContactsHelper;",
                "getSIMContacts",
                "()V",
            ),
        }
        if apkinfo.core_library == "androguard":
            assert len(apkinfo.custom_methods) == 3999
        elif apkinfo.core_library == "rizin":
            assert len(apkinfo.custom_methods) > 0
        elif apkinfo.core_library == "shuriken":
            assert len(apkinfo.custom_methods) == 3999

        assert test_custom_method.issubset(apkinfo.custom_methods)

    def test_all_methods(self, apkinfo):
        test_custom_method = {
            MethodObject(
                "Lcom/example/google/service/ContactsHelper;",
                "getPhoneContacts",
                "()V",
            ),
            MethodObject(
                "Lcom/example/google/service/ContactsHelper;",
                "getSIMContacts",
                "()V",
            ),
        }

        if apkinfo.core_library == "androguard":
            assert len(apkinfo.all_methods) == 5452
        elif apkinfo.core_library == "rizin":
            assert len(apkinfo.all_methods) > 0
        elif apkinfo.core_library == "shuriken":
            assert len(apkinfo.all_methods) == 5451

        assert test_custom_method.issubset(apkinfo.all_methods)

    @staticmethod
    @pytest.mark.parametrize(
        "test_input, expected",
        [
            (
                [
                    "Ljava/lang/reflect/Field;",
                    "setAccessible",
                    "(Z)V",
                ],
                [
                    "Ljava/lang/reflect/Field;",
                    "setAccessible",
                    "(Z)V",
                ],
            ),
            (
                [
                    "",
                    "onReceive",
                    "(Landroid/content/Context; Landroid/content/Intent;)V",
                ],
                [
                    "Landroid/support/v4/media/TransportMediatorJellybeanMR2$3;",
                    "onReceive",
                    "(Landroid/content/Context; Landroid/content/Intent;)V",
                ],
            ),
            (
                [
                    "Landroid/support/v4/media/TransportMediatorJellybeanMR2$3;",
                    "",
                    "(Landroid/content/Context; Landroid/content/Intent;)V",
                ],
                [
                    "Landroid/support/v4/media/TransportMediatorJellybeanMR2$3;",
                    "onReceive",
                    "(Landroid/content/Context; Landroid/content/Intent;)V",
                ],
            ),
            (
                [
                    "Landroid/support/v4/media/TransportMediatorJellybeanMR2$3;",
                    "onReceive",
                    "",
                ],
                [
                    "Landroid/support/v4/media/TransportMediatorJellybeanMR2$3;",
                    "onReceive",
                    "(Landroid/content/Context; Landroid/content/Intent;)V",
                ],
            ),
            (
                [
                    None,
                    None,
                    None,
                ],
                [
                    "Landroid/support/v4/media/TransportMediatorJellybeanMR2$3;",
                    "onReceive",
                    "(Landroid/content/Context; Landroid/content/Intent;)V",
                ],
            ),
        ],
    )
    def test_find_method(apkinfo, test_input, expected):
        result = apkinfo.find_method(
            test_input[0], test_input[1], test_input[2]
        )
        expect_method = MethodObject(
            expected[0],
            expected[1],
            expected[2],
        )

        assert isinstance(result, list)
        assert expect_method in result

    def test_upperfunc(self, apkinfo):
        if apkinfo.core_library == "radare2":
            pytest.skip(
                reason="The upstream missed the xrefs of the function."
            )

        api = apkinfo.find_method(
            "Lcom/example/google/service/ContactsHelper;",
            "<init>",
            "(Landroid/content/Context;)V",
        )[0]

        expect_function = apkinfo.find_method(
            "Lcom/example/google/service/SMSReceiver;",
            "isContact",
            "(Ljava/lang/String;)Ljava/lang/Boolean;",
        )[0]

        upper_methods = list(apkinfo.upperfunc(api))

        assert expect_function in upper_methods

    def test_get_method_bytecode(self, apkinfo):
        if apkinfo.core_library == "radare2":
            pytest.skip(
                reason=(
                    "Upstream missed the bytecodes "
                    "in the latter part of the function.")
            )

        expected_bytecode_list = [
            BytecodeObject(
                "iput-object",
                ["v5", "v8"],
                (
                    "Landroid/support/v4/app/FragmentManagerImpl;"
                    "->mTmpActions [Ljava/lang/Runnable;"
                ),
            ),
            BytecodeObject(
                "invoke-direct",
                ["v5", "v6"],
                (
                    "Ljava/lang/IllegalStateException;"
                    "-><init>(Ljava/lang/String;)V"
                ),
            ),
            BytecodeObject("array-length", ["v5", "v5"], None),
            BytecodeObject(
                "invoke-static",
                [],
                "Landroid/os/Looper;->myLooper()Landroid/os/Looper;",
            ),
            BytecodeObject("return", ["v0"], None),
            BytecodeObject("const/4", ["v3"], 0),
            BytecodeObject("add-int/lit8", ["v2", "v2"], 1),
        ]

        method = apkinfo.find_method(
            class_name="Landroid/support/v4/app/FragmentManagerImpl;",
            method_name="execPendingActions",
            descriptor="()Z",
        )[0]

        bytecodes = list(apkinfo.get_method_bytecode(method))

        for expected in expected_bytecode_list:
            assert expected in bytecodes

    def test_another_get_method_bytecode(self, apkinfo):
        if apkinfo.core_library == "radare2":
            pytest.skip(
                reason=(
                    "Upstream missed the bytecodes "
                    "in the latter part of the function."
                )
            )

        # 13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk with 00193.json rule
        expected_bytecode_list1 = [
            BytecodeObject(
                "invoke-virtual/range",
                ["v2", "v3", "v4", "v5", "v6", "v7"],
                (
                    "Landroid/telephony/SmsManager;"
                    "->sendTextMessage(Ljava/lang/String; "
                    "Ljava/lang/String; Ljava/lang/String; "
                    "Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V"
                ),
            ),
            BytecodeObject("const-string", ["v4"], "SMS"),
            BytecodeObject(
                "invoke-virtual",
                ["v8"],
                "Ljava/lang/String;->length()I",
            ),
        ]
        expected_bytecode_list1 = [expected_bytecode_list1[1]]
        # 13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk with 00189.json rule
        expected_bytecode_list2 = [
            BytecodeObject(
                "invoke-virtual/range",
                ["v0", "v1", "v2", "v3", "v4", "v5"],
                (
                    "Landroid/content/ContentResolver;"
                    "->query(Landroid/net/Uri; "
                    "[Ljava/lang/String; "
                    "Ljava/lang/String; "
                    "[Ljava/lang/String; Ljava/lang/String;)"
                    "Landroid/database/Cursor;"
                ),
            ),
        ]

        method1 = apkinfo.find_method(
            class_name="Lcom/example/google/service/SMSSender;",
            method_name="SendSMS",
            descriptor="(Landroid/os/Message;)V",
        )[0]

        bytecodes1 = list(apkinfo.get_method_bytecode(method1))

        for expected in expected_bytecode_list1:
            assert expected in bytecodes1

        method2 = apkinfo.find_method(
            class_name="Lcom/example/google/service/ContactsHelper;",
            method_name="getPhoneContactNumbers",
            descriptor="()V",
        )[0]

        bytecodes2 = list(apkinfo.get_method_bytecode(method2))

        for expected in expected_bytecode_list2:
            assert expected in bytecodes2

    def test_get_method_bytecode_with_instructions_including_method_field(
            self, apkinfo):

        method = apkinfo.find_method(
            "Landroid/support/v4/widget/ContentLoadingProgressBar$1;",
            "run",
            "()V"
        )[0]

        expected_bytecode = BytecodeObject(
            "iget-object",
            ["v0", "v3"],
            (
                "Landroid/support/v4/widget/ContentLoadingProgressBar$1;->"
                "this$0 Landroid/support/v4/widget/ContentLoadingProgressBar;"
            ),
        )

        bytecodes = list(apkinfo.get_method_bytecode(method))

        assert expected_bytecode in bytecodes

    @staticmethod
    @pytest.mark.parametrize(
        "method_info, expected_bytecode_info",
        [
            (
                ("Landroid/support/v4/widget/ContentLoadingProgressBar$1;",
                    "run",
                    "()V"),
                (
                    "invoke-static",
                    ["v0", "v1"],
                    (
                        "Landroid/support/v4/widget/ContentLoadingProgressBar;"
                        "->access$002(Landroid/support/v4/widget"
                        "/ContentLoadingProgressBar; Z)Z"
                    )),
            ),
            (
                ("Landroid/support/v4/app/Fragment$InstantiationException;",
                    "<init>",
                    "(Ljava/lang/String; Ljava/lang/Exception;)V"),
                (
                    "invoke-direct",
                    ["v0", "v1", "v2"],
                    (
                        "Ljava/lang/RuntimeException;-><init>"
                        "(Ljava/lang/String; Ljava/lang/Throwable;)V"
                    )),
            )
        ],
    )
    def test_get_method_bytecode_with_instructions_including_method_call(
            method_info, expected_bytecode_info, apkinfo):
        if apkinfo.core_library == "radare2":
            pytest.skip(
                reason=(
                    "The core library skipped"
                    " didn't parse the bytecode correctly."
                )
            )

        method = apkinfo.find_method(*method_info)[0]

        expected_bytecode = BytecodeObject(
            *expected_bytecode_info
        )

        bytecodes = list(apkinfo.get_method_bytecode(method))

        assert expected_bytecode in bytecodes

    def test_get_method_bytecode_with_const_wide_instructions(self, apkinfo):
        if apkinfo.core_library in ["rizin", "radare2"]:
            pytest.skip(
                reason="The upstream does not parse the instruction correctly."
            )

        method = apkinfo.find_method(
            "Landroid/support/v4/view/ViewPager;",
            "distanceInfluenceForSnapDuration",
            "(F)F",
        )[0]

        bytecodes = list(apkinfo.get_method_bytecode(method))
        assert any((b for b in bytecodes
                    if b.mnemonic == "const-wide" and
                    b.registers == ["v2"] and
                    (b.parameter == 4602160705557665991 or
                     b.parameter == 0.471239)))

    def test_lowerfunc(self, apkinfo):
        if apkinfo.core_library == "radare2":
            pytest.skip(
                reason="The upstream missed the xrefs of the function."
            )

        method = apkinfo.find_method(
            "Lcom/example/google/service/SMSReceiver;",
            "isContact",
            "(Ljava/lang/String;)Ljava/lang/Boolean;",
        )[0]

        expect_method = apkinfo.find_method(
            "Lcom/example/google/service/ContactsHelper;",
            "<init>",
            "(Landroid/content/Context;)V",
        )[0]
        expect_offset = 10

        upper_methods = apkinfo.lowerfunc(method)

        assert (expect_method, expect_offset) in upper_methods

    def test_superclass_relationships_with_expected_class(self, apkinfo):
        expected_upper_class = {"Lcom/example/google/service/HttpHelper;"}
        class_name = "Lcom/example/google/service/WebServiceCalling;"

        upper_set = apkinfo.superclass_relationships[class_name]

        assert expected_upper_class == upper_set

    @staticmethod
    @pytest.mark.parametrize(
        "test_input, expected",
        [
            (
                "Landroid/view/KeyEvent;",
                str,
            ),
            (
                0x3E8,
                float,
            ),
            (
                (
                    "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)"
                    "Ljava/lang/StringBuilder;"
                ),
                str,
            ),
            (
                "str.google.c.a.tc",
                str,
            ),
        ],
    )
    def test_parse_parameter(test_input, expected, apkinfo_with_R2Imp_only):
        apkinfo = apkinfo_with_R2Imp_only
        parsed_param = apkinfo._parse_parameter(test_input)
        assert isinstance(parsed_param, expected)

    def test_get_strings(self, apkinfo):
        if apkinfo.core_library in ["radare2", "rizin"]:
            pytest.skip(
                reason="Upstream missed some strings in the binary."
            )

        expectStrings = {"cache", "display_name", "ACTION_CUT"}

        result = apkinfo.get_strings()

        assert expectStrings.issubset(result)

    def test_get_wrapper_smali(self, apkinfo):
        if apkinfo.core_library in ["radare2", "rizin"]:
            pytest.skip(
                reason=(
                    "Upstream missed the bytecodes "
                    "in the latter part of the function."
                )
            )

        parent_method = apkinfo.find_method(
            "Lcom/example/google/service/ContactsHelper;",
            "getSIMContacts",
            "()V",
        )[0]

        first_method = apkinfo.find_method(
            "Landroid/content/ContentResolver;",
            "query",
            (
                "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; "
                "[Ljava/lang/String; Ljava/lang/String;)"
                "Landroid/database/Cursor;"
            ),
        )[0]

        second_method = apkinfo.find_method(
            "Landroid/database/Cursor;",
            "getColumnIndex",
            "(Ljava/lang/String;)I",
        )[0]

        expected_result = {
            "first": [
                "invoke-virtual/range",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
                (
                    "Landroid/content/ContentResolver;->query"
                    "(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String;"
                    " [Ljava/lang/String; Ljava/lang/String;)"
                    "Landroid/database/Cursor;"
                ),
            ],
            "first_hex": "74 06 83 00 00 00",
            "second": [
                "invoke-interface",
                "v7",
                "v2",
                (
                    "Landroid/database/Cursor;->getColumnIndex"
                    "(Ljava/lang/String;)I"
                ),
            ],
            "second_hex": "72 20 f5 00 27 00",
        }

        result = apkinfo.get_wrapper_smali(
            parent_method, first_method, second_method
        )

        for key, expected in expected_result.items():
            assert result[key] == expected
