# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from quark.core.apkinfo import AndroguardImp
from quark.core.dextraceapkinfo import DexTraceImp
from quark.core.rzapkinfo import RizinImp
from quark.utils.regex import (
    extract_url,
    extract_ip,
    extract_content,
    validate_base64,
    extract_file,
)


class Forensic:
    __slots__ = ["apk", "all_strings"]

    def __init__(self, apkpath, core_library="dextrace"):
        match core_library:
            case "rizin":
                self.apk = RizinImp(apkpath)
            case "androguard":
                self.apk = AndroguardImp(apkpath)
            case "dextrace":
                self.apk = DexTraceImp(apkpath)

        self.all_strings = self.apk.get_strings()

    def get_all_strings(self):
        """
        Return all the strings inside the APK with a set.
        :return: a set of strings containing all strings
        """

        return self.all_strings

    def get_url(self):
        """
        Return all the url strings inside the APK with a set.
        :return: a set of strings containing the url
        """

        url = set()

        for string in self.all_strings:

            if extract_url(string):
                for url_string in extract_url(string):
                    url.add(url_string)

        return url

    def get_ip(self):
        """
        Return all the ip address strings inside the APK with a set.
        :return: a set of strings containing the ip address
        """

        ip = set()

        for string in self.all_strings:

            if extract_ip(string):

                for ip_string in extract_ip(string):
                    ip.add(ip_string)

        return ip

    def get_content(self):
        """
        Return all the content strings inside the APK with a set.
        :return: a set of strings containing "content://"
        """

        return {string for string in self.all_strings if extract_content(string)}

    def get_file(self):
        """
        Return all the file strings inside the APK with a set.
        :return: a set of strings containing "file://"
        """

        return {string for string in self.all_strings if extract_file(string)}

    def get_base64(self):
        """
        Return all possible Base64-encoded strings in the APK.
        :return: a set of strings containing possible Base64-encoded string
        """

        return {string for string in self.all_strings if validate_base64(string)}

    def get_android_api(self):
        """
        Return all Android APIs in the APK.

        :return: a list of MethodAnalysis which contains all Android API.
        """

        return self.apk.android_apis


if __name__ == "__main__":
    pass
