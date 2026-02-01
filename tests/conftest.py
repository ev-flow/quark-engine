# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os
from typing import Dict

import pytest
import requests

SAMPLES = [
    {
        "sourceUrl": (
            "https://github.com/quark-engine/apk-samples"
            "/raw/master/malware-samples/14d9f1a92dd984d6040cc41ed06e273e.apk"
        ),
        "fileName": "14d9f1a92dd984d6040cc41ed06e273e.apk",
    },
    {
        "sourceUrl": (
            "https://github.com/quark-engine/apk-samples"
            "/raw/master/malware-samples/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
        ),
        "fileName": "13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk",
    },
    {
        "sourceUrl": (
            "https://github.com/quark-engine/apk-samples"
            "/raw/master/malware-samples/Ahmyth.apk"
        ),
        "fileName": "Ahmyth.apk"
    },
    {
        "sourceUrl": (
            "https://github.com/quark-engine/apk-samples"
            "/raw/master/vulnerable-samples/pivaa.apk"
        ),
        "fileName": "pivaa.apk"
    },
    {
        "sourceUrl": (
            "https://github.com/quark-engine/apk-samples"
            "/raw/master/vulnerable-samples/Vuldroid.apk"
        ),
        "fileName": "Vuldroid.apk",
    },
    {
        "sourceUrl": (
            "https://github.com/quark-engine/apk-samples"
            "/raw/master/malware-samples/"
            "3d52b5728af55c37d5bd74c3f9b7e9ea6b007a9ec202a648ce3dc7e37ff49b29"
            ".apk"
        ),
        "fileName": (
            "3d52b5728af55c37d5bd74c3f9b7e9ea6b007a9ec202a648ce3dc7e37ff49b29"
            ".apk"
        ),
    },
]


def downloadSample(
    tmp_path_factory: pytest.TempPathFactory, sample: Dict[str, str]
):
    folder = os.path.splitext(os.path.basename(__file__))[0]
    folder = tmp_path_factory.mktemp(folder)

    SAMPLE_PATH_14d9f = folder / sample["fileName"]

    response = requests.get(sample["sourceUrl"], allow_redirects=True)
    file = open(SAMPLE_PATH_14d9f, "wb")
    file.write(response.content)
    file.close()

    return str(SAMPLE_PATH_14d9f)


@pytest.fixture(scope="session")
def SAMPLE_PATH_14d9f(tmp_path_factory: pytest.TempPathFactory) -> str:
    return downloadSample(tmp_path_factory, SAMPLES[0])


@pytest.fixture(scope="session")
def SAMPLE_PATH_13667(tmp_path_factory: pytest.TempPathFactory) -> str:
    return downloadSample(tmp_path_factory, SAMPLES[1])


@pytest.fixture(scope="session")
def SAMPLE_PATH_Ahmyth(tmp_path_factory: pytest.TempPathFactory) -> str:
    return downloadSample(tmp_path_factory, SAMPLES[2])


@pytest.fixture(scope="session")
def SAMPLE_PATH_pivaa(tmp_path_factory: pytest.TempPathFactory) -> str:
    return downloadSample(tmp_path_factory, SAMPLES[3])


@pytest.fixture(scope="session")
def SAMPLE_PATH_Vuldroid(tmp_path_factory: pytest.TempPathFactory) -> str:
    return downloadSample(tmp_path_factory, SAMPLES[4])


@pytest.fixture(scope="session")
def SAMPLE_PATH_3d52b(tmp_path_factory: pytest.TempPathFactory) -> str:
    return downloadSample(tmp_path_factory, SAMPLES[5])
