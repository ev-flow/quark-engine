<p align="center">
    <a href="https://www.blackhat.com/asia-24/arsenal/schedule/index.html#quark-script---dig-vulnerabilities-in-the-blackbox-37549">
        <img alt="Black Hat Arsenal" src="https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202024-blue">
    </a>
    <a href="https://www.blackhat.com/asia-21/arsenal/schedule/index.html#quark-engine-storyteller-of-android-malware-22458">
        <img alt="Black Hat Arsenal" src="https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202021-blue">
    </a>
    <a href="https://conference.hitb.org/hitb-lockdown002/sessions/quark-engine-an-obfuscation-neglect-android-malware-scoring-system/">
        <img alt="HITB" src="https://img.shields.io/badge/HITB-Lockdown%20002-red">
    </a>
    <a href="https://www.youtube.com/watch?v=XK-yqHPnsvc&ab_channel=DEFCONConference">
        <img alt="defcon" src="https://img.shields.io/badge/DEFCON%2028-BTV-blue">
    </a><br>
    <a href="https://github.com/quark-engine/quark-engine/actions/workflows/pytest.yml">
        <img alt="build status" src="https://github.com/quark-engine/quark-engine/actions/workflows/pytest.yml/badge.svg">
    </a>
    <a href="https://codecov.io/gh/quark-engine/quark-engine">
        <img alt="codecov" src="https://codecov.io/gh/ev-flow/quark-engine/graph/badge.svg">
    </a>
    <a href="https://github.com/18z/quark-rules/blob/master/LICENSE">
        <img alt="license" src="https://img.shields.io/badge/License-GPLv3-blue.svg">
    </a>
    <a href="https://www.python.org/downloads/release/python-31015/">
        <img alt="python version" src="https://img.shields.io/badge/python-3.10-blue.svg">
    </a>
    <a href="https://pypi.org/project/quark-engine/">
        <img alt="PyPi Download" src="https://pepy.tech/badge/quark-engine">
    </a><br>
    <a href="https://twitter.com/quarkengine">
        <img alt="Twitter" src="https://img.shields.io/twitter/follow/quarkengine?style=social">
    </a><br>
    <img src="https://i.imgur.com/8GwkWei.png"/>
</p>

# Android Malware Ontology — Unveil the Behavior of Android Malware
## Malware Family Analysis Report Showcase

<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/e8f150e8-a27f-4d0f-b3f0-346714a4cdc4" width="310"></td>
    <td><img src="https://github.com/user-attachments/assets/1a209c41-7f14-4a71-957a-637148e8a5ec" width="310"></td>
    <td><img src="https://github.com/user-attachments/assets/ad93ee2d-e65d-4ac6-8df2-909153151f68" width="310"></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/ea66a178-0eb1-4832-9b3f-745b973639aa" width="310"></td>
    <td><img src="https://github.com/user-attachments/assets/342a4e3f-33bd-4ff4-92ed-7869356ee1c7" width="310"></td>
    <td><img src="https://github.com/user-attachments/assets/a95e99b1-b7aa-4672-89be-cd2f6bc9e3cd" width="310"></td>
  </tr>
</table>


| Family      | Summary                                            | Signature Behaviors                    | Report |
|-------------|----------------------------------------------------|--------------------------|--------|
| DroidKungFu | Privilege escalation with C2 control.              | 1. Gain unlimited access to a device.<br>2. Install/Uninstall additional apps.<br>3. Forward confidential data. | [View](https://quark-engine.readthedocs.io/en/latest/quark_rules.html#new-quark-rules-for-droidkungfu) | 
| GoldDream   | SMS/call log exfiltration with remote C2 commands. | 1. Monitor SMS messages and phone calls.<br>2. Upload SMS messages and phone calls to remote servers.              | [View](https://quark-engine.readthedocs.io/en/latest/quark_rules.html#new-quark-rules-for-golddream) |
| SpyNote     | Credential theft and device surveillance via RAT.  | 1. Take screenshots.<br>2. Simulate user gestures.<br>3. Log user input.<br>4. Communicate with C2 servers.      | [View](https://quark-engine.readthedocs.io/en/latest/quark_rules.html#new-quark-rules-for-spynote) |
| DawDropper  | Dropper that installs banking trojans for financial theft. | 1. Download APKs from remote servers.<br>2. Install additional APKs. | [View](https://quark-engine.readthedocs.io/en/latest/quark_rules.html#new-quark-rules-for-dawdropper) |
| SLocker     | Android ransomware locking/encrypting devices.     | 1. Lock the device with an overlay screen. | [View](https://quark-engine.readthedocs.io/en/latest/quark_rules.html#new-quark-rules-for-slocker) |
| PhantomCard | NFC relay–based financial fraud.                   | 1. Communicate with C2 servers.<br>2. Read the payment data of NFC cards.<br>3. Captures PINs of NFC cards through deceptive screens.  | [View](https://quark-engine.readthedocs.io/en/latest/quark_rules.html#new-quark-rules-for-phantomcard) |



## Quick Start

### Step 1. Install via PyPi
Install the latest version of Quark Engine:
```bash
$ pip3 install -U quark-engine
```

### Step 2. Download Latest Rules
Fetch the latest rule database:
```bash
$ freshquark
```

### Step 3. Run Summary Report
Analyze an APK with the downloaded rules and generate a summary report:
```bash
$ quark -a <apk_file> -s
```
### Step 4. View Results
Example output:
<img width="1280" height="461" alt="Screenshot-2025-11-25-22-36-54" src="https://github.com/user-attachments/assets/fc919b8d-d10d-4f14-bdd5-0a58b0893708" />


## Acknowledgments

### The Honeynet Project

<a href="https://www.honeynet.org"> <img style="border: 0.2px solid black" width=115 height=150 src="https://i.imgur.com/znu7cMJ.png" alt="Honeynet.org logo"> </a>

### Google Summer Of Code

Quark-Engine has been participating in the GSoC under the Honeynet Project!

*   2021:
    *   [YuShiang Dang](https://twitter.com/YushianhD): [New Rule Generation Technique & Make Quark Everywhere Among Security Open Source Projects](https://github.com/ev-flow/ref/blob/main/GSoC-2021-YuShiangDang.md)
    *   [Sheng-Feng Lu](https://twitter.com/haeter525): [Replace the core library of Quark-Engine](https://github.com/ev-flow/ref/blob/main/GSoC-2021-ShengFengLu.md)

Stay tuned for the upcoming GSoC! Join the [Honeynet Slack chat](https://gsoc-slack.honeynet.org/) for more info.

## Core Values of Quark Engine Team

*   We love **battle fields**. We embrace **uncertainties**. We challenge **impossibles**. We **rethink** everything. We change the way people think. And the most important of all, we benefit ourselves by benefit others **first**.
