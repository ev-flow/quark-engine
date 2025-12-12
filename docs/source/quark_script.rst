++++++++++++++++++++++++++++++++++++++++++++++++++
Quark Script
++++++++++++++++++++++++++++++++++++++++++++++++++

Ecosystem for Mobile Security Tools
------------------------------------

Innovative & Interactive
=========================

The goal of Quark Script aims to provide an innovative way for mobile security researchers to analyze or **pentest**  the targets.

Based on Quark, we integrate decent tools as Quark Script APIs and make them exchange valuable intelligence to each other. This enables security researchers to **interact**  with staged results and perform **creative**  analysis with Quark Script.

Dynamic & Static Analysis
==========================

In Quark script, we integrate not only static analysis tools (e.g. Quark itself) but also dynamic analysis tools (e.g. `objection <https://github.com/sensepost/objection>`_).  

Re-Usable & Sharable
====================

Once the user creates a Quark script for specific analysis scenario. The script can be used in another targets. Also, the script can be shared to other security researchers. This enables the exchange of knowledges. 

More APIs to come
==================
Quark Script is now in a beta version. We'll keep releasing practical APIs and analysis scenarios.  


Quickstart 
-----------

| In this tutorial, we will learn how to install and run Quark Script with a very easy example.
| We show how to detect CWE-798 in ovaa.apk.

Step 1: Environments Requirements
==================================
- Quark Script requires Python 3.10 or above.

Step 2: Install Quark Engine
=============================

You can install Quark Engine by running:

::

    $ pip3 install quark-engine


Step 3: Prepare Quark Script, Detection Rule and the Sample File
================================================================

1. Get the CWE-798 Quark Script and the detection rule `here <https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-798-in-android-application-ovaa-apk>`_.
2. Get the sampe file (ovaa.apk) `here <https://github.com/dark-warlord14/ovaa/releases/tag/1.0>`_.
3. Put the script, detection rule, and sample file in the same directory.
4. Edit accordingly to the file names:

.. code-block:: python

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "findSecretKeySpec.json"


Now you are ready to run the script!

Step 4: Run the script
======================

::

    $ python3 CWE-798.py


You should now see the detection result in the terminal.

::

    Found hard-coded AES key 49u5gh249gh24985ghf429gh4ch8f23f


Introduce of Quark Script APIs
------------------------------

findMethodInAPK(samplePath, targetMethod)
=========================================

- **Description**: Find the target method in APK
- **params**: 
    1. samplePath: Target file
    2. targetMethod: A python list contains class name, method name, and descriptor of target method
- **return**: Python list contains caller method instance of target method

checkMethodCalls(samplePath, targetMethod, checkMethods)
=========================================================

- **Description**: Check any of the specific methods shown in the target method.
- **params**: 
    1. samplePath: target file
    2. targetMethod: python list contains the class name, method name, and descriptor of the target method or a Method Object
    3. checkMethods: python list contains the class name, method name, and descriptor of the target method
- **return**: bool that indicates if the specific methods are called or defined within a target method or not

findMethodImpls(samplePath, targetMethod)
=========================================================

- **Description**: Find all implementations of a specified method in the APK.
- **params**:
    1. samplePath: target file
    2. targetMethod: python list contains the class name, method name, and descriptor of the target method
- **return**: python list contains the method implementations of the target method

isMethodReturnAlwaysTrue(samplePath, targetMethod)
=========================================================

- **Description**: Check if a method always returns True.
- **params**:
    1. samplePath: target file
    2. targetMethod: python list contains the class name, method name, and descriptor of the target method
- **return**: True/False

Rule(rule.json)
===============

- **Description**: Making detection rule a rule instance
- **params**: Path of a single Quark rule
- **return**: Quark rule instance

runQuarkAnalysis(SAMPLE_PATH, ruleInstance)
===========================================

- **Description**: Given detection rule and target sample, this instance runs the basic Quark analysis.
- **params**: 
    1. SAMPLE_PATH: Target file 
    2. ruleInstance: Quark rule object
- **return**: quarkResult instance

quarkResultInstance.behaviorOccurList
=====================================

- **Description**: List that stores instances of detected behavior in different part of the target file.
- **params**: none
- **return**: detected behavior instance

quarkResultInstance.getAllStrings(none)
=======================================

- **Description**: Get all strings inside the target APK file.
- **params**: none
- **return**: python list containing all strings inside the target APK file.

quarkResultInstance.isHardcoded(argument)
==========================================

- **Description**: Check if the argument is hardcoded into the APK.
- **params**: 
    1. argument: string value that is passed in when a method is invoked
- **return**: True/False

quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)
==================================================================
- **Description**: Find target method in caller method.
- **params**: 
    1. callerMethod: python list contains class name, method name and descriptor of caller method.
    2. targetMethod: python list contains class name, method name and descriptor of target method.
- **return**: python list contains target method instances.

behaviorInstance.firstAPI.fullName
==================================

- **Description**: Show the name of the first key API called in this behavior.
- **params**: none
- **return**: API name

behaviorInstance.secondAPI.fullName
===================================

- **Description**: Show the name of the second key API called in this behavior.
- **params**: none
- **return**: API name

behaviorInstance.hasString(pattern, isRegex)
============================================

- **Description**: Check if the arguments of the two APIs contain the string.
- **params**: 
    1. pattern: string that may appear in the arguments
    2. isRegex: consider the string as a regular expression if True, defaults to False
- **return**: the matched string

behaviorInstance.hasUrl(none)
=============================

-  **Description**: Check if the behavior contains urls.
-  **params**: none
-  **return**: python list containing all detected urls.

behaviorInstance.methodCaller
=============================

- **Description**: Find method who calls this behavior (API1 & API2).
- **params**: none
- **return**: method instance 

behaviorInstance.getParamValues(none)
=====================================

- **Description**: Get parameter values that API1 sends to API2 in the behavior.
- **params**: none
- **return**: python list containing parameter values.

behaviorInstance.isArgFromMethod(targetMethod)
==============================================

- **Description**: Check if there are any arguments from the target method.
- **params**: 
    1. targetMethod: python list contains class name, method name, and descriptor of target method
- **return**: True/False

behaviorInstance.getMethodsInArgs(none)
==============================================

- **Description**: Get the methods which the arguments in API2 has passed through.
- **params**: none
- **return**: python list containing method instances

methodInstance.getXrefFrom(none)
================================

- **Description**: Find out who call this method.
- **params**: none
- **return**: python list containing caller methods.

methodInstance.getXrefTo(none)
==============================

- **Description**: Find out who this method called.
- **params**: none
- **return**: python list containing tuples (callee methods, index).

methodInstance.getArguments(none)
==================================

- **Description**: Get arguments from method.
- **params**: none
- **return**: python list containing arguments.
  
methodInstance.findSuperclassHierarchy(none)
=============================================

- **Description**: Find all superclasses of this method object.
- **params**: none
- **return**: Python list contains all superclass names of this method. 

Objection(host)
===============

- **Description**: Create an instance for Objection (dynamic analysis tool). 
- **params**: Monitoring IP:port
- **return**: objection instance

objInstance.hookMethod(method, watchArgs, watchBacktrace, watchRet)
=====================================================================

- **Description**: Hook the target method with Objection.
- **params**: 
    1. method: the target API. (type: str or method instance) 
    2. watchArgs: Return Args information if True. (type: boolean) 
    3. watchBacktrace: Return backtrace information if True. (type: boolean) 
    4. watchRet: Return the return information of the target API if True. (type: boolean)
- **return**: none

runFridaHook(apkPackageName, targetMethod, methodParamTypes, secondToWait)
============================================================================

- **Description**: Track calls to the specified method for given seconds.
- **params**:
    1. apkPackageName: the package name of the target APP
    2. targetMethod: the target API
    3. methodParamTypes: string that holds the parameters used by the target API
    4. secondToWait: seconds to wait for method calls, defaults to 10
- **return**: FridaResult instance

checkClearText(inputString)
============================

- **Description**: Check the decrypted value of the input string.
- **params**:
    1. inputString: string to be checked
- **return**: the decrypted value

getActivities(samplePath)
==========================
- **Description**: Get activities from the manifest of target sample.
- **params**: 
    1. samplePath: the file path of target sample
- **return**: python list containing activities

activityInstance.hasIntentFilter(none)
======================================
- **Description**: Check if the activity has an intent-filter.
- **params**: none
- **return**: True/False

activityInstance.isExported(none)
==================================
- **Description**: Check if the activity set ``android:exported=true``.
- **params**: none
- **return**: True/False

getReceivers(samplePath)
==========================
- **Description**: Get receivers from a target sample.
- **params**:
    1. samplePath: target sample
- **return**: python list containing receivers

receiverInstance.hasIntentFilter(none)
======================================
- **Description**: Check if the receiver has an intent-filter.
- **params**: none
- **return**: True/False

receiverInstance.isExported(none)
==================================
- **Description**: Check if the receiver is exported.
- **params**: none
- **return**: True/False

getApplication(samplePath)
==========================
- **Description**: Get the application element from the manifest file of the target sample.
- **params**: 
    1. samplePath: the file path of the target sample
- **return**: the application element of the target sample

applicationInstance.isDebuggable(none)
======================================
- **Description**: Check if the application element sets ``android:debuggable=true``.
- **params**: none
- **return**:  True/False

getProviders(samplePath)
==========================
- **Description**: Get provider elements from the manifest file of the target sample.
- **params**:
    1. samplePath: the file path of target sample
- **return**: python list containing provider elements

providerInstance.isExported(none)
==================================
- **Description**: Check if the provider element set ``android:exported=true``.
- **params**: none
- **return**:  True/False

Analyzing real case (InstaStealer) using Quark Script
------------------------------------------------------

Quark Script that dynamic hooks the method containing urls 
===========================================================

The scenario is simple! We'd like to dynamic hooking the methods in the malware that contains urls. We can use APIs above to write Quark Script.

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule
    from quark.script.objection import Objection

    SAMPLE_PATH = "6f032.apk"
    RULE_PATH = "00211.json"

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for behaviorInstance in quarkResult.behaviorOccurList:
        detectedUrl = behaviorInstance.hasUrl()
        
        if detectedUrl:
            print(f"\nDetected Behavior -> {ruleInstance.crime}")
            print(f"\nDetected Url -> {detectedUrl}")
            
            method = behaviorInstance.methodCaller
            print(f"\nThe detected behavior was called by -> {method.fullName}")

            print("\nAttempt to hook the method:")
            obj = Objection("127.0.0.1:8888")
            
            obj.hookMethod(method, 
                        watchArgs=True, 
                        watchBacktrace=True, 
                        watchRet=True)
            print(f"\tHook -> {method.fullName}")
            
            for methodCaller in method.getXrefFrom():
                obj.hookMethod(methodCaller, 
                            watchArgs=True, 
                            watchBacktrace=True, 
                            watchRet=True)
                print(f"\tHook -> {methodCaller.fullName}")
                
            for methodCallee, _ in method.getXrefTo():
                obj.hookMethod(methodCallee, 
                            watchArgs=True, 
                            watchBacktrace=True, 
                            watchRet=True)
                print(f"\tHook -> {methodCallee.fullName}")
                
    print("\nSee the hook results in Objection's terminal.")

.. note::
    Please make sure you have the dynamic analysis environment ready before executing the script.

    1. Objection installed and running. Check the guideline `here <https://github.com/sensepost/objection/wiki/Installation>`_.
    2. Android Virtual Machine with frida installed. Check the guideline `here <https://frida.re/docs/android/>`_.
    3. Or a rooted Android Device (Google Pixel 6) with frida installed. Check the root guideline `here <https://forum.xda-developers.com/t/guide-root-pixel-6-with-magisk-android-12-1.4388733/>`_, frida install guideline is the `same <https://frida.re/docs/android/>`_ with Android Virtual Machine.

Quark Script Result
===================

.. image:: https://i.imgur.com/elztZdC.png

Logs on the Objection terminal (hooking)
========================================

.. image:: https://i.imgur.com/XrtfgjY.jpg

Method (callComponentMethod) with urls is detected triggered!
=============================================================

.. image:: https://i.imgur.com/ryV3f57.jpg


Detect CWE-798 in Android Application
-------------------------------------------------

This scenario seeks to find **hard-coded credentials** in the APK file.

CWE-798: Use of Hard-coded Credentials
======================================

We analyze the definition of CWE-798 and identify its characteristics.

See `CWE-798 <https://cwe.mitre.org/data/definitions/798.html>`_ for more details.

.. image:: https://imgur.com/rF8J8hE.png

Code of CWE-798 in ovaa.apk
============================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-798.

.. image:: https://imgur.com/Cg7DacP.png

CWE-798 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/R8CfDqD.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``findSecretKeySpec.json`` to spot on behavior using the constructor ``SecretKeySpec``. Second, we get all the parameter values from this constructor. Then, we parse the AES key from the parameter values. Finally, we check if the AES key is hardcoded in the APK file. If the answer is **YES**, BINGO!!! We find hard-coded credentials in the APK file.

Quark Script: CWE-798.py
========================

.. image:: https://imgur.com/IOyrqDc.png

.. code-block:: python

    import re
    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "findSecretKeySpec.json"

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for secretKeySpec in quarkResult.behaviorOccurList:

        firstParam = secretKeySpec.secondAPI.getArguments()[1]
        secondParam = secretKeySpec.secondAPI.getArguments()[2]

        if secondParam == "AES":
            AESKey = re.findall(r"\((.*?)\)", firstParam)[1]

            if quarkResult.isHardcoded(AESKey):
                print(f"Found hard-coded {secondParam} key {AESKey}")

Quark Rule: findSecretKeySpec.json
===================================

.. image:: https://imgur.com/2BYOE70.png

.. code-block:: json

    {
        "crime": "Detect APK using SecretKeySpec.",
        "permission": [],
        "api": [
            {
                "descriptor": "()[B",
                "class": "Ljava/lang/String;",
                "method": "getBytes"
            },
            {
                "descriptor": "([BLjava/lang/String;)V",
                "class": "Ljavax/crypto/spec/SecretKeySpec;",
                "method": "<init>"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-798.py
    Found hard-coded AES key 49u5gh249gh24985ghf429gh4ch8f23f



Detect CWE-94 in Android Application
-------------------------------------

This scenario seeks to find **code injection** in the APK file. 

CWE-94: Improper Control of Generation of Code
===============================================

We analyze the definition of CWE-94 and identify its characteristics.

See `CWE-94 <https://cwe.mitre.org/data/definitions/94.html>`_ for more details.

.. image:: https://imgur.com/M9Jlgrn.png

Code of CWE-94 in ovaa.apk
===========================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-94.

.. image:: https://imgur.com/MdlAnvu.png

CWE-94 Detection Process Using Quark Script API
================================================

Let's use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``loadExternalCode.json`` to spot on behavior using the method ``createPackageContext``. Then, we find the caller method that calls the ``createPackageContext``. Finally, we check if the method ``checkSignatures`` is called in the caller method for verification.

.. image:: https://imgur.com/6cPBMWP.jpg

Quark Script: CWE-94.py
========================

.. image:: https://imgur.com/Aw26Lv2.jpg

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "loadExternalCode.json"

    targetMethod = [
            "Landroid/content/pm/PackageManager;",
            "checkSignatures",
            "(Ljava/lang/String;Ljava/lang/String;)I"
            ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for ldExternalCode in quarkResult.behaviorOccurList:

        callerMethod = [
                ldExternalCode.methodCaller.className,
                ldExternalCode.methodCaller.methodName,
                ldExternalCode.methodCaller.descriptor
                ]

        if not quarkResult.findMethodInCaller(callerMethod, targetMethod):
            print(f"Method: {targetMethod[1]} not found!")
            print(f"CWE-94 is detected in {SAMPLE_PATH}")

Quark Rule: loadExternalCode.json
==================================

.. image:: https://imgur.com/IHENeJx.jpg

.. code-block:: json

    {
        "crime": "Load external code from other APK.",
        "permission": [],
        "api": [
            {
                "descriptor": "(Ljava/lang/String;I)Landroid/content/Context;",
                "class": "",
                "method": "createPackageContext"
            },
            {
                "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;",
                "class": "Ljava/lang/ClassLoader;",
                "method": "loadClass"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-94.py
    Method: checkSignatures not found!
    CWE-94 is detected in ovaa.apk




Detect CWE-921 in Android Application
--------------------------------------

This scenario seeks to find the **unsecured storage mechanism of sensitive data** in the APK file.

CWE-921: Storage of Sensitive Data in a Mechanism without Access Control
========================================================================

We analyze the definition of CWE-921 and identify its characteristics.

See `CWE-921 <https://cwe.mitre.org/data/definitions/921.html>`_ for more details.

.. image:: https://imgur.com/2zlPLHe.jpg


Code of CWE-921 in ovaa.apk
============================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-921.

.. image:: https://imgur.com/2u5iL1K.jpg

CWE-921 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/qHOMqKy.jpg

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``checkFileExistence.json`` to spot on behavior that checks if a file exists on a given storage mechanism. Then, we use API ``methodInstance.getArguments()`` to get the file path. Finally, CWE-921 is found if the file path contains the keyword ``sdcard``.

Quark Script: CWE-921.py
========================

.. image:: https://imgur.com/HULgyIy.jpg

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "checkFileExistence.json"

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for existingFile in quarkResult.behaviorOccurList:
        filePath = existingFile.secondAPI.getArguments()[0]
        if "sdcard" in filePath:
            print(f"This file is stored inside the SDcard\n")
            print(f"CWE-921 is detected in {SAMPLE_PATH}.")

Quark Rule: checkFileExistence.json
====================================

.. image:: https://imgur.com/zRiYLtS.jpg

.. code-block:: json

    {
        "crime": "Check file existence",
        "permission": [],
        "api": [
            {
                "descriptor": "(Ljava/lang/String;)V",
                "class": "Ljava/io/File;",
                "method": "<init>"
            },
            {
                "descriptor": "()Z",
                "class": "Ljava/io/File;",
                "method": "exists"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-921.py
    This file is stored inside the SDcard

    CWE-921 is detected in ovaa.apk.




Detect CWE-312 in Android Application
--------------------------------------

This scenario seeks to find **cleartext storage of sensitive data** in the APK file.

CWE-312: Cleartext Storage of Sensitive Information
====================================================

We analyze the definition of CWE-312 and identify its characteristics.

See `CWE-312 <https://cwe.mitre.org/data/definitions/312.html>`_ for more details.

.. image:: https://imgur.com/mD2uXUy.jpg

Code of CWE-312 in ovaa.apk
============================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-312.

.. image:: https://imgur.com/MfnYIYy.jpg

CWE-312 Detection Process Using Quark Script API
=================================================

Let’s use the above APIs to show how the Quark script finds this vulnerability.

We have designed a `Frida <https://frida.re/>`_ script ``agent.js`` to hook a specified method and get the arguments when the method is called. It can be found in `quark-engine/quark/script/frida <https://github.com/quark-engine/quark-engine/tree/master/quark/script/frida>`_.
 
To begin with, we hook the method ``putString`` to catch its arguments. Then, we check if sensitive information like email or password is passed. Finally, we use ``checkClearText`` imported from `Ares <https://github.com/bee-san/Ares>`_ to check if the arguments are cleartext. If both **YES**, CWE-312 vulnerability might be caused.

.. image:: https://imgur.com/eNjm3ES.jpg

Quark Script: CWE-312.py
========================

.. image:: https://imgur.com/rxMPZX8.jpg

.. code-block:: python

    from quark.script.frida import runFridaHook
    from quark.script.ares import checkClearText

    APP_PACKAGE_NAME = "oversecured.ovaa"

    TARGET_METHOD = "android.app." "SharedPreferencesImpl$EditorImpl." "putString"

    METHOD_PARAM_TYPE = "java.lang.String," "java.lang.String"

    fridaResult = runFridaHook(
        APP_PACKAGE_NAME, TARGET_METHOD, METHOD_PARAM_TYPE, secondToWait=10
    )

    for putString in fridaResult.behaviorOccurList:

        firstParam = putString.firstAPI.getArguments()
        secondParam = putString.secondAPI.getArguments()

        if firstParam in ["email", "password"] and secondParam == checkClearText(
            secondParam
        ):

            print(
                "The CWE-312 vulnerability is found. "
                f'The cleartext is "{secondParam}"'
            )


Frida Script: agent.js
=======================


.. code-block:: javascript

    // -*- coding: utf-8 -*-
    // This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
    // See the file 'LICENSE' for copying permission.

    /*global Java, send, rpc*/
    function replaceMethodImplementation(targetMethod, classAndMethodName, methodParamTypes, returnType) {
        targetMethod.implementation = function () {
            let callEvent = {
                "type": "CallCaptured",
                "identifier": [classAndMethodName, methodParamTypes, returnType],
                "paramValues": []
            };

            for (const arg of arguments) {
                callEvent["paramValues"].push((arg || "(none)").toString());
            }

            send(JSON.stringify(callEvent));
            return targetMethod.apply(this, arguments);
        };
    }

    function watchMethodCall(classAndMethodName, methodParamTypes) {
        if (classAndMethodName == null || methodParamTypes == null) {
            return;
        }

        const indexOfLastSeparator = classAndMethodName.lastIndexOf(".");
        const classNamePattern = classAndMethodName.substring(0, indexOfLastSeparator);
        const methodNamePattern = classAndMethodName.substring(indexOfLastSeparator + 1);

        Java.perform(() => {
            const classOfTargetMethod = Java.use(classNamePattern);
            const possibleMethods = classOfTargetMethod[`${methodNamePattern}`];

            if (typeof possibleMethods === "undefined") {
                const failedToWatchEvent = {
                    "type": "FailedToWatch",
                    "identifier": [classAndMethodName, methodParamTypes]
                };

                send(JSON.stringify(failedToWatchEvent));
                return;
            }

            possibleMethods.overloads.filter((possibleMethod) => {
                const paramTypesOfPossibleMethod = possibleMethod.argumentTypes.map((argument) => argument.className);
                return paramTypesOfPossibleMethod.join(",") === methodParamTypes;
            }).forEach((matchedMethod) => {
                const retType = matchedMethod.returnType.name;
                replaceMethodImplementation(matchedMethod, classAndMethodName, methodParamTypes, retType);
            }
            );

        });
    }

    rpc.exports["watchMethodCall"] = (classAndMethodName, methodParamTypes) => watchMethodCall(classAndMethodName, methodParamTypes);


Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-312.py
    The CWE-312 vulnerability is found. The cleartext is "test@email.com"
    The CWE-312 vulnerability is found. The cleartext is "password"


Detect CWE-89 in Android Application
-------------------------------------

This scenario seeks to find **SQL injection** in the APK file.

CWE-89 Improper Neutralization of Special Elements used in an SQL Command
==========================================================================

We analyze the definition of CWE-89 and identify its characteristics.

See `CWE-89 <https://cwe.mitre.org/data/definitions/89.html>`_ for more details.

.. image:: https://imgur.com/Yx9vIS2.jpg

Code of CWE-89 in AndroGoat.apk
================================

We use the `AndroGoat.apk <https://github.com/satishpatnayak/AndroGoat>`_ sample to explain the vulnerability code of CWE-89.

.. image:: https://imgur.com/QWvu8te.jpg

CWE-89 Detection Process Using Quark Script API
================================================

.. image:: https://imgur.com/gvPBB3v.jpg

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``executeSQLCommand.json`` to spot on behavior using SQL command Execution. Then, we use API ``behaviorInstance.isArgFromMethod(targetMethod)`` to check if ``append`` uses the value of ``getText`` as the argument. If yes, we confirmed that the SQL command string is built from user input, which will cause CWE-89 vulnerability.

Quark Script: CWE-89.py
========================

.. image:: https://imgur.com/B6Mfp2L.jpg

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "AndroGoat.apk"
    RULE_PATH = "executeSQLCommand.json"

    targetMethod = [
        "Landroid/widget/EditText;", # class name
        "getText",                   # method name
        "()Landroid/text/Editable;", # descriptor
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for sqlCommandExecution in quarkResult.behaviorOccurList:
        if sqlCommandExecution.isArgFromMethod(
            targetMethod
        ):
            print(f"CWE-89 is detected in {SAMPLE_PATH}")

Quark Rule: executeSQLCommand.json
===================================

.. image:: https://imgur.com/aYnt5oq.jpg

.. code-block:: json

    {
        "crime": "Execute SQL Command",
        "permission": [],
        "api": [
            {
                "class": "Ljava/lang/StringBuilder;",
                "method": "append",
                "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
            },
            {
                "class": "Landroid/database/sqlite/SQLiteDatabase;",
                "method": "rawQuery",
                "descriptor": "(Ljava/lang/String; [Ljava/lang/String;)Landroid/database/Cursor;"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-89.py

    CWE-89 is detected in AndroGoat.apk


Detect CWE-926 in Android Application 
----------------------------------------

This scenario seeks to find **Improper Export of Android Application Components** in the APK file.

CWE-926 Improper Export of Android Application Components
============================================================

We analyze the definition of CWE-926 and identify its characteristics.

See `CWE-926 <https://cwe.mitre.org/data/definitions/926.html>`_ for more details.

.. image:: https://imgur.com/Km8wtGs.jpg

Code of CWE-926 in dvba.apk
=========================================

We use the `dvba.apk <https://github.com/rewanthtammana/Damn-Vulnerable-Bank>`_ sample to explain the vulnerability code of CWE-926.

.. image:: https://imgur.com/KoOt5ii.jpg

CWE-926 Detection Process Using Quark Script API
================================================

.. image:: https://i.postimg.cc/Qtg97yD0/jie-tu-2025-10-30-wan-shang7-30-04.png

Let's use the above APIs to show how the Quark script finds this vulnerability.

First, we use Quark API ``getActivities(samplePath)`` to get all activity data in the manifest. Then, we use ``activityInstance.hasIntentFilter()`` to check if the activities have ``intent-filter``. Also, we use ``activityInstance.isExported()`` to check if the activities set the attribute ``android:exported=true``. If both are **true**, then the APK exports the component for use by other applications. That may cause CWE-926 vulnerabilities.

Quark Script: CWE-926.py
========================

.. image:: https://i.postimg.cc/KcwSLv9L/jie-tu-2025-10-30-wan-shang7-32-01.png

.. code-block:: python

	from quark.script import *

	SAMPLE_PATH = "dvba.apk"

	for activityInstance in getActivities(SAMPLE_PATH):

	    if activityInstance.hasIntentFilter() and activityInstance.isExported():
		print(f"CWE-926 is detected in the activity, {activityInstance}")

Quark Script Result
=====================

.. code-block:: TEXT

	$ python3 CWE-926.py 
	CWE-926 is detected in the activity, com.app.damnvulnerablebank.CurrencyRates
	CWE-926 is detected in the activity, com.app.damnvulnerablebank.SplashScreen


Detect CWE-749 in Android Application
----------------------------------------------

This scenario seeks to find **exposed methods or functions** in the APK file.

CWE-749 Exposed Dangerous Method or Function
=================================================

We analyze the definition of CWE-749 and identify its characteristics.

See `CWE-749 <https://cwe.mitre.org/data/definitions/749.html>`_ for more details.

.. image:: https://imgur.com/hmihGze.png

Code of CWE-749 in MSTG-Android-Java.apk
=============================================

We use the `MSTG-Android-Java.apk <https://github.com/OWASP/MASTG-Hacking-Playground>`_ sample to explain the vulnerability code of CWE-749.

.. image:: https://imgur.com/KiA0vRD.png

CWE-749 Detection Process Using Quark Script API
================================================

.. image:: https://i.postimg.cc/xjWjXH3P/jie-tu-2025-12-12-wan-shang11-01-40.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``configureJsExecution.json`` to spot on behavior using the method ``setJavascriptEnabled``. Then, we use the API ``methodInstance.getArguments()`` to check if it enables JavaScript execution on websites. Finally, we look for calls to the method ``addJavaScriptInterface`` in the caller method. If yes, the APK exposes dangerous methods or functions to websites. That causes CWE-749 vulnerability.

Quark Script: CWE-749.py
========================

.. image:: https://i.postimg.cc/TwKGwYyH/jie-tu-2025-12-12-wan-shang11-02-28.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "MSTG-Android-Java.apk"
    RULE_PATH = "configureJsExecution.json"

    targetMethod = [
        "Landroid/webkit/WebView;",
        "addJavascriptInterface",
        "(Ljava/lang/Object; Ljava/lang/String;)V"
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for configureJsExecution in quarkResult.behaviorOccurList:

        caller = configureJsExecution.methodCaller
        secondAPI = configureJsExecution.secondAPI

        enableJS = secondAPI.getArguments()[1]
        exposeAPI = quarkResult.findMethodInCaller(caller, targetMethod)

        if enableJS and exposeAPI:
            print(f"CWE-749 is detected in method, {caller.fullName}")

Quark Rule: configureJsExecution.json
=====================================

.. code-block:: json

    {
        "crime": "Configure JavaScript execution on websites",
        "permission": [],
        "api": [
            {
                "class": "Landroid/webkit/WebView;",
                "method": "getSettings",
                "descriptor": "()Landroid/webkit/WebSettings;"
            },
            {
                "class": "Landroid/webkit/WebSettings;",
                "method": "setJavaScriptEnabled",
                "descriptor": "(Z)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-749.py

    CWE-749 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Remote; onCreate (Landroid/os/Bundle;)V
    CWE-749 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Local; onCreate (Landroid/os/Bundle;)V


Detect CWE-532 in Android Application
--------------------------------------

This scenario seeks to find **insertion of sensitive information into Log file** in the APK file.

CWE-532: Insertion of Sensitive Information into Log File
==========================================================

We analyze the definition of CWE-532 and identify its characteristics.

See `CWE-532 <https://cwe.mitre.org/data/definitions/532.html>`_ for more details.

.. image:: https://imgur.com/6WzpyId.jpg

Code of CWE-532 in dvba.apk
============================

We use the `dvba.apk <https://github.com/rewanthtammana/Damn-Vulnerable-Bank>`_  sample to explain the vulnerability code of CWE-532.

.. image:: https://imgur.com/cLzBvh2.jpg

CWE-532 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/KLbnflF.jpg

Let's use the above APIs to show how the Quark script finds this vulnerability.

First, we use the API ``findMethodInAPK(samplePath, targetMethod)`` to locate ``log.d`` method. Then we use API ``methodInstance.getArguments()`` to get the argument that input to ``log.d``. Finally, we use some keywords such as "token", "password", and "decrypt" to check if arguments include sensitive data. If the answer is **YES**, that may cause sensitive data leakage into log file.

You can use your own keywords in the keywords list to detect sensitive data.

Quark Script: CWE-532.py
=========================

.. image:: https://imgur.com/L9Ciqlp.jpg

.. code-block:: python

    from quark.script import findMethodInAPK

    SAMPLE_PATH = "dvba.apk"
    TARGET_METHOD = [
        "Landroid/util/Log;",                       # class name
        "d",                                        # method name
        "(Ljava/lang/String; Ljava/lang/String;)I"  # descriptor
    ]
    CREDENTIAL_KEYWORDS = [
        "token",
        "decrypt",
        "password"
    ]

    methodsFound = findMethodInAPK(SAMPLE_PATH, TARGET_METHOD)

    for debugLogger in methodsFound:
        arguments = debugLogger.getArguments()

        for keyword in CREDENTIAL_KEYWORDS:
            if keyword in arguments[1]:
                print(f"CWE-532 is detected in method, {debugLogger.fullName}")

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-532.py
    CWE-532 is detected in method, Lcom/google/firebase/auth/FirebaseAuth; d (Lc/c/b/h/o;)V



Detect CWE-780 in Android Application
-----------------------------------------

This scenario seeks to find **the use of the RSA algorithm without Optimal Asymmetric Encryption Padding (OAEP)** in the APK file.

CWE-780 Use of RSA Algorithm without OAEP
============================================

We analyze the definition of CWE-780 and identify its characteristics.

See `CWE-780 <https://cwe.mitre.org/data/definitions/780.html>`_ for more details.

.. image:: https://imgur.com/veZNZcg.png

Code of CWE-780 in dvba.apk
=========================================

We use the `MSTG-Android-Java.apk <https://github.com/OWASP/MASTG-Hacking-Playground>`_ sample to explain the vulnerability code of CWE-780.

.. image:: https://imgur.com/c03senv.png

CWE-780 Detection Process Using Quark Script API
=================================================

.. image:: https://i.postimg.cc/x8zTSxpq/jie-tu-2025-11-14-shang-wu10-30-26.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

We first design a detection rule ``useOfCryptographicAlgo.json`` to spot on behavior using the cryptographic algorithm. Then, we use API ``behaviorInstance.hasString(pattern, isRegex)`` to filter behaviors using the RSA algorithm. Finally, we use the same API to check if the algorithm runs without the OAEP scheme. If the answer is YES, the plaintext is predictable.

Quark Script: CWE-780.py
=========================

.. image:: https://i.postimg.cc/fTYxNZP6/jie-tu-2025-11-14-shang-wu10-31-55.png

.. code-block:: python

    from quark.script import Rule, runQuarkAnalysis

    SAMPLE_PATH = "MSTG-Android-Java.apk"
    RULE_PATH = "useOfCryptographicAlgo.json"

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for useCryptographicAlgo in quarkResult.behaviorOccurList:
        methodCaller = useCryptographicAlgo.methodCaller

        if useCryptographicAlgo.hasString(
            "RSA"
        ) and not useCryptographicAlgo.hasString("OAEP"):
            print(f"CWE-780 is detected in method, {methodCaller.fullName}")


Quark Rule: useOfCryptographicAlgo.json
=======================================

.. code-block:: json

    {
        "crime": "Use of cryptographic algorithm",
        "permission": [],
        "api": [
            {
                "class": "Ljavax/crypto/Cipher;",
                "method": "getInstance",
                "descriptor": "(Ljava/lang/String; Ljava/lang/String;)Ljavax/crypto/Cipher"
            },
            {
                "class": "Ljavax/crypto/Cipher;",
                "method": "init",
                "descriptor": "(I Ljava/security/Key;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-780.py
    CWE-780 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_KeyStore; encryptString (Ljava/lang/String;)V




Detect CWE-319 in Android Application
--------------------------------------

This scenario seeks to find **Cleartext Transmission of Sensitive Information** in the APK file.

CWE-319 Cleartext Transmission of Sensitive Information
========================================================

We analyze the definition of CWE-319 and identify its characteristics.

See `CWE-319 <https://cwe.mitre.org/data/definitions/319.html>`_ for more details.

.. image:: https://imgur.com/hjEYP5b.jpg

Code of CWE-319 in ovaa.apk
============================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-319.

.. image:: https://imgur.com/wCYfTNx.jpg

CWE-319 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/H1FgUtE.jpg

Let’s use the above APIs to show how the Quark script finds this vulnerability. This sample uses the package ``Retrofit`` to request Web APIs, but the APIs use cleartext protocols.

We first design a detection rule ``setRetrofitBaseUrl.json`` to spot on behavior that sets the base URL of the Retrofit instance. Then, we loop through a custom list of cleartext protocol schemes and use API ``behaviorInstance.hasString(pattern, isRegex)`` to filter if there are arguments that are URL strings with cleartext protocol.

If the answer is **YES**, CWE-319 vulnerability is caused.

Quark Script: CWE-319.py
=========================

.. image:: https://imgur.com/CktArDJ.jpg

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "./ovaa.apk"
    RULE_PATH = "setRetrofitBaseUrl.json"

    PROTOCOL_KEYWORDS = [
        "http",
        "smtp",
        "ftp"
    ]


    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for setRetrofitBaseUrl in quarkResult.behaviorOccurList:
        for protocol in PROTOCOL_KEYWORDS:

            regexRule = f"{protocol}://[0-9A-Za-z./-]+"
            cleartextProtocolUrl = setRetrofitBaseUrl.hasString(regexRule, True)

            if cleartextProtocolUrl:
                print(f"CWE-319 detected!")
                print(f"Here are the found URLs with cleartext protocol:")
                print("\n".join(cleartextProtocolUrl))

Quark Rule: setRetrofitBaseUrl.json
====================================

.. image:: https://imgur.com/751Dhce.jpg

.. code-block:: json

    {
        "crime": "Set Retrofit Base Url",
        "permission": [],
        "api":
        [
            {
                "descriptor": "()V",
                "class": "Lretrofit2/Retrofit$Builder;",
                "method": "<init>"
            },
            {
                "descriptor": "(Ljava/lang/String;)Lretrofit2/Retrofit$Builder;",
                "class": "Lretrofit2/Retrofit$Builder;",
                "method": "baseUrl"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-319.py
    CWE-319 detected!
    Here are the found URLs with cleartext protocol:
    http://example.com./api/v1/




Detect CWE-327 in Android Application
--------------------------------------

This scenario seeks to find **Use of a Broken or Risky Cryptographic Algorithm** in the APK file.

CWE-327 Use of a Broken or Risky Cryptographic Algorithm
=========================================================

We analyze the definition of CWE-327 and identify its characteristics.

See `CWE-327 <https://cwe.mitre.org/data/definitions/327.html>`_ for more details.

.. image:: https://imgur.com/Xfm5C9K.jpg

Code of CWE-327 in InjuredAndroid.apk
======================================

We use the `InjuredAndroid.apk <https://github.com/B3nac/InjuredAndroid>`_ sample to explain the vulnerability code of CWE-327.

.. image:: https://imgur.com/R5zkGt2.jpg

CWE-327 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/2owB5Z7.jpg

Let’s use the above APIs to show how the Quark script finds this vulnerability.

We first design a detection rule ``useOfCryptographicAlgo.json`` to spot on behavior using cryptographic algorithms. Then, we use API ``behaviorInstance.hasString(pattern, isRegex)`` with a list to check if the algorithm is risky. If **YES**, that may cause the exposure of sensitive data.

Quark Script CWE-327.py
========================

.. image:: https://imgur.com/4fa3yS0.jpg

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "InjuredAndroid.apk"
    RULE_PATH = "useOfCryptographicAlgo.json"

    WEAK_ALGORITHMS = ["DES", "ARC4", "BLOWFISH"]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for useCryptoAlgo in quarkResult.behaviorOccurList:

        caller = useCryptoAlgo.methodCaller

        for algo in WEAK_ALGORITHMS:
            if useCryptoAlgo.hasString(algo):
                print(f"CWE-327 is detected in method, {caller.fullName}")

Quark Rule: useOfCryptographicAlgo.json
========================================

.. image:: https://imgur.com/rjRykWM.jpg

.. code-block:: json

    {
        "crime": "Use of cryptographic algorithm",
        "permission": [],
        "api": [
            {
                "class": "Ljavax/crypto/Cipher;",
                "method": "getInstance",
                "descriptor": "(Ljava/lang/String;)Ljavax/crypto/Cipher"
            },
            {
                "class": "Ljavax/crypto/Cipher;",
                "method": "init",
                "descriptor": "(I Ljava/security/Key;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-327.py
    CWE-327 is detected in method, Lb3nac/injuredandroid/k; b (Ljava/lang/String;)Ljava/lang/String;
    CWE-327 is detected in method, Lb3nac/injuredandroid/k; a (Ljava/lang/String;)Ljava/lang/String;



Detect CWE-20 in Android Application
-------------------------------------

This scenario seeks to find **Improper Input Validation** in the APK file.

CWE-20: Improper Input Validation
==================================

We analyze the definition of CWE-20 and identify its characteristics.

See `CWE-20 <https://cwe.mitre.org/data/definitions/20.html>`_ for more details.

.. image:: https://imgur.com/eO8fepu.jpg

Code of CWE-20 in diva.apk
===========================

We use the `diva.apk <https://github.com/payatu/diva-android>`_ sample to explain the vulnerability code of CWE-20.

.. image:: https://imgur.com/nsuXYGU.jpg

CWE-20 Detection Process Using Quark Script API
================================================

.. image:: https://imgur.com/C7zmwLm.jpg

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``openUrlThatUserInput.json``, to spot the behavior of opening the URL that the user inputs. Then, we use API ``behaviorInstance.getMethodsInArgs()`` to get a list of methods that the URL in ``loadUrl`` passes through. Finally, we check if any validation method is in the list. If No, the APK does not validate user input. That causes CWE-20 vulnerability.

Quark Script CWE-20.py
=======================

.. image:: https://imgur.com/bwPqc4K.jpg

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "diva.apk"
    RULE_PATH = "openUrlThatUserInput.json"

    rule = Rule(RULE_PATH)
    result = runQuarkAnalysis(SAMPLE_PATH, rule)

    VALIDATE_METHODS = ["contains", "indexOf", "matches", "replaceAll"]

    for openUrl in result.behaviorOccurList:
        calledMethods = openUrl.getMethodsInArgs()

        if not any(
            method.methodName in VALIDATE_METHODS for method in calledMethods
        ):
            print(f"CWE-20 is detected in method, {openUrl.methodCaller.fullName}")

Quark Rule: openUrlThatUserInput.json
======================================

.. image:: https://imgur.com/k4WT8Fb.jpg

.. code-block:: json

    {
        "crime": "Open the Url that user input",
        "permission": [],
        "api": [
            {
                "class": "Landroid/widget/EditText;",
                "method": "getText",
                "descriptor": "()Landroid/text/Editable;"
            },
            {
                "class": "Landroid/webkit/WebView;",
                "method": "loadUrl",
                "descriptor": "(Ljava/lang/String;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-20.py
    CWE-20 is detected in method, Ljakhar/aseem/diva/InputValidation2URISchemeActivity; get (Landroid/view/View;)V



Detect CWE-79 in Android Application
-------------------------------------

This scenario seeks to find **Improper Neutralization of Input During Web Page Generation (‘Cross-site Scripting’)** in the APK file.

CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
=============================================================================================

We analyze the definition of CWE-79 and identify its characteristics.

See `CWE-79 <https://cwe.mitre.org/data/definitions/79.html>`_ for more details.

.. image:: https://imgur.com/3W1QpU1.png

Code of CWE-79 in Vuldroid.apk
===============================

We use the `Vuldroid.apk <https://github.com/jaiswalakshansh/Vuldroid>`_ sample to explain the vulnerability code of CWE-79.

.. image:: https://imgur.com/iv3Guwi.png

CWE-79 Detection Process Using Quark Script API
================================================

.. image:: https://imgur.com/MpUjFP0.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``loadUrlFromIntent.json`` to spot the behavior loading URL from intent data to the WebView instance.

Next, we use API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` and ``methodInstance.getArguments()`` to check if the Javascript execution is enabled in the WebView. Finally, we check if there are any famous XSS filters. If **NO**, that may cause CWE-79 vulnerability.

Quark Script CWE-79.py
=======================

.. image:: https://imgur.com/NyMpLZW.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "Vuldroid.apk"
    RULE_PATH = "loadUrlFromIntent.json"

    XSS_FILTERS = [
        [
            "Lorg/owasp/esapi/Validator;",
            "getValidSafeHTML",
            "(Ljava/lang/String; Ljava/lang/String; I Z)Ljava/lang/String;",
        ],
        [
            "Lorg/owasp/esapi/Encoder;",
            "encodeForHTML",
            "(Ljava/lang/String;)Ljava/lang/String;",
        ],
        [
            "Lorg/owasp/esapi/Encoder;",
            "encodeForJavaScript",
            "(Ljava/lang/String;)Ljava/lang/String;",
        ],
        [
            "Lorg/owasp/html/PolicyFactory;",
            "sanitize",
            "(Ljava/lang/String;)Ljava/lang/String;",
        ],
    ]

    targetMethod = ["Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V"]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for loadUrl in quarkResult.behaviorOccurList:
        caller = loadUrl.methodCaller
        setJS = quarkResult.findMethodInCaller(caller, targetMethod)
        enableJS = []

        if setJS:
            enableJS = setJS[0].getArguments()[1]

        if enableJS:
            XSSFiltersInCaller = [
                filterAPI
                for filterAPI in XSS_FILTERS
                if quarkResult.findMethodInCaller(caller, filterAPI)
            ]

            if not XSSFiltersInCaller:
                print(f"CWE-79 is detected in method, {caller.fullName}")

Quark Rule: loadUrlFromIntent.json
===================================

.. image:: https://imgur.com/m4aa4Jk.png

.. code-block:: json

    {
        "crime": "Load URL from intent to WebView",
        "permission": [],
        "api": [
            {
                "descriptor": "()Landroid/net/Uri;",
                "class": "Landroid/content/Intent;",
                "method": "getData"
            },
            {
                "descriptor": "(Ljava/lang/String;)V",
                "class": "Landroid/webkit/WebView;",
                "method": "loadUrl"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-79.py
    CWE-79 is detected in method, Lcom/vuldroid/application/ForgetPassword; onCreate (Landroid/os/Bundle;)V



Detect CWE-328 in Android Application
--------------------------------------

This scenario seeks to find the **Use of Weak Hash**.

CWE-328 Use of Weak Hash
=========================

We analyze the definition of CWE-328 and identify its characteristics.

See `CWE-328 <https://cwe.mitre.org/data/definitions/328.html>`_ for more details.

.. image:: https://imgur.com/DUaOaKi.jpg

Code of CWE-328 in allsafe.apk
===============================

We use the `allsafe.apk <https://github.com/t0thkr1s/allsafe>`_ sample to explain the vulnerability code of CWE-328.

.. image:: https://imgur.com/nyreKX2.jpg

CWE-328 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/bM7WJKo.jpg

Let's use the above APIs to show how the Quark script finds this vulnerability.

First, we use API ``findMethodInAPK(samplePath, targetMethod)`` to find the method ``MessageDigest.getInstance()`` or ``SecretKeyFactory.getInstance()``. Next, we use API ``methodInstance.getArguments()`` with a list to check if the method uses weak hashing algorithms. If **YES**, that causes CWE-328 vulnerability.

Quark Script: CWE-328.py
=========================

.. image:: https://imgur.com/wb9Baa3.jpg

.. code-block:: python

    from quark.script import findMethodInAPK

    SAMPLE_PATH = "./allsafe.apk"

    TARGET_METHODS = [
        [
            "Ljava/security/MessageDigest;",
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/MessageDigest;",
        ],
        [
            "Ljavax/crypto/SecretKeyFactory;",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;",
        ],
    ]

    HASH_KEYWORDS = [
        "MD2",
        "MD4",
        "MD5",
        "PANAMA",
        "SHA0",
        "SHA1",
        "HAVAL128",
        "RIPEMD128",
    ]

    methodsFound = []
    for target in TARGET_METHODS:
        methodsFound += findMethodInAPK(SAMPLE_PATH, target)

    for setHashAlgo in methodsFound:
        algoName = setHashAlgo.getArguments()[0].replace("-", "")

        if any(keyword in algoName for keyword in HASH_KEYWORDS):
            print(
                f"CWE-328 is detected in {SAMPLE_PATH},\n\t"
                f"and it occurs in method, {setHashAlgo.fullName}"
            )

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-328.py
    CWE-328 is detected in ./allsafe.apk,
            and it occurs in method, Linfosecadventures/allsafe/challenges/SQLInjection; md5 (Ljava/lang/String;)Ljava/lang/String;
    CWE-328 is detected in ./allsafe.apk,
            and it occurs in method, Linfosecadventures/allsafe/challenges/WeakCryptography; md5Hash (Ljava/lang/String;)Ljava/lang/String;
    CWE-328 is detected in ./allsafe.apk,
            and it occurs in method, Lcom/google/firebase/database/core/utilities/Utilities; sha1HexDigest (Ljava/lang/String;)Ljava/lang/String;



Detect CWE-295 in Android Application
--------------------------------------

This scenario seeks to find **Improper Certificate Validation**.

CWE-295: Improper Certificate Validation
=========================================

We analyze the definition of CWE-295 and identify its characteristics.

See `CWE-295 <https://cwe.mitre.org/data/definitions/295.html>`_ for more details.

.. image:: https://imgur.com/w6yx17J.jpg

Code of CWE-295 in InsecureShop.apk
====================================

We use the `InsecureShop.apk <https://github.com/hax0rgb/InsecureShop>`_ sample to explain the vulnerability code of CWE-295.

.. image:: https://imgur.com/iBt3mzh.jpg

CWE-295 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/HBBurwx.jpg

To begin with, we use the API ``findMethodInAPK(samplePath, targetMethod)`` to locate all callers of method ``SslErrorHandler.proceed``.

Next, we must verify whether the caller overrides the method ``WebViewClient.onReceivedSslError``.

Therefore, we check if the caller has the same method name and descriptor as ``WebViewClient.onReceivedSslError``, then use ``findSuperclassHierarchy()`` to see if its class extends ``Landroid/webkit/WebViewClient``.

If both are **YES**, the APK will proceed with HTTPS connections without certificate validation when an SSL error occurs, which may cause CWE-295 vulnerability.

Quark Script CWE-295.py
========================

.. image:: https://imgur.com/h9ydW0Y.jpg

.. code-block:: python

    from quark.script import findMethodInAPK

    SAMPLE_PATH = "insecureShop.apk"
    TARGET_METHOD = [
        "Landroid/webkit/SslErrorHandler;",  # class name
        "proceed",                           # method name
        "()V",                               # descriptor
    ]
    OVERRIDDEN_METHOD = [
        "Landroid/webkit/WebViewClient;",    # class name
        "onReceivedSslError",                # method name
        "(Landroid/webkit/WebView;"
        + " Landroid/webkit/SslErrorHandler;"
        + " Landroid/net/http/SslError;)V",  # descriptor
    ]

    for sslProceedCaller in findMethodInAPK(SAMPLE_PATH, TARGET_METHOD):
        if (
            sslProceedCaller.name == OVERRIDDEN_METHOD[1]
            and sslProceedCaller.descriptor == OVERRIDDEN_METHOD[2]
            and OVERRIDDEN_METHOD[0] in sslProceedCaller.findSuperclassHierarchy()
        ):
            print(f"CWE-295 is detected in method, {sslProceedCaller.fullName}")

Quark Script Result
====================

.. code-block:: TEXT

    $　python3 CWE-295.py
    CWE-295 is detected in method, Lcom/insecureshop/util/CustomWebViewClient; onReceivedSslError (Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V



Detect CWE-489 in Android Application
--------------------------------------

This scenario seeks to find **active debug code**.

CWE-489: Active Debug Code
===========================

We analyze the definition of CWE-489 and identify its characteristics.

See `CWE-489 <https://cwe.mitre.org/data/definitions/489.html>`_ for more details.

.. image:: https://imgur.com/UuDNFXW.jpg

Code of CWE-489 in allsafe.apk
===============================

We use the `allsafe.apk <https://github.com/t0thkr1s/allsafe>`_ sample to explain the vulnerability code of CWE-489.

.. image:: https://imgur.com/QSrATmt.jpg

CWE-489 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/ydGfkV4.jpg

First, we use Quark API ``getApplication(samplePath)`` to get the application element in the manifest file. Then we use ``applicationInstance.isDebuggable()`` to check if the application element sets the attribute ``android:debuggable`` to true. If **Yes**, that causes CWE-489 vulnerabilities.

Quark Script CWE-489.py
========================

.. image:: https://imgur.com/ToCAmD3.jpg

.. code-block:: python

    from quark.script import getApplication

    SAMPLE_PATH = "allsafe.apk"

    if getApplication(SAMPLE_PATH).isDebuggable():
        print(f"CWE-489 is detected in {SAMPLE_PATH}.")

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-489.py
    CWE-489 is detected in allsafe.apk.



Detect CWE-22 in Android Application
-------------------------------------

This scenario seeks to find **the improper limitation of a pathname to a restricted directory (‘Path Traversal’)**.

CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
=======================================================================================

We analyze the definition of CWE-22 and identify its characteristics.

See `CWE-22 <https://cwe.mitre.org/data/definitions/22.html>`_ for more details.

.. image:: https://imgur.com/XnOUZsV.png

Code of CWE-22 in ovaa.apk
===========================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-22.

.. image:: https://imgur.com/bgWgeT7.png

CWE-22 Detection Process Using Quark Script API
================================================

.. image:: https://imgur.com/N69bQK2.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``accessFileInExternalDir.json`` to spot behavior accessing a file in an external directory.

Next, we use API ``methodInstance.getArguments()`` to get the argument for the file path and use ``quarkResultInstance.isHardcoded(argument)`` to check if the argument is hardcoded into the APK. If **No**, the argument is from external input.

Finally, we use Quark API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` to check if there are any APIs in the caller method for string matching. If **NO**, the APK does not neutralize special elements within the argument, which may cause CWE-22 vulnerability.

Quark Scipt: CWE-22.py
=======================

.. image:: https://imgur.com/4b2e4tN.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "accessFileInExternalDir.json"


    STRING_MATCHING_API = [
        ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
        ["Ljava/lang/String;", "indexOf", "(I)I"],
        ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
        ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
    ]


    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for accessExternalDir in quarkResult.behaviorOccurList:

        filePath = accessExternalDir.secondAPI.getArguments()[2]

        if quarkResult.isHardcoded(filePath):
            continue

        caller = accessExternalDir.methodCaller
        strMatchingAPIs = [
                api for api in STRING_MATCHING_API if quarkResult.findMethodInCaller(
                    caller, api)
        ]

        if not strMatchingAPIs:
            print(f"CWE-22 is detected in method, {caller.fullName}")

Quark Rule: accessFileInExternalDir.json
=========================================

.. image:: https://imgur.com/N2uKsZj.png

.. code-block:: json

    {
        "crime": "Access a file in an external directory",
        "permission": [],
        "api": [
            {
                "class": "Landroid/os/Environment;",
                "method": "getExternalStorageDirectory",
                "descriptor": "()Ljava/io/File;"
            },
            {
                "class": "Ljava/io/File;",
                "method": "<init>",
                "descriptor": "(Ljava/io/File;Ljava/lang/String;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-22.py
    CWE-22 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;




Detect CWE-23 in Android Application
-------------------------------------

This scenario aims to demonstrate the detection of the **Relative Path Traversal** vulnerability.

CWE-23: Relative Path Traversal
================================

We analyze the definition of CWE-23 and identify its characteristics.

See `CWE-23 <https://cwe.mitre.org/data/definitions/23.html>`_ for more details.

.. image:: https://imgur.com/k4UPsKO.png

Code of CWE-23 in ovaa.apk
===========================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-23.

.. image:: https://imgur.com/KT277GG.png

CWE-23 Detection Process Using Quark Script API
================================================

.. image:: https://imgur.com/D852ZLV.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we create a detection rule named ``accessFileInExternalDir.json`` to identify behavior that accesses a file in an external directory.

Next, we use ``methodInstance.getArguments()`` to retrieve the file path argument and check whether it belongs to the APK. If it does not belong to the APK, the argument is likely from external input.

Then, we use the Quark Script API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` to search for any APIs in the caller method that are used to match strings. If no API is found, that implies the APK does not neutralize special elements within the argument, possibly resulting in CWE-23 vulnerability.

Quark Script: CWE-23.py
========================

.. image:: https://imgur.com/lk1C4CX.jpg

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "accessFileInExternalDir.json"


    STRING_MATCHING_API = [
        ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
        ["Ljava/lang/String;", "indexOf", "(I)I"],
        ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
        ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
        [
            "Ljava/lang/String;",
            "replaceAll",
            "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;",
        ],
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for accessExternalDir in quarkResult.behaviorOccurList:

        filePath = accessExternalDir.secondAPI.getArguments()[2]

        if quarkResult.isHardcoded(filePath):
            continue

        caller = accessExternalDir.methodCaller
        strMatchingAPIs = [
            api
            for api in STRING_MATCHING_API
            if quarkResult.findMethodInCaller(caller, api)
        ]

        if not strMatchingAPIs:
            print(f"CWE-23 is detected in method, {caller.fullName}")

Quark Rule: accessFileInExternalDir.json
=========================================

.. image:: https://imgur.com/N2uKsZj.png

.. code-block:: json

    {
        "crime": "Access a file in an external directory",
        "permission": [],
        "api": [
            {
                "class": "Landroid/os/Environment;",
                "method": "getExternalStorageDirectory",
                "descriptor": "()Ljava/io/File;"
            },
            {
                "class": "Ljava/io/File;",
                "method": "<init>",
                "descriptor": "(Ljava/io/File;Ljava/lang/String;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-23.py
    CWE-23 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;





Detect CWE-338 in Android Application
--------------------------------------

This scenario seeks to find **Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)**.

CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
=============================================================================

We analyze the definition of CWE-338 and identify its characteristics.

See `CWE-338 <https://cwe.mitre.org/data/definitions/338.html>`_ for more details.

.. image:: https://imgur.com/aLybax5.jpg

Code of CWE-338 in pivaa.apk
=============================

We use the `pivaa.apk <https://github.com/HTBridge/pivaa>`_ sample to explain the vulnerability code of CWE-338.

.. image:: https://i.postimg.cc/mr5rpTDz/image.png

CWE-338 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/yWLNwZV.jpg

First, we design a detection rule ``useMethodOfPRNG.json`` to spot on behavior that uses Pseudo Random Number Generator (PRNG). Then, we use API ``methodInstance.getXrefFrom()`` to get the caller method of PRNG. Finally, we use some keywords such as "token", "password", and "encrypt" to check if the PRNG is for credential usage.

Quark Script CWE-338.py
========================

.. image:: https://i.postimg.cc/xdt54Lft/image.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "pivaa.apk"
    RULE_PATH = "useMethodOfPRNG.json"

    CREDENTIAL_KEYWORDS = [
        "token", "password", "account", "encrypt",
        "authentication", "authorization", "id", "key"
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for usePRNGMethod in quarkResult.behaviorOccurList:
        for prngCaller in usePRNGMethod.methodCaller.getXrefFrom():
            if any(
                keyword in prngCaller.fullName for keyword in CREDENTIAL_KEYWORDS
            ):
                print("CWE-338 is detected in %s" % prngCaller.fullName)
    
Quark Rule: useMethodOfPRNG.json
=================================

.. image:: https://i.postimg.cc/jS6x74Kg/image.png

.. code-block:: json

    {
        "crime": "Use method of PRNG",
        "permission": [],
        "api": [
            {
                "class": "Ljava/util/Random;",
                "method": "<init>",
                "descriptor": "()V"
            },
            {
                "class": "Ljava/util/Random;",
                "method": "nextInt",
                "descriptor": "(I)I"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-338.py
    CWE-338 is detected in Lcom/htbridge/pivaa/EncryptionActivity$2; onClick (Landroid/view/View;)V

    


Detect CWE-88 in Android Application 
--------------------------------------

This scenario seeks to find **Argument Injection** in the APK file.

CWE-88 Improper Neutralization of Argument Delimiters in a Command
===================================================================

We analyze the definition of CWE-88 and identify its characteristics.

See `CWE-88 <https://cwe.mitre.org/data/definitions/88.html>`_ for more details.

.. image:: https://imgur.com/5vfXkIE.png

Code of CWE-88 in vuldroid.apk
===============================

We use the `vuldroid.apk <https://github.com/jaiswalakshansh/Vuldroid>`_ sample to explain the vulnerability code of CWE-88.

.. image:: https://imgur.com/recX0t5.png

CWE-88 Detection Process Using Quark Script API
================================================

.. image:: https://imgur.com/s7Ajr6M.png

Let‘s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``ExternalStringsCommands.json`` to spot on behavior using external strings as commands.

Next, we use Quark API ``behaviorInstance.getMethodsInArgs()`` to get the methods that passed the external command.

Then we check if the method neutralizes any special elements in the argument.

If the neutralization is not complete, then it may cause CWE-88 vulnerability.

Quark Script: CWE-88.py
========================

.. image:: https://imgur.com/f8Yee3P.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule, findMethodInAPK

        SAMPLE_PATH = "Vuldroid.apk"
        RULE_PATH = "ExternalStringCommand.json"


        STRING_MATCHING_API = set([
            ("Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"),
            ("Ljava/lang/String;", "indexOf", "(I)I"),
            ("Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"),
            ("Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"),
            ("Ljava/lang/String;", "replaceAll", "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;")
        ])

        delimeter = "-"

        ruleInstance = Rule(RULE_PATH)
        quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

        for ExternalStringCommand in quarkResult.behaviorOccurList:

            methodCalled = set()
            caller = ExternalStringCommand.methodCaller

            for method in ExternalStringCommand.getMethodsInArgs():
                methodCalled.add(method.fullName)

            if methodCalled.intersection(STRING_MATCHING_API) and not ExternalStringCommand.hasString(delimeter):
                continue
            else:
                print(f"CWE-88 is detected in method, {caller.fullName}")


Quark Rule: ExternalStringCommand.json
=======================================

.. image:: https://imgur.com/s9QNF19.png

.. code-block:: json

    {
        "crime": "Using external strings as commands",
        "permission": [],
        "api": [
            {
                "class": "Landroid/content/Intent;",
                "method": "getStringExtra",
                "descriptor": "(Ljava/lang/String;)Ljava/lang/String"
            },
            {
                "class": "Ljava/lang/Runtime;",
                "method": "exec",
                "descriptor": "(Ljava/lang/String;)Ljava/lang/Process"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-88.py
    CWE-88 is detected in method, Lcom/vuldroid/application/RootDetection; onCreate (Landroid/os/Bundle;)V



Detect CWE-925 in Android Application
--------------------------------------

This scenario seeks to find **Improper Verification of Intent by Broadcast Receiver** in the APK file.

CWE-925 Improper Verification of Intent by Broadcast Receiver
==============================================================

We analyze the definition of CWE-925 and identify its characteristics.

See `CWE-925 <https://cwe.mitre.org/data/definitions/925.html>`_ for more details.

.. image:: https://imgur.com/fMZ2bMN.jpg

Code of CWE-925 in InsecureBankv2.apk
======================================

We use the `InsecureBankv2.apk <https://github.com/dineshshetty/Android-InsecureBankv2>`_ sample to explain the vulnerability code of CWE-925.

.. image:: https://imgur.com/V7VtL3x.jpg


CWE-925 Detection Process Using Quark Script API
=================================================

.. image:: https://i.postimg.cc/Ls0Kw749/2025-09-17-4-19-22.png

First, we use API ``getReceivers(samplePath)`` and ``receiverInstance.isExported()`` to find all the exported receivers defined in the APK.

Second, we use API ``checkMethodCalls(samplePath, targetMethod, checkMethods)`` to check if the ``onReceive`` method of every exported receiver obtains an intent action.

If **No**, it could imply that the APK does not verify intent properly, potentially leading to a CWE-925 vulnerability.


Quark Script CWE-925.py
========================

.. image:: https://i.postimg.cc/dQhts2gN/2025-09-17-4-17-51.png

.. code-block:: python

    from quark.script import checkMethodCalls, getReceivers

    sample_path = "InsecureBankv2.apk"

    TARGET_METHOD = [
        '',
        'onReceive',
        '(Landroid/content/Context; Landroid/content/Intent;)V'
    ]

    CHECK_METHODS = [
        ['Landroid/content/Intent;', 'getAction', '()Ljava/lang/String;']
    ]

    receivers = getReceivers(sample_path)
    for receiver in receivers:
        if receiver.isExported():
            className = "L"+str(receiver).replace('.', '/')+';'
            TARGET_METHOD[0] = className
            if not checkMethodCalls(sample_path, TARGET_METHOD, CHECK_METHODS):
                print(f"CWE-925 is detected in method, {className}")

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-925.py
    CWE-925 is detected in method, Lcom/android/insecurebankv2/MyBroadCastReceiver;



Detect CWE-73 in Android Application 
--------------------------------------

This scenario seeks to find **External Control of File Name or Path** in the APK file.

CWE-73 External Control of File Name or Path
=============================================

We analyze the definition of CWE-73 and identify its characteristics.

See `CWE-73 <https://cwe.mitre.org/data/definitions/73.html>`_ for more details.

.. image:: https://imgur.com/I1C5yku.png

Code of CWE-73 in ovaa.apk
===========================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-73.

.. image:: https://imgur.com/gLJ6zWr.png

CWE-73 Detection Process Using Quark Script API
================================================

.. image:: https://imgur.com/zGjZHA1.png

Let’s use the above APIs to show how Quark script finds this vulnerability.

First, we design a detection rule ``useLastPathSegmentAsFileName.json`` to spot behavior that uses the last path segment as the file name.

Second, we use the API ``methodInstance.getArguments()`` to get the argument for the file path and use ``quarkResultInstance.isHardcoded(argument)`` to check if the argument is hardcoded into the APK. If **No**, the argument is from external input.

Finally, we use Quark API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` to check if there are any APIs in the caller method for opening files. If **YES**, the APK performs file operations using external input as a path, which may cause CWE-73 vulnerability.

Quark Script: CWE-73.py
========================

.. image:: https://imgur.com/EHrcCPg.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "useLastPathSegmentAsFileName.json"

    OPEN_FILE_API = [
        "Landroid/os/ParcelFileDescriptor;",                   # Class name
        "open",                                                # Method name
        "(Ljava/io/File; I)Landroid/os/ParcelFileDescriptor;"  # Descriptor
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for accessExternalDir in quarkResult.behaviorOccurList:
        filePath = accessExternalDir.secondAPI.getArguments()[2]

        if quarkResult.isHardcoded(filePath):
            continue

        caller = accessExternalDir.methodCaller
        result = quarkResult.findMethodInCaller(caller, OPEN_FILE_API)

        if result:
            print("CWE-73 is detected in method, ", caller.fullName)

Quark Rule: useLastPathSegmentAsFileName.json
==============================================

.. image:: https://imgur.com/JxBdde0.png

.. code-block:: json

    {
        "crime": "Use the last path segment as the file name",
        "permission": [],
        "api": [
            {
                "class": "Landroid/net/Uri;",
                "method": "getLastPathSegment",
                "descriptor": "()Ljava/lang/String;"
            },
            {
                "class": "Ljava/io/File;",
                "method": "<init>",
                "descriptor": "(Ljava/io/File;Ljava/lang/String;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-73.py
    CWE-73 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;

   

Detect CWE-78 in Android Application
-------------------------------------

This scenario seeks to find **Improper Neutralization of Special Elements used in an OS Command** in the APK file.

CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
==================================================================================================

We analyze the definition of CWE-78 and identify its characteristics.

See `CWE-78 <https://cwe.mitre.org/data/definitions/78.html>`_ for more details.

.. image:: https://imgur.com/HpMGGsO.png

Code of CWE-78 in Vuldroid.apk
===============================

We use the `Vuldroid.apk <https://github.com/jaiswalakshansh/Vuldroid>`_ sample to explain the vulnerability code of CWE-78.

.. image:: https://imgur.com/7Tu0Y3H.png

CWE-78 Detection Process Using Quark Script API
================================================

.. image:: https://imgur.com/Hi7qGjw.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``ExternalStringsCommands.json`` to spot on behavior using external strings as commands.

Next, we use Quark API ``behaviorInstance.getMethodsInArgs()`` to get the methods that passed the external command.

Then we check if the method neutralizes any special elements in the argument.

If the neutralization is not complete, then it may cause CWE-78 vulnerability.

Quark Script: CWE-78.py
========================

.. image:: https://imgur.com/UpRWgGe.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule, findMethodInAPK

    SAMPLE_PATH = "Vuldroid.apk"
    RULE_PATH = "ExternalStringCommand.json"


    STRING_MATCHING_API = set([
        ("Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"),
        ("Ljava/lang/String;", "indexOf", "(I)I"),
        ("Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"),
        ("Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"),
        (
            "Ljava/lang/String;",
            "replaceAll",
            "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;",
        ),
    ])

    specialElementsPattern = r"[ ;|,>`]+"

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for ExternalStringCommand in quarkResult.behaviorOccurList:

        methodCalled = set()
        caller = ExternalStringCommand.methodCaller

        for method in ExternalStringCommand.getMethodsInArgs():
            methodCalled.add(method.fullName)

        if methodCalled.intersection(STRING_MATCHING_API) and not ExternalStringCommand.hasString(specialElementsPattern):
            continue
        else:
            print(f"CWE-78 is detected in method, {caller.fullName}")
        
Quark Rule: ExternalStringCommand.json
=======================================

.. image:: https://imgur.com/eoV8hnZ.png

.. code-block:: json

    {
        "crime": "Using external strings as commands",
        "permission": [],
        "api": [
            {
                "class": "Landroid/content/Intent;",
                "method": "getStringExtra",
                "descriptor": "(Ljava/lang/String;)Ljava/lang/String"
            },
            {
                "class": "Ljava/lang/Runtime;",
                "method": "exec",
                "descriptor": "(Ljava/lang/String;)Ljava/lang/Process"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-78.py
    CWE-78 is detected in method, Lcom/vuldroid/application/RootDetection; onCreate (Landroid/os/Bundle;)V




Detect CWE-117 in Android Application
--------------------------------------

This scenario seeks to find **Improper Output Neutralization for Logs**.

CWE-117: Improper Output Neutralization for Logs
=================================================

We analyze the definition of CWE-117 and identify its characteristics.

See `CWE-117 <https://cwe.mitre.org/data/definitions/117.html>`_ for more details.

.. image:: https://imgur.com/JEAyEsU.jpg

Code of CWE-117 in allsafe.apk
===============================

We use the `allsafe.apk <https://github.com/t0thkr1s/allsafe>`_ sample to explain the vulnerability code of CWE-117.

.. image:: https://imgur.com/ueePFNu.jpg

CWE-117 Detection Process Using Quark Script API
=================================================

.. image:: https://imgur.com/Y5hd4Uc.jpg

First, we design a detection rule ``writeContentToLog.json`` to spot on behavior using the method that writes contents to the log file.

Then, we use ``methodInstance.getArguments()`` to get all parameter values of this method. And we check if these parameters contain keywords of APIs for neutralization, such as ``escape``, ``replace``, ``format``, and ``setFilter``.

If the answer is **YES**, that may result in secret context leakage into the log file, or the attacker may perform log forging attacks.

Quark Script CWE-117.py
========================

.. image:: https://imgur.com/F1X3qg3.jpg

.. code-block:: python

    from quark.script import Rule, runQuarkAnalysis

    SAMPLE_PATH = "allsafe.apk"
    RULE_PATH = "writeContentToLog.json"
    KEYWORDS_FOR_NEUTRALIZATION = ["escape", "replace", "format", "setFilter"]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for logOutputBehavior in quarkResult.behaviorOccurList:

        secondAPIParam = logOutputBehavior.secondAPI.getArguments()

        isKeywordFound = False
        for keyword in KEYWORDS_FOR_NEUTRALIZATION:
            if keyword in secondAPIParam:
                isKeywordFound = True
                break

        if not isKeywordFound:
            caller = logOutputBehavior.methodCaller.fullName
            print(f"CWE-117 is detected in method, {caller}")

Quark Rule: writeContentToLog.json
===================================

.. image:: https://imgur.com/hC4zGgT.jpg

.. code-block:: json

    {
        "crime": "Write contents to the log",
        "permission": [],
        "api": [
            {
                "descriptor": "()Landroid/text/Editable;",
                "class": "Lcom/google/android/material/textfield/TextInputEditText;",
                "method": "getText"
            },
            {
                "descriptor": "(Ljava/lang/String;Ljava/lang/String;)I",
                "class": "Landroid/util/Log;",
                "method": "d"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-117.py
    CWE-117 is detected in method, Linfosecadventures/allsafe/challenges/InsecureLogging; lambda$onCreateView$0 (Lcom/google/android/material/textfield/TextInputEditText; Landroid/widget/TextView; I Landroid/view/KeyEvent;)Z



Detect CWE-940 in Android Application
--------------------------------------

This scenario seeks to find the **Improper Verification of Source of a Communication Channel** in the APK file.

CWE-940: Improper Verification of Source of a Communication Channel
====================================================================

We analyze the definition of CWE-940 and identify its characteristics.

See `CWE-940 <https://cwe.mitre.org/data/definitions/940.html>`_ for more details.

.. image:: https://imgur.com/wia3OKo.png

Code of CWE-940 in ovaa.apk
============================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-940.

.. image:: https://imgur.com/1zP5xkN.png

CWE-940 Detection Process Using Quark Script API
=================================================

.. image:: https://i.postimg.cc/1XGWt89Q/jie-tu-2025-11-21-xia-wu4-46-36.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we create a detection rule named ``LoadUrlFromIntent.json`` to identify behavior that loads URLs from intent data to the ``WebView``.

Next, we retrieve the methods that pass the URL. Then, we check if these methods are only for getting the URL, such as ``findViewById``, ``getStringExtra``, or ``getIntent``.

If **YES**, it could imply that the APK uses communication channels without proper verification, which may cause CWE-940 vulnerability.

Quark Script: CWE-940.py
=========================

.. image:: https://i.postimg.cc/pLTZNG5J/jie-tu-2025-11-21-xia-wu4-47-11.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "LoadUrlFromIntent.json"

    URL_GETTING_METHODS = [
        "findViewById",
        "getStringExtra",
        "getIntent",
    ]

    ruleInstance = Rule(RULE_PATH)

    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for behaviorInstance in quarkResult.behaviorOccurList:
        methodsInArgs = behaviorInstance.getMethodsInArgs()

        verifiedMethodCandidates = []

        for method in methodsInArgs:
            if method.methodName not in URL_GETTING_METHODS:
                verifiedMethodCandidates.append(method)

        if verifiedMethodCandidates == []:
            caller = behaviorInstance.methodCaller.fullName
            print(f"CWE-940 is detected in method, {caller}")

Quark Rule: LoadUrlFromIntent.json
===================================

.. code-block:: json

    {
        "crime": "Load Url from Intent",
        "permission": [],
        "api": [
            {
                "class": "Landroid/content/Intent;",
                "method": "getStringExtra",
                "descriptor": "(Ljava/lang/String;)Ljava/lang/String"
            },
            {
                "class": "Landroid/webkit/WebView;",
                "method": "loadUrl",
                "descriptor": "(Ljava/lang/String;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-940.py
    CWE-940 is detected in method, Loversecured/ovaa/activities/WebViewActivity; onCreate (Landroid/os/Bundle;)V


Detect CWE-502 in Android Application
--------------------------------------

This scenario seeks to find **Deserialization of Untrusted Data** in the APK file.

CWE-502: Deserialization of Untrusted Data
===========================================

We analyze the definition of CWE-502 and identify its characteristics.

See `CWE-502 <https://cwe.mitre.org/data/definitions/502.html>`_ for more details.

.. image:: https://i.postimg.cc/YSyQsgGf/image.png

Code of CWE-502 in pivaa.apk
=============================

We use the `pivaa.apk <https://github.com/htbridge/pivaa>`_ sample to explain the vulnerability code of CWE-502.

.. image:: https://i.postimg.cc/XJdXkywv/image.png

CWE-502 Detection Process Using Quark Script API
=================================================

.. image:: https://i.postimg.cc/mkV97HsH/image.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we created a detection rule named ``deserializeData.json`` to identify behaviors that deserialize data.

Next, we retrieve the methods that interact with the deserialization API. Following this, we check if the methods match any APIs for verifying data.

If **NO**, it could imply that the APK deserializes the untrusted data, potentially leading to a CWE-502 vulnerability.

Quark Script CWE-502.py
========================

.. image:: https://i.postimg.cc/vTmXSj7g/image.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "pivaa.apk"
    RULE_PATH = "deserializeData.json"

    ruleInstance = Rule(RULE_PATH)

    result = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    verificationApis = [
        ["Ljava/io/File;", "exists", "()Z"],
        ["Landroid/content/Context;", "getFilesDir", "()Ljava/io/File;"],
        ["Landroid/content/Context;", "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;"],
        ["Landroid/os/Environment;", "getExternalStorageDirectory", "()Ljava/io/File;"],
    ]

    for dataDeserialization in result.behaviorOccurList:
        apis = dataDeserialization.getMethodsInArgs()
        caller = dataDeserialization.methodCaller
        if not any(api in apis for api in verificationApis):
            print(f"CWE-502 is detected in method, {caller.fullName}")

Quark Rule: deserializeData.json
=================================

.. image:: https://i.postimg.cc/FsdDQm7r/image.png

.. code-block:: json

    {
        "crime": "Deserialize Data",
        "permission": [],
        "api": [

            {
                "class": "Ljava/io/ObjectInputStream;",
                "method": "<init>",
                "descriptor": "(Ljava/io/InputStream;)V"
            },
            {
                "class": "Ljava/io/ObjectInputStream;",
                "method": "readObject",
                "descriptor": "()Ljava/lang/Object;"
            }

        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-502.py
    CWE-502 is detected in method, Lcom/htbridge/pivaa/handlers/ObjectSerialization; loadObject ()V



Detect CWE-601 in Android Application
--------------------------------------

This scenario seeks to find **URL Redirection to Untrusted Site** in the APK file.

CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
=============================================================

We analyze the definition of CWE-601 and identify its characteristics.

See `CWE-601 <https://cwe.mitre.org/data/definitions/601.html>`_ for more details.

.. image:: https://imgur.com/sgRhcel.png

Code of CWE-601 in ovaa.apk
=========================================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-601.

.. image:: https://i.postimg.cc/hjqKnKLN/2025-10-08-1-12-43.png


CWE-601 Detection Process Using Quark Script API
=================================================

.. image:: https://i.postimg.cc/q75yxptk/2025-10-09-9-14-34.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To detect the vulnerability, we use the API ``findMethodInAPK(samplePath, targetMethod)`` to find all the caller methods of ``startActivity``. Next, we examine the arguments of each method to discover the methods receiving external input. If a method receives external input but lacks proper input validation, the CWE-601 vulnerability is identified.


Quark Script: CWE-601.py
========================

.. image:: https://i.postimg.cc/wTwvm0Rm/2025-10-09-9-18-38.png

.. code-block:: python

    from quark.script import findMethodInAPK

    SAMPLE_PATH = 'ovaa.apk'

    # This is the input for findMethodInAPK, formatted as class name, method name, descriptor
    TARGET_METHOD = ["", "startActivity", "(Landroid/content/Intent;)V"]

    """
    Due to varying descriptors and classes in smali code from different APIs,
    our search relies solely on the consistent method names.
    """

    EXTERNAL_INPUT_METHODS = ["getIntent", "getQueryParameter"]

    INPUT_FILTER_METHODS = [
        "parse",
        "isValidUrl",
        "Pattern",
        "Matcher",
        "encode",
        "decode",
        "escapeHtml",
        "HttpURLConnection",
    ]

    redirectMethods = findMethodInAPK(SAMPLE_PATH, TARGET_METHOD)

    for redirectMethod in redirectMethods:
        arguments = redirectMethod.getArguments()
        for argument in arguments:
            if any(
                externalInput in argument
                for externalInput in EXTERNAL_INPUT_METHODS
            ):
                if not any(
                    filterMethod in argument
                    for filterMethod in INPUT_FILTER_METHODS
                ):
                    print(f"CWE-601 is detected in {redirectMethod.fullName}")

Quark Script Result
======================

.. code-block:: TEXT

    $ python CWE-601.py
    CWE-601 is detected in Loversecured/ovaa/activities/DeeplinkActivity; processDeeplink (Landroid/net/Uri;)V
    CWE-601 is detected in Loversecured/ovaa/activities/LoginActivity; onLoginFinished ()V



Detect CWE-329 in Android Application
-------------------------------------

This scenario seeks to find **Generation of Predictable IV with CBC Mode** in the APK file.

CWE-329: Generation of Predictable IV with CBC Mode
===================================================

We analyze the definition of CWE-329 and identify its characteristics.

See `CWE-329 <https://cwe.mitre.org/data/definitions/329.html>`_ for more details.


.. image:: https://i.postimg.cc/ZY6WjB5z/Screenshot-2025-07-11-17-13-40.png
   :target: https://i.postimg.cc/ZY6WjB5z/Screenshot-2025-07-11-17-13-40.png
   :alt:


Code of CWE-329 in InsecureBankv2.apk
========================================

We use the `InsecureBankv2.apk <https://github.com/dineshshetty/Android-InsecureBankv2>`_ sample to explain the vulnerability code of CWE-329.


.. image:: https://i.postimg.cc/LXgBX9SB/Screenshot-2025-07-11-17-46-25.png
   :target: https://i.postimg.cc/LXgBX9SB/Screenshot-2025-07-11-17-46-25.png
   :alt:


CWE-329 Detection Process Using Quark Script API
================================================


.. image:: https://i.postimg.cc/50cscyh2/Screenshot-2025-07-12-10-02-34.png
   :target: https://i.postimg.cc/50cscyh2/Screenshot-2025-07-12-10-02-34.png
   :alt:


Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we created a detection rule named ``initializeCipherWithIV.json`` to identify behaviors that initialize a cipher object with IV. Then, we use API ``behaviorInstance.getParamValues()`` to check if the cipher object uses CBC mode.

Finally, we use API ``behaviorInstance.isArgFromMethod(targetMethod)``  to check if any random API is applied on the IV used in the cipher object. If **NO**\ , it could imply that the APK uses a predictable IV in CBC mode cipher, potentially leading to a CWE-329 vulnerability.

Quark Script CWE-329.py
=======================


.. image:: https://i.postimg.cc/prCCnZpm/Screenshot-2025-07-12-10-02-58.png
   :target: https://i.postimg.cc/prCCnZpm/Screenshot-2025-07-12-10-02-58.png
   :alt:


.. code-block:: python

   from quark.script import runQuarkAnalysis, Rule

   SAMPLE_PATH = "InsecureBankv2.apk"
   RULE_PATH = "initializeCipherWithIV.json"

   randomAPIs = [
       ["Ljava/security/SecureRandom", "next", "(I)I"],
       ["Ljava/security/SecureRandom", "nextBytes", "([B)V"],
   ]

   ruleInstance = Rule(RULE_PATH)
   quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

   for initCipherWithIV in quarkResult.behaviorOccurList:
       methodcaller = initCipherWithIV.methodCaller
       cipherName = initCipherWithIV.getParamValues()[0]

       if "CBC" not in cipherName:
           break

       if not any(
           initCipherWithIV.isArgFromMethod(api) for api in randomAPIs
       ):
           print(f"CWE-329 is detected in method, {methodcaller.fullName}")

Quark Rule: initializeCipherWithIV.json
=======================================


.. image:: https://i.postimg.cc/Y9tM29YT/Screenshot-2025-07-11-17-49-41.png
   :target: https://i.postimg.cc/Y9tM29YT/Screenshot-2025-07-11-17-49-41.png
   :alt:


.. code-block:: json

   {
       "crime": "Initialize a cipher object with IV",
       "permission": [],
       "api": [
           {
               "class": "Ljavax/crypto/spec/IvParameterSpec;",
               "method": "<init>",
               "descriptor": "([B)V"
           },
           {
               "class": "Ljavax/crypto/Cipher;",
               "method": "init",
               "descriptor": "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"
           }
       ],
       "score": 1,
       "label": []
   }

Quark Script Result
===================

.. code-block:: text

   $ python CWE-329.py
   CWE-329 is detected in method, Lcom/google/android/gms/internal/zzar; zzc ([B Ljava/lang/String;)[B
   CWE-329 is detected in method, Lcom/android/insecurebankv2/CryptoClass; aes256encrypt ([B [B [B)[B
   CWE-329 is detected in method, Lcom/android/insecurebankv2/CryptoClass; aes256decrypt ([B [B [B)[B




Detect CWE-297 in Android Application
--------------------------------------

This scenario seeks to find **Improper Validation of Certificate with Host Mismatch**.

CWE-297: Improper Validation of Certificate with Host Mismatch
===============================================================

We analyze the definition of CWE-297 and identify its characteristics.

See `CWE-297 <https://cwe.mitre.org/data/definitions/297.html>`_ for more details.

.. image:: https://i.postimg.cc/PrpC3vgy/image.png

Code of CWE-297 in pivaa.apk
=============================

We use the `pivaa.apk <https://github.com/htbridge/pivaa>`_ sample to explain the vulnerability code of CWE-297.

.. image:: https://i.postimg.cc/wT29kqv2/image.png

CWE-297 Detection Process Using Quark Script API
=================================================

.. image:: https://i.postimg.cc/ryYJRWGN/image.png

First, we use API ``findMethodImpls(samplePath, targetMethod)`` to locate the method that implements the hostname verification, which verifies the hostname of a certificate.

Next, we use API ``isMethodReturnAlwaysTrue(samplePath, targetMethod)`` to check if the method always returns true.

If the answer is **YES**, the method does not check the certificate of the host properly, which may cause CWE-297 vulnerability.

Quark Script CWE-297.py
========================

.. image:: https://i.postimg.cc/Dw311cSL/image.png

.. code-block:: python

    from quark.script import findMethodImpls, isMethodReturnAlwaysTrue

    SAMPLE_PATH = "pivaa.apk"

    ABSTRACT_METHOD = [
        "Ljavax/net/ssl/HostnameVerifier;",
        "verify",
        "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
    ]

    for hostVerification in findMethodImpls(SAMPLE_PATH, ABSTRACT_METHOD):
        methodImpls = [
            hostVerification.className,
            hostVerification.methodName,
            hostVerification.descriptor
        ]
        if isMethodReturnAlwaysTrue(SAMPLE_PATH, methodImpls):
            print(f"CWE-297 is detected in method, {hostVerification.fullName}")

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-297.py
    CWE-297 is detected in method, Lcom/htbridge/pivaa/handlers/API$1; verify (Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z



Detect CWE-1204 in Android Application
---------------------------------------

This scenario seeks to find **Generation of Weak Initialization Vector (IV)**.

CWE-1204: Generation of Weak Initialization Vector (IV)
========================================================

We analyze the definition of CWE-1204 and identify its characteristics.

See `CWE-1204 <https://cwe.mitre.org/data/definitions/1204.html>`_ for more details.

.. image:: https://i.postimg.cc/3NNmYz6J/image.png

Code of CWE-1204 in InsecureBankv2.apk
=======================================

We use the `InsecureBankv2.apk <https://github.com/dineshshetty/Android-InsecureBankv2>`_ sample to explain the vulnerability code of CWE-1204.

.. image:: https://i.postimg.cc/rsHWmQXG/image.png


CWE-1204 Detection Process Using Quark Script API
==================================================

.. image:: https://i.postimg.cc/jq3yZdwW/image.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we created a detection rule named ``initializeCipherWithIV.json`` to identify behaviors that initialize a cipher object with IV.

Then, we use API ``behaviorInstance.isArgFromMethod(targetMethod)`` to check if any random API is applied on the IV used in the cipher object. If **NO**, it could imply that the APK uses a weak IV, potentially leading to a CWE-1204 vulnerability.

Quark Scipt: CWE-1204.py
=========================

.. image:: https://i.postimg.cc/Hxs79fT4/image.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "InsecureBankv2.apk"
    RULE_PATH = "initializeCipherWithIV.json"

    randomAPIs = [
        ["Ljava/security/SecureRandom", "next", "(I)I"],
        ["Ljava/security/SecureRandom", "nextBytes", "([B)V"],
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for initCipherWithIV in quarkResult.behaviorOccurList:
        methodcaller = initCipherWithIV.methodCaller

        if not any(
            initCipherWithIV.isArgFromMethod(api) for api in randomAPIs
        ):
            print(f"CWE-1204 is detected in method, {methodcaller.fullName}")

Quark Rule: initializeCipherWithIV.json
========================================

.. image:: https://i.postimg.cc/kGL69GKf/image.png

.. code-block:: json

    {
        "crime": "Initialize a cipher object with IV",
        "permission": [],
        "api": [
            {
                "class": "Ljavax/crypto/spec/IvParameterSpec;",
                "method": "<init>",
                "descriptor": "([B)V"
            },
            {
                "class": "Ljavax/crypto/Cipher;",
                "method": "init",
                "descriptor": "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python CWE-1204.py
    CWE-1204 is detected in method, Lcom/android/insecurebankv2/CryptoClass; aes256encrypt ([B [B [B)[B
    CWE-1204 is detected in method, Lcom/android/insecurebankv2/CryptoClass; aes256decrypt ([B [B [B)[B
    CWE-1204 is detected in method, Lcom/google/android/gms/internal/zzar; zzc ([B Ljava/lang/String;)[B




Detect CWE-24 in Android Application
-------------------------------------

This scenario aims to demonstrate the detection of the **Relative Path Traversal** vulnerability.

CWE-24: Path Traversal: '../filedir'
=====================================

We analyze the definition of CWE-24 and identify its characteristics.

See `CWE-24 <https://cwe.mitre.org/data/definitions/24.html>`_ for more details.

.. image:: https://i.postimg.cc/xdQjd3M2/image.png

Code of CWE-24 in ovaa.apk
===========================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-24.

.. image:: https://imgur.com/KT277GG.png

CWE-24 Detection Process Using Quark Script API
================================================

.. image:: https://i.postimg.cc/YCz0YPp9/image.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we create a detection rule named ``accessFileInExternalDir.json`` to identify behavior that accesses a file in an external directory.

Next, we use ``methodInstance.getArguments()`` to retrieve the file path argument and check whether it belongs to the APK. If it does not belong to the APK, the argument is likely from external input.

Finally, we use the Quark Script API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` to search for any APIs in the caller method that are used to match strings, and ``getParamValues(none)`` to retrieve the parameters.

If no API is found or ``"../"`` is not in parameters, that implies the APK does not neutralize the special element ``../`` within the argument, possibly resulting in CWE-24 vulnerability.

Quark Script: CWE-24.py
========================

.. image:: https://i.postimg.cc/rwfc82VS/image.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "accessFileInExternalDir.json"


    STRING_MATCHING_API = [
        ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
        ["Ljava/lang/String;", "indexOf", "(I)I"],
        ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
        ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
        [
            "Ljava/lang/String;",
            "replaceAll",
            "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;",
        ],
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for accessExternalDir in quarkResult.behaviorOccurList:

        filePath = accessExternalDir.secondAPI.getArguments()[2]

        if quarkResult.isHardcoded(filePath):
            continue

        caller = accessExternalDir.methodCaller
        strMatchingAPIs = [
            api
            for api in STRING_MATCHING_API
            if quarkResult.findMethodInCaller(caller, api)
        ]

        if not strMatchingAPIs or "../" not in accessExternalDir.getParamValues():
            print(f"CWE-24 is detected in method, {caller.fullName}")

Quark Rule: accessFileInExternalDir.json
=========================================

.. image:: https://i.postimg.cc/1RDQ8qRR/image.png

.. code-block:: json

    {
        "crime": "Access a file in an external directory",
        "permission": [],
        "api": [
            {
                "class": "Landroid/os/Environment;",
                "method": "getExternalStorageDirectory",
                "descriptor": "()Ljava/io/File;"
            },
            {
                "class": "Ljava/io/File;",
                "method": "<init>",
                "descriptor": "(Ljava/io/File;Ljava/lang/String;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-24.py
    CWE-24 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;






Detect CWE-359 in Android Application
--------------------------------------

This scenario aims to demonstrate the detection of the **Exposure of Private Personal Information to an Unauthorized Actor** vulnerability.

CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
===========================================================================

We analyze the definition of CWE-359 and identify its characteristics.

See `CWE-359 <https://cwe.mitre.org/data/definitions/359.html>`_ for more details.

.. image:: https://i.postimg.cc/QxZcD3gb/image.png

Code of CWE-359 in ovaa.apk
============================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-359.

.. image:: https://i.postimg.cc/LhKL2vvC/image.png

CWE-359 Detection Process Using Quark Script API
=================================================

.. image:: https://i.postimg.cc/8CB6ywzN/image.png

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we create a detection rule named ``accessFileWithUnsafeUriPath.json`` to identify behavior that accesses a file with an unsafe path from ``Uri``.

Next, we use API ``methodInstance.methodCaller`` to retrieve the name of the caller that has this behavior.

Then, we use API ``quarkResultInstance.isHardcoded(argument)`` to check if the file path is hardcoded into the APK. If not, the file path is likely from external input.

After that, we use API ``getProviders(samplePath)``  and ``providerInstance.isExported()`` to check if there is any exported provider that matches the caller class name. If yes, any external application can access the behavior.

Finally, we use API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` to search for any APIs in the caller method that are used to match strings.

If **NO** API is found, that implies the APK does not neutralize special elements within the argument, possibly resulting in a CWE-359 vulnerability.

Quark Script: CWE-359.py
=========================

.. image:: https://i.postimg.cc/76KT46zR/image.png

.. code-block:: python

    from quark.script import Rule, runQuarkAnalysis, getProviders

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "accessFileWithUnsafeUriPath.json"

    STRING_MATCHING_API = [
        ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
        ["Ljava/lang/String;", "indexOf", "(I)I"],
        ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
        ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
        [
            "Ljava/lang/String;",
            "replaceAll",
            "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;",
        ],
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    exportedProviders = [
        str(provider)
        for provider in getProviders(SAMPLE_PATH)
        if provider.isExported()
    ]

    for behavior in quarkResult.behaviorOccurList:
        caller = behavior.methodCaller
        classNameInJavaFormat = caller.className.replace("/", ".")[1:-1]
        filePath = behavior.secondAPI.getArguments()[2]

        if quarkResult.isHardcoded(filePath):
            continue

        if classNameInJavaFormat not in exportedProviders:
            continue

        if not any(
            quarkResult.findMethodInCaller(caller, api)
            for api in STRING_MATCHING_API
        ):
            print(f"CWE-359 is detected in method, {caller.fullName}")

Quark Rule: accessFileWithUnsafeUriPath.json
=============================================

.. image:: https://i.postimg.cc/kGDRgmFg/image.png

.. code-block:: json

    {
        "crime": "Access a File with an unsafe path from Uri",
        "permission": [],
        "api": [
            {
                "class": "Landroid/net/Uri;",
                "method": "getLastPathSegment",
                "descriptor": "()Ljava/lang/String;"
            },
            {
                "class": "Ljava/io/File;",
                "method": "<init>",
                "descriptor": "(Ljava/io/File;Ljava/lang/String;)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-359.py
    CWE-359 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;




Detect CWE-256 in Android Application
--------------------------------------

This scenario seeks to find **Plaintext Storage of a Password**.

CWE-256: Plaintext Storage of a Password
=========================================

We analyze the definition of CWE-256 and identify its characteristics.

See `CWE-256 <https://cwe.mitre.org/data/definitions/256.html>`_ for more details.

.. image:: https://i.postimg.cc/rpydts5T/image.png

Code of CWE-256 in ovaa.apk
============================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-256.

.. image:: https://i.postimg.cc/RhtqzHx7/image.png

CWE-256 Detection Process Using Quark Script API
=================================================

.. image:: https://i.postimg.cc/X7PzpBFM/image.png

First, we define a detection rule ``putStrAndCommit.json`` to identify behaviors that store information using ``SharedPreferences.Editor``.

Next, we call ``behaviorInstance.getParamValues()`` to retrieve all parameter values associated with this behavior. We then check whether any parameter contains keywords that suggest it is being used as a password (e.g., ``password``, ``pswd``, or ``passwd``).

Finally, we use ``behaviorInstance.isArgFromMethod(targetMethod)`` to verify whether the ``doFinal`` method for encryption is applied on the second argument ``value``. (Note: this Quark Script API checks all arguments, not just a specific one. Therefore, the API returns ``True`` even if the ``doFinal`` method is applied on the ``key`` argument rather than the ``value`` argument of ``putString`` . But the situation is so rare that we can neglect it.)

If the answer is **NO**, it indicates that the value may be stored in plaintext, which could lead to a CWE-256 vulnerability.

Quark Script CWE-256.py
========================

.. image:: https://i.postimg.cc/brxQ0JNR/image.png

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "putStrAndCommit.json"

    encryptAPI = ["Ljavax/crypto/Cipher;", "doFinal", ""]

    passwordPatterns = ["password", "pswd", "passwd"]


    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for putStrAndCommit in quarkResult.behaviorOccurList:
        paramValues = [
            paramValue.lower() for paramValue in putStrAndCommit.getParamValues()
        ]
        if not any(
            passwordPattern in paramValues for passwordPattern in passwordPatterns
        ):
            continue

        if not putStrAndCommit.isArgFromMethod(encryptAPI):
            print(
                f"CWE-256 is detected in method",
                putStrAndCommit.methodCaller.fullName
            )

Quark Rule: putStrAndCommit.json
=================================

.. image:: https://i.postimg.cc/h4sFPGpg/image.png

.. code-block:: json

    {
        "crime": "Use editor to store information",
        "permission": [],
        "api": [
            {
                "class": "Landroid/content/SharedPreferences$Editor;",
                "method": "putString",
                "descriptor": "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;"
            },
            {
                "class": "Landroid/content/SharedPreferences$Editor;",
                "method": "commit",
                "descriptor": "()Z"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-256.py
    CWE-256 is detected in method, Loversecured/ovaa/utils/LoginUtils; saveCredentials (Loversecured/ovaa/objects/LoginData;)V




Detect CWE-927 in Android Application
--------------------------------------

This scenario seeks to find **Use of Implicit Intent for Sensitive Communication**.

CWE-927: Use of Implicit Intent for Sensitive Communication
===========================================================

We analyze the definition of CWE-927 and identify its characteristics.

See `CWE-927 <https://cwe.mitre.org/data/definitions/927.html>`_ for more details.

.. image:: https://hackmd.io/_uploads/H1UYN6pqxe.png

Code of CWE-927 in ovaa.apk
============================

We use the `ovaa.apk <https://github.com/oversecured/ovaa>`_ sample to explain the vulnerability code of CWE-927.

.. image:: https://hackmd.io/_uploads/SJCe0Z1sll.png

CWE-927 Detection Process Using Quark Script API
=================================================

.. image:: https://hackmd.io/_uploads/ByAqo4ksxg.png

First, we design a detection rule ``startActivityWithIntent.json`` to identify the behavior of using an intent to start an activity.

Then, we use the API ``behaviorInstance.getMethodsInArgs()`` to retrieve a list of methods that prepare an intent. 

Finally, we check whether any component setting method is present in the list. If **none** is found, it indicates that the APK is using an implicit intent, which may lead to a CWE-927 vulnerability.

Quark Script CWE-927.py
========================

.. image:: https://hackmd.io/_uploads/rkl2ii4ysex.png

.. code-block:: python

	from quark.script import runQuarkAnalysis, Rule
	
	SAMPLE_PATH = "ovaa.apk"
	RULE_PATH = "startActivityWithIntent.json"
	
	ruleInstance = Rule(RULE_PATH)
	quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)
	
	COMPONENT_SETTING_METHODS = ["setComponent", "setClass", "setClassName"]
	
	for intentUsage in quarkResult.behaviorOccurList:
	    calledMethods = intentUsage.getMethodsInArgs()
	
	    if not any(
	        method.methodName in COMPONENT_SETTING_METHODS for method in calledMethods
	    ):
	        print(f"CWE-927 is detected in method, {intentUsage.methodCaller.fullName}")


Quark Rule: startActivityWithIntent.json
========================================

.. code-block:: json

	{
	    "crime": "Start Activity With Intent.",
	    "permission": [],
	    "api": [
	        {
	            "descriptor": "(Landroid/content/Context;Ljava/lang/Class;)V",
	            "class": "Landroid/content/Intent;",
	            "method": "<init>"
	        },
	        {
	            "descriptor": "(Landroid/content/Intent;)V",
	            "class": "",
	            "method": "startActivity"
	        }
	    ],
	    "score": 1,
	    "label": []
	}


Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-927.py
    CWE-927 is detected in method, Loversecured/ovaa/activities/DeeplinkActivity; processDeeplink (Landroid/net/Uri;)V
