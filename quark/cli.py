# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import json
import os

import click
import numpy as np
from tqdm import tqdm

from quark import __version__, config
from quark.core.parallelquark import ParallelQuark
from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject
from quark.logo import logo
from quark.rulegeneration import RuleGeneration
from quark.utils.colors import yellow
from quark.utils.graph import select_label_menu, show_comparison_graph
from quark.utils.pprint import print_info, print_success, print_warning
from quark.utils.weight import Weight
from quark.webreport.generate import ReportGenerator

logo()


@click.version_option(version=__version__)
@click.command(no_args_is_help=True)
@click.option(
    "-s",
    "--summary",
    is_flag=False,
    flag_value="all_rules",
    help="Show summary report. Optionally specify the name of a rule/label",
)
@click.option(
    "-d",
    "--detail",
    is_flag=False,
    flag_value="all_rules",
    help="Show detail report. Optionally specify the name of a rule/label",
)
@click.option(
    "-o",
    "--output",
    help="Output report in JSON",
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
    required=False,
)
@click.option(
    "-w",
    "--webreport",
    help="Generate web report",
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
    required=False,
)
@click.option(
    "-a",
    "--apk",
    help="APK file",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=True,
    multiple=True,
)
@click.option(
    "-r",
    "--rule",
    help="Rules directory",
    type=click.Path(exists=True, file_okay=True, dir_okay=True),
    default=f"{config.DIR_PATH}",
    required=False,
    show_default=True,
)
@click.option(
    "-g",
    "--graph",
    is_flag=False,
    help="Create call graph to call_graph_image directory",
    flag_value="png",
    type=click.Choice(["png", "json"]),
    required=False,
)
@click.option(
    "-c",
    "--classification",
    is_flag=True,
    help="Show rules classification",
    required=False,
)
@click.option(
    "-t",
    "--threshold",
    help="Set the lower limit of the confidence threshold",
    type=click.Choice(["100", "80", "60", "40", "20"]),
    required=False,
)
@click.option(
    "-i",
    "--list",
    help="List classes, methods and descriptors",
    type=click.Choice(["all", "native", "custom"]),
    required=False,
)
@click.option(
    "-p",
    "--permission",
    help="List Android permissions",
    is_flag=True,
    required=False,
)
@click.option(
    "-l",
    "--label",
    help="Show report based on label of rules",
    type=click.Choice(["max", "detailed"]),
    required=False,
)
@click.option(
    "-C",
    "--comparison",
    help="Behaviors comparison based on max confidence of rule labels",
    required=False,
    is_flag=True,
)
@click.option(
    "--generate-rule",
    "rule_generation",
    help="Generate rules and output to given directory",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    required=False,
)
@click.option(
    "--core-library",
    "core_library",
    help="Specify the core library used to analyze an APK",
    type=click.Choice(
        ("androguard", "rizin", "radare2", "shuriken", "dextrace"),
        case_sensitive=False
    ),
    required=False,
    default="androguard",
)
@click.option(
    "--multi-process",
    "num_of_process",
    type=click.IntRange(min=1),
    help="Allow analyzing APK with N processes, where N doesn't exceeds" +
    " the number of usable CPUs - 1 to avoid memory exhaustion.",
    required=False,
    default=1,
)
def entry_point(
    summary,
    detail,
    rule_generation,
    apk,
    rule,
    output,
    webreport,
    graph,
    classification,
    threshold,
    list,
    permission,
    label,
    comparison,
    core_library,
    num_of_process,
):
    """Quark is an Obfuscation-Neglect Android Malware Scoring System"""
    # Load rules
    rule_buffer_list = []
    rule_filter = summary or detail

    # Determine the location of rules
    if rule_filter and rule_filter.endswith("json"):
        if not os.path.isfile(rule_filter):
            print_warning(
                f"Specified rule not found.\n"
                f"If you want to specify one of the rules of Quark-Rule, "
                f"use {yellow(f'{config.DIR_PATH}/{rule_filter}')} "
                f"as an argument."
            )
            return

        rule_path_list = [rule_filter]
    else:
        rule_path_list = [
            os.path.join(dir_path, file)
            for dir_path, _, file_list in os.walk(rule)
            for file in file_list
            if file.endswith("json")
        ]

    # Load rules into memory
    update_rule_buffer(rule_buffer_list, rule_path_list)

    # Determine if the user provide a rule label
    if (
        rule_filter
        and rule_filter != "all_rules"
        and not rule_filter.endswith("json")
    ):
        rule_checker_list = [
            rule_checker
            for rule_checker in rule_buffer_list
            if rule_filter in rule_checker.label
        ]
    else:
        rule_checker_list = rule_buffer_list

    if comparison:

        # selection of labels on which it will be done the comparison on radar chart
        # first look for all label found in the rule list
        all_labels = set()  # array type, e.g. ['network', 'collection']

        for rule_checker in rule_checker_list:
            all_labels.update(rule_checker.label)

        # let user choose a list of label on which it will be performed the analysis
        selected_label = np.array(
            select_label_menu(all_labels, min_labels=5, max_labels=15)
        )

        # perform label based analysis on the apk_
        malware_confidences = {}
        for apk_ in apk:
            data = (
                ParallelQuark(apk_, core_library, num_of_process)
                if num_of_process > 1
                else Quark(apk_, core_library)
            )
            all_labels = {}
            # dictionary containing
            # key: label
            # value: list of confidence values
            # $ print(all_rules["accessibility service"])
            # > [60, 40, 60, 40, 60, 40]

            # analyse malware only on rules where appears label selected
            rule_checker_list = [
                rule_checker
                for rule_checker in rule_buffer_list
                if len(np.intersect1d(rule_checker.label, selected_label)) != 0
            ]

            if num_of_process > 1:
                data.apply_rules(rule_checker_list)

            for rule_checker in tqdm(rule_checker_list):
                # Run the checker
                data.run(rule_checker)
                confidence = rule_checker.check_item.count(True) * 20
                labels = (
                    rule_checker.label
                )  # array type, e.g. ['network', 'collection']
                for single_label in labels:
                    if single_label in all_labels:
                        all_labels[single_label].append(confidence)
                    else:
                        all_labels[single_label] = [confidence]

            # extrapolate data used to plot radar chart
            radar_data = {}
            for _label in selected_label:
                confidences = np.array(all_labels[_label])
                # on radar data use the maximum confidence for a certain label
                radar_data[_label] = np.max(confidences)

            radar_confidence = [
                value_ for _label, value_ in radar_data.items()
            ]
            malware_confidences[apk_.split("/")[-1]] = radar_confidence

        show_comparison_graph(
            title=f"Malicious Actions Comparison Between {len(apk)} Malwares",
            labels=selected_label,
            malware_confidences=malware_confidences,
            font_size=22,
        )

        return

    # Load APK
    data = (
        ParallelQuark(apk[0], core_library, num_of_process)
        if num_of_process > 1
        else Quark(apk[0], core_library)
    )

    if label:
        all_labels = {}
        # dictionary containing
        # key: label
        # value: list of confidence values
        # $ print(all_rules["accessibility service"])
        # > [60, 40, 60, 40, 60, 40]

        if num_of_process > 1:
            data.apply_rules(rule_buffer_list)

        for rule_checker in tqdm(rule_buffer_list):
            # Run the checker
            data.run(rule_checker)
            confidence = rule_checker.check_item.count(True) * 20
            labels = (
                rule_checker.label
            )  # array type, e.g. ['network', 'collection']
            for single_label in labels:
                if single_label in all_labels:
                    all_labels[single_label].append(confidence)
                else:
                    all_labels[single_label] = [confidence]

        # get how many label with max confidence >= 80%
        counter_high_confidence = sum(
            max(value) >= 80 for single_label, value in all_labels.items()
        )

        print_info(f"Total Label found: {yellow(len(all_labels))}")
        print_info(
            f"Rules with label which max confidence >= 80%: {yellow(counter_high_confidence)}"
        )

        data.show_label_report(rule, all_labels, label)
        print(data.quark_analysis.label_report_table)

    # Show summary report
    if summary:

        if isinstance(data, ParallelQuark):
            data.apply_rules(rule_checker_list)

        for rule_checker in tqdm(rule_checker_list):
            # Run the checker
            data.run(rule_checker)

            data.show_summary_report(rule_checker, threshold)

        w = Weight(
            data.quark_analysis.score_sum, data.quark_analysis.weight_sum
        )
        print_warning(w.calculate())
        print_info(f"Total Score: {data.quark_analysis.score_sum}")
        print(data.quark_analysis.summary_report_table)

        if classification:
            data.show_rule_classification()
        if graph:
            data.show_call_graph(graph)

    # Show detail report
    if detail:
        threshold_number = int(threshold) if threshold else 0

        if isinstance(data, ParallelQuark):
            data.apply_rules(rule_checker_list)

        for rule_checker in tqdm(rule_checker_list):
            # Run the checker
            data.run(rule_checker)

            confidence = rule_checker.check_item.count(True) * 20

            if confidence >= threshold_number:
                print(
                    f"Rulepath: "
                    f"{os.path.join(rule, rule_checker.rule_filename)}"
                )
                print(f"Rule crime: {rule_checker.crime}")
                data.show_detail_report(rule_checker)
                print_success("OK")

        if classification:
            data.show_rule_classification()
        if graph:
            data.show_call_graph()

    if rule_generation:
        generator = RuleGeneration(apk[0], rule_generation)

        if webreport:
            if ".html" not in webreport:
                webreport = f"{webreport}.html"
            webreport_file = os.path.join(rule_generation, webreport)
            generator.generate_rule(web_editor=webreport_file)
        else:
            generator.generate_rule()

    # Show JSON report
    if output:
        if isinstance(data, ParallelQuark):
            data.apply_rules(rule_buffer_list)

        for rule_checker in tqdm(rule_buffer_list):
            # Run the checker
            data.run(rule_checker)

            data.generate_json_report(rule_checker)

        json_report = data.get_json_report()

        with open(output, "w") as file:
            json.dump(json_report, file, indent=4)
            file.close()

    # Generate web report
    if webreport:
        if summary or detail:
            for rule_checker in tqdm(rule_buffer_list):
                data.generate_json_report(rule_checker)

            json_report = data.get_json_report()
            report_html = ReportGenerator(
                json_report).get_analysis_report_html()

            if ".html" not in webreport:
                webreport = f"{webreport}.html"

            with open(webreport, "w") as file:
                file.write(report_html)
                file.close()

    if list:

        if list == "all":
            for all_method in data.apkinfo.all_methods:
                print(all_method.full_name)
        if list == "native":
            for api in data.apkinfo.android_apis:
                print(api.full_name)
        if list == "custom":
            for custom_method in data.apkinfo.custom_methods:
                print(custom_method.full_name)

    if permission:

        for p in data.apkinfo.permissions:
            print(p)

    if isinstance(data, ParallelQuark):
        data.close()


def update_rule_buffer(rule_buffer_list, rule_path_list):
    for rule_path in rule_path_list:
        with open(rule_path, "r") as json_file:
            json_data = json.loads(json_file.read())
        if isinstance(json_data, list):
            for rule_data in json_data:
                rule_buffer_list.append(RuleObject(rule_path, rule_data))
        else:
            rule_buffer_list.append(RuleObject(rule_path, json_data))


if __name__ == "__main__":
    entry_point()
