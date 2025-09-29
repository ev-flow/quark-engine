import importlib.resources


class ReportGenerator:
    """
    This module is for web report generating.
    """

    def __init__(self, json_report):

        self.json_report = json_report

        # Load html layout
        rulegenerate_html_path = (
            importlib.resources.files("quark.webreport")
            / "genrule_report_layout.html"
        )

        analysis_result_html_path = (
            importlib.resources.files("quark.webreport")
            / "analysis_report_layout.html"
        )

        with importlib.resources.as_file(rulegenerate_html_path) as file:
            self.rulegenerate_layout = file.read_text()

        with importlib.resources.as_file(analysis_result_html_path) as file:
            self.analysis_result_layout = file.read_text()

    def get_rule_generate_editor_html(self):
        """
        Load the rule generation result
        and generate the HTML of the Quark web report.

        :return: the string of Quark web report HTML
        """

        generate_result = self.json_report["result"]
        filesize = format(
            float(self.json_report["size_bytes"])/float(1024*1024), '.2f',
        )
        filename = self.json_report["apk_filename"]
        md5 = self.json_report["md5"]
        rule_number = len(generate_result)

        self.insert_genrule_report_html(
            generate_result, filename, md5, filesize, rule_number)
        self.rulegenerate_layout = get_json_report_html(
            self.rulegenerate_layout, generate_result)

        return self.rulegenerate_layout

    def get_analysis_report_html(self):
        """
        Load the quark JSON report
        and generate the HTML of the Quark web report.

        :return: the string of Quark web report HTML
        """

        analysis_result = self.json_report["crimes"]
        filesize = format(
            float(self.json_report["size_bytes"])/float(1024*1024), '.2f',
        )
        filename = self.json_report["apk_filename"]
        md5 = self.json_report["md5"]

        rule_number_set = {
            "all": len(analysis_result),
            "100%": count_confidence_rule_number(analysis_result, "100%"),
            "80%": count_confidence_rule_number(analysis_result, "80%"),
            "60%": count_confidence_rule_number(analysis_result, "60%"),
            "40%": count_confidence_rule_number(analysis_result, "40%"),
            "20%": count_confidence_rule_number(analysis_result, "20%"),
            "0%": count_confidence_rule_number(analysis_result, "0%"),
        }

        # Get all labels
        five_stages_labels = get_five_stages_labels(analysis_result)
        all_labels = get_all_labels(analysis_result)

        self.insert_sample_information_html(
            rule_number_set, filename, md5, filesize, five_stages_labels)
        self.insert_radarchart_html(five_stages_labels, all_labels)
        self.insert_report_html(analysis_result)

        self.analysis_result_layout = get_json_report_html(
            self.analysis_result_layout, analysis_result)

        return self.analysis_result_layout

    def insert_radarchart_html(self, five_stages_labels, all_labels):
        """
        Generate the HTML of radar chart secton in Quark web report.

        :param five_stages_labels: the set of lebels
        with 100% confidence crimes
        :param all_labels: the set contain all labels
        with crimes above 0% confidence
        """

        five_labels_html = ""
        for label in five_stages_labels:
            five_labels_html += f"""<label class="label-tag">{label}</label>"""

        all_labels_html = ""
        for label in all_labels:
            if label == "power manager":
                label = "power"
            elif label == "accessibility service":
                label = "accessibility"
            elif label == "dexClassLoader":
                label = "dex"

            all_labels_html += f"""
            <label id="collection" class="label-container">{label}
                <input class="rule-label" type="checkbox"
                    name="label" value="{label}">
                <span class="checkmark"></span>
            </label>
            """

        replace_dict = {
            "$five_labels_html$": five_labels_html,
            "$all_labels_html$": all_labels_html,
        }

        for key, replace_str in replace_dict.items():
            self.analysis_result_layout = self.analysis_result_layout.replace(
                key, str(replace_str))

    def insert_genrule_report_html(
        self,
        data,
        filename,
        md5,
        filesize,
        rule_number
    ):
        """
        Generate the HTML of rule generation result secton.

        :param data: the dict of rule generation result
        """
        contentHTML = ""

        for rule in data:
            api1 = rule["api"][0]["class"].split(
                '/')[-1] + rule["api"][0]["method"]
            api2 = rule["api"][0]["class"].split(
                '/')[-1] + rule["api"][1]["method"]
            api1 = api1.replace("<", "&lt;").replace(">", "&gt;")
            api2 = api2.replace("<", "&lt;").replace(">", "&gt;")
            contentHTML += f"""
                <tr id="{rule["number"]}">
                    <td><p class="fw-normal mb-1">{rule["number"]}</p></td>
                    <td><p class="api-td fw-normal mb-1">{api1}</p></td>
                    <td><p class="api-td fw-normal mb-1">{api2}</p></td>
                    <td>
                        <a href="#" class="edit-btn btn btn-info btn-sm">
                            Edit
                        </a>
                    </td>
                </tr>
            """
        replace_dict = {
            "$genrule_report$": contentHTML,
            "$filename$": filename,
            "$md5$": md5,
            "$filesize$": filesize,
            "$rule_numbers$": rule_number,
        }

        for key, replace_str in replace_dict.items():
            self.rulegenerate_layout = self.rulegenerate_layout.replace(
                key, str(replace_str))

    def insert_report_html(self, data):
        """
        Generate the HTML of summary report secton in Quark web report.

        :param data: the dict of Quark JSON report
        """

        confidence_badge = {
            "0%": "badge-secondary",
            "20%": "badge-success",
            "40%": "badge-info",
            "60%": "badge-primary",
            "80%": "badge-warning",
            "100%": "badge-danger",
        }

        contentHTML = ""
        for crime in data:
            description = crime["crime"]
            confidence = crime["confidence"]
            rule_number = crime["rule"].split('.')[0]
            crime_text = str(crime).replace("'", '\\"')
            contentHTML += f"""
                <tr>
                    <td><p class="fw-normal mb-1">{rule_number}</p></td>
                    <td onclick='showModal("{crime_text}")'><p class="fw-normal mb-1">{description}</p></td>
                    <td>
                        <span class="badge {confidence_badge[confidence]}">
                            {confidence}
                        </span>
                    </td>
                </tr>
            """

        self.analysis_result_layout = self.analysis_result_layout.replace(
            "$report_content$", contentHTML)

    def insert_sample_information_html(
        self,
        rules_number_set,
        filename,
        md5,
        filesize,
        labels
    ):
        """
        Generate the HTML of sample information secton in Quark web report.

        :param rules_number_set: the dict of rule number
        for each confidence
        :param filename: the string of the sample filename
        :param md5: the string of the sample md5 hash value
        :param filesize: the string of the sample filesize
        :param labels: the set of lebels with 100% confidence crimes
        """
        five_labels_html = ""
        for label in labels:
            five_labels_html += f"""<label class="label-tag">{label}</label>"""

        replace_dict = {
            "$effective_rules_number_100$": rules_number_set["100%"],
            "$effective_rules_number_80$": rules_number_set["80%"],
            "$effective_rules_number_60$": rules_number_set["60%"],
            "$effective_rules_number_40$": rules_number_set["40%"],
            "$effective_rules_number_20$": rules_number_set["20%"],
            "$effective_rules_number_0$": rules_number_set["0%"],
            "$all_rules_number$": rules_number_set["all"],
            "$filename$": filename,
            "$md5$": md5,
            "$filesize$": filesize,
            "$five_labels_html$": five_labels_html
        }

        for key, replace_str in replace_dict.items():
            self.analysis_result_layout = self.analysis_result_layout.replace(
                key, str(replace_str))


def get_json_report_html(layout, data):
    """
    Convert the quark JSON report to HTML with script tag.

    :param data: the dict of Quark JSON report
    :return: the string of Quark JSON report HTML
    """
    report_data_html = f"""<script>var reportData = {str(data)}</script>"""
    layout = layout.replace(
        "$report_data$", report_data_html)

    return layout


def get_five_stages_labels(data):
    """
    Get the labels with 100% confidence crimes.

    :param data: the dict of Quark JSON report
    :return: the set contain all lebels with 100% confidence crimes
    """

    five_stage_label_set = set()
    for item in data:
        if item["confidence"] == "100%":
            five_stage_label_set.update(item["label"])

    return five_stage_label_set


def get_all_labels(data):
    """
    Get all labels with crimes above 0% confidence.

    :param data: the dict of Quark JSON report
    :return: the set contain all labels with crimes above 0% confidence
    """

    all_label_set = set()
    for item in data:
        if not item["confidence"] == "0%":
            all_label_set.update(item["label"])

    return all_label_set


def count_confidence_rule_number(data, confidence):
    """
    Get the number of rules with given confidence in JSON report.

    :param data: the dict of Quark JSON report
    :param confidence: the string of given confidence
    :return: the int for the number of rules
    with given confidence in JSON report
    """

    count = 0
    for item in data:
        if item["confidence"] == confidence:
            count += 1
    return count
