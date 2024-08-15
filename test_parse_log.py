import pytest
from parse_log import parse_log


def test_basic_key_value_pairs():
    input_string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"

    expected_output = {
        "cat": "C2",
        "cs1Label": "subcat",
        "cs1": "DNS TUNNELING",
        "cs2Label": "vueUrls",
        "cs2": "https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650",
        "cs3Label": "Tags",
        "cs3": "USA,Finance",
        "cs4Label": "Url",
        "cs4": "https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323",
        "cn1Label": "severityScore",
        "cn1": "900",
        "msg": "Malicious activity was reported in CAAS\\= A threat intelligence rule has been automatically created in DAAS.",
        "dhost": "bad.com",
        "dst": "1.1.1.1"
    }

    result = parse_log(input_string)
    assert result == expected_output


def test_empty_string():
    input_string = ""
    expected_output = {}
    result = parse_log(input_string)
    assert result == expected_output


def test_no_key_value_pairs():
    input_string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High"
    expected_output = {}
    result = parse_log(input_string)
    assert result == expected_output
