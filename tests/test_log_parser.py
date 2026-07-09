"""
Phase 2 test suite for log_correlation/parser.py -- no live domain
controller or .evtx file required. Runs entirely against synthetic
XML fixtures modeled on real Windows Security event schemas.

Run with:
    python -m pytest tests/test_log_parser.py -v
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_correlation.parser import (
    parse_event_xml,
    is_relevant_event,
    check_kerberoast_indicator,
    check_dcsync_indicator,
    EventParseError,
)
from tests.fixtures.sample_events import (
    EVENT_4769_RC4,
    EVENT_4769_AES,
    EVENT_4768,
    EVENT_4624,
    EVENT_4625,
    EVENT_4662_DCSYNC,
    EVENT_4662_BENIGN,
    MALFORMED_XML,
)


# --- Basic parsing ---------------------------------------------------

def test_parse_4769_basic_fields():
    parsed = parse_event_xml(EVENT_4769_RC4)
    assert parsed["event_id"] == "4769"
    assert parsed["computer"] == "DC01.phantom.corp"
    assert parsed["time_created"] == "2026-07-09T14:32:10.123456Z"
    assert parsed["fields"]["ServiceName"] == "helpdesk_svc"


def test_parse_all_event_types():
    for xml in [EVENT_4769_RC4, EVENT_4769_AES, EVENT_4768, EVENT_4624, EVENT_4625, EVENT_4662_DCSYNC]:
        parsed = parse_event_xml(xml)
        assert parsed["event_id"] is not None
        assert is_relevant_event(parsed) is True


def test_malformed_xml_raises_event_parse_error():
    try:
        parse_event_xml(MALFORMED_XML)
        assert False, "Expected EventParseError to be raised"
    except EventParseError:
        pass


# --- Kerberoasting detection (4769) -----------------------------------

def test_kerberoast_indicator_flags_rc4_as_weak():
    parsed = parse_event_xml(EVENT_4769_RC4)
    result = check_kerberoast_indicator(parsed)

    assert result is not None
    assert result["account"] == "helpdesk_svc"
    assert result["encryption_type"] == "0x17"
    assert result["encryption_name"] == "RC4-HMAC"
    assert result["is_weak"] is True


def test_kerberoast_indicator_does_not_flag_aes():
    parsed = parse_event_xml(EVENT_4769_AES)
    result = check_kerberoast_indicator(parsed)

    assert result is not None
    assert result["account"] == "web_frontend_svc"
    assert result["encryption_type"] == "0x12"
    assert result["encryption_name"] == "AES256-CTS-HMAC-SHA1"
    assert result["is_weak"] is False


def test_kerberoast_indicator_returns_none_for_non_4769_events():
    parsed = parse_event_xml(EVENT_4624)
    result = check_kerberoast_indicator(parsed)
    assert result is None


# --- DCSync detection (4662) ------------------------------------------

def test_dcsync_indicator_detects_both_replication_rights():
    parsed = parse_event_xml(EVENT_4662_DCSYNC)
    result = check_dcsync_indicator(parsed)

    assert result is not None
    assert result["subject_account"] == "helpdesk_svc"
    assert result["full_dcsync_rights"] is True
    assert "DS-Replication-Get-Changes" in result["rights_used"]
    assert "DS-Replication-Get-Changes-All" in result["rights_used"]


def test_dcsync_indicator_ignores_benign_4662():
    parsed = parse_event_xml(EVENT_4662_BENIGN)
    result = check_dcsync_indicator(parsed)
    assert result is None


def test_dcsync_indicator_returns_none_for_non_4662_events():
    parsed = parse_event_xml(EVENT_4769_RC4)
    result = check_dcsync_indicator(parsed)
    assert result is None


if __name__ == "__main__":
    test_parse_4769_basic_fields()
    test_parse_all_event_types()
    test_malformed_xml_raises_event_parse_error()
    test_kerberoast_indicator_flags_rc4_as_weak()
    test_kerberoast_indicator_does_not_flag_aes()
    test_kerberoast_indicator_returns_none_for_non_4769_events()
    test_dcsync_indicator_detects_both_replication_rights()
    test_dcsync_indicator_ignores_benign_4662()
    test_dcsync_indicator_returns_none_for_non_4662_events()
    print("All Phase 2 log parser tests passed.")
