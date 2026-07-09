"""
Phase 2 test suite for kerberoast_detector -- no live domain controller
required. Tests the pure parsing/assessment logic against static fixtures
modeled on real ldap3 output.

Run with:
    python -m pytest tests/test_kerberoast_detector.py -v
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kerberoast_detector.weak_crypto import assess_encryption
from kerberoast_detector.spn_enum import parse_ldap_entry
from tests.fixtures.sample_ldap_entries import (
    ENTRY_RC4_ONLY,
    ENTRY_UNSET_ENCRYPTION,
    ENTRY_RC4_AND_AES,
    ENTRY_AES_ONLY,
    ENTRY_DISABLED_RC4,
    ENTRY_MULTIPLE_SPNS,
)


# --- weak_crypto.assess_encryption() -----------------------------------

def test_rc4_only_is_weak():
    result = assess_encryption(4)
    assert result.supports_rc4 is True
    assert result.supports_aes128 is False
    assert result.supports_aes256 is False
    assert result.is_weak is True


def test_unset_encryption_defaults_to_weak():
    result = assess_encryption(None)
    assert result.is_weak is True
    assert result.supports_rc4 is True
    assert "unset" in result.risk_reason.lower()


def test_rc4_and_aes_still_flagged_weak():
    # 4 (RC4) + 8 (AES128) + 16 (AES256) = 28
    result = assess_encryption(28)
    assert result.supports_rc4 is True
    assert result.supports_aes128 is True
    assert result.supports_aes256 is True
    assert result.is_weak is True  # RC4 downgrade still possible


def test_aes_only_is_not_weak():
    # 8 (AES128) + 16 (AES256) = 24
    result = assess_encryption(24)
    assert result.supports_rc4 is False
    assert result.supports_des is False
    assert result.is_weak is False


def test_des_flags_weak():
    result = assess_encryption(1)  # DES-CBC-CRC only
    assert result.supports_des is True
    assert result.is_weak is True


def test_zero_value_treated_same_as_unset():
    result = assess_encryption(0)
    assert result.is_weak is True
    assert result.supports_rc4 is True


# --- spn_enum.parse_ldap_entry() ---------------------------------------

def test_parse_rc4_only_entry():
    account = parse_ldap_entry(ENTRY_RC4_ONLY)
    assert account.sam_account_name == "helpdesk_svc"
    assert account.spns == ["HTTP/helpdesk.phantom.corp"]
    assert account.enabled is True
    assert account.encryption.is_weak is True
    assert account.is_high_risk is True


def test_parse_unset_encryption_entry():
    account = parse_ldap_entry(ENTRY_UNSET_ENCRYPTION)
    assert account.sam_account_name == "legacy_app_svc"
    assert account.encryption.is_weak is True
    assert account.is_high_risk is True


def test_parse_aes_only_entry_is_not_high_risk():
    account = parse_ldap_entry(ENTRY_AES_ONLY)
    assert account.encryption.is_weak is False
    assert account.is_high_risk is False


def test_parse_disabled_account_is_not_high_risk():
    account = parse_ldap_entry(ENTRY_DISABLED_RC4)
    assert account.enabled is False
    assert account.encryption.is_weak is True  # still crypto-weak
    assert account.is_high_risk is False  # but disabled accounts aren't prioritized


def test_parse_multiple_spns():
    account = parse_ldap_entry(ENTRY_MULTIPLE_SPNS)
    assert len(account.spns) == 3
    assert "MSSQLSvc/multi.phantom.corp:1433" in account.spns


def test_parse_mixed_rc4_aes_entry_still_high_risk():
    account = parse_ldap_entry(ENTRY_RC4_AND_AES)
    assert account.encryption.is_weak is True
    assert account.is_high_risk is True


if __name__ == "__main__":
    test_rc4_only_is_weak()
    test_unset_encryption_defaults_to_weak()
    test_rc4_and_aes_still_flagged_weak()
    test_aes_only_is_not_weak()
    test_des_flags_weak()
    test_zero_value_treated_same_as_unset()
    test_parse_rc4_only_entry()
    test_parse_unset_encryption_entry()
    test_parse_aes_only_entry_is_not_high_risk()
    test_parse_disabled_account_is_not_high_risk()
    test_parse_multiple_spns()
    test_parse_mixed_rc4_aes_entry_still_high_risk()
    print("All kerberoast_detector tests passed.")
