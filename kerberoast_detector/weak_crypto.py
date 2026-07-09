"""
Analyzes the msDS-SupportedEncryptionTypes attribute to determine whether
an account is exposed to Kerberoasting with a crackable (RC4/DES) ticket.

msDS-SupportedEncryptionTypes is a bitmask (MS-ADA3 2.375):
    0x01 = DES-CBC-CRC
    0x02 = DES-CBC-MD5
    0x04 = RC4-HMAC
    0x08 = AES128-CTS-HMAC-SHA1-96
    0x10 = AES256-CTS-HMAC-SHA1-96
    0x18 = AES128 + AES256 (common "fully modern" combination)

Important real-world nuance: if this attribute is NOT SET (None/absent)
on an account, Windows falls back to RC4 by default on most domains
unless AES has been explicitly enforced elsewhere (e.g. via GPO or
msDS-SupportedEncryptionTypes being set domain-wide). An unset value is
therefore treated as weak here, not as "unknown/safe" -- this matches
how real Kerberoasting tooling (Rubeus, GetUserSPNs.py) treats it.
"""

from dataclasses import dataclass

DES_CBC_CRC = 0x01
DES_CBC_MD5 = 0x02
RC4_HMAC = 0x04
AES128 = 0x08
AES256 = 0x10


@dataclass
class EncryptionAssessment:
    raw_value: int | None
    supports_des: bool
    supports_rc4: bool
    supports_aes128: bool
    supports_aes256: bool
    is_weak: bool
    risk_reason: str


def assess_encryption(msds_supported_encryption_types) -> EncryptionAssessment:
    """
    Takes the raw msDS-SupportedEncryptionTypes value (int, numeric string,
    or None/empty if unset) and returns a structured risk assessment.
    """
    if msds_supported_encryption_types in (None, "", 0):
        return EncryptionAssessment(
            raw_value=None,
            supports_des=False,
            supports_rc4=True,  # unset defaults to RC4-capable in practice
            supports_aes128=False,
            supports_aes256=False,
            is_weak=True,
            risk_reason=(
                "msDS-SupportedEncryptionTypes is unset. Account will "
                "negotiate RC4 unless AES is enforced elsewhere (e.g. GPO)."
            ),
        )

    value = int(msds_supported_encryption_types)

    supports_des = bool(value & (DES_CBC_CRC | DES_CBC_MD5))
    supports_rc4 = bool(value & RC4_HMAC)
    supports_aes128 = bool(value & AES128)
    supports_aes256 = bool(value & AES256)

    if supports_des or supports_rc4:
        if supports_aes128 or supports_aes256:
            is_weak = True
            risk_reason = (
                "Account supports RC4/DES alongside AES. An attacker can "
                "still request an RC4 ticket even if AES is also offered, "
                "since Kerberoasting tools request the weakest accepted type."
            )
        else:
            is_weak = True
            risk_reason = "Account only supports RC4/DES -- no AES fallback available."
    else:
        is_weak = False
        risk_reason = "Account is AES-only. Not practically Kerberoastable."

    return EncryptionAssessment(
        raw_value=value,
        supports_des=supports_des,
        supports_rc4=supports_rc4,
        supports_aes128=supports_aes128,
        supports_aes256=supports_aes256,
        is_weak=is_weak,
        risk_reason=risk_reason,
    )
