"""
Data model for accounts discovered via SPN enumeration.
"""

from dataclasses import dataclass, field
from kerberoast_detector.weak_crypto import EncryptionAssessment


@dataclass
class KerberoastableAccount:
    sam_account_name: str
    spns: list[str] = field(default_factory=list)
    enabled: bool = True
    password_last_set: str | None = None
    encryption: EncryptionAssessment | None = None

    @property
    def is_high_risk(self) -> bool:
        """
        Flags accounts as high risk when they're enabled, roastable
        (weak encryption), and have at least one SPN. Disabled accounts
        can technically still be roasted in some edge cases but are far
        lower priority for remediation.
        """
        return bool(
            self.enabled
            and self.spns
            and self.encryption
            and self.encryption.is_weak
        )
