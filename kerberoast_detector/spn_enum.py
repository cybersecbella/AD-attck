"""
Enumerates Active Directory accounts with SPNs set (Kerberoastable
candidates) via LDAP, and assesses each one's encryption exposure.

Uses ldap3 rather than raw impacket.ldap -- ldap3 is impacket's own
underlying LDAP dependency in most modern setups and has a cleaner
search API. impacket is still used elsewhere in this project (Kerberos
ticket handling), just not for the LDAP query itself here.

Split into two layers on purpose:
  - parse_ldap_entry(): pure function, no network -- fully unit testable
  - enumerate_spn_accounts(): live LDAP connection + search, not covered
    by unit tests (requires a real or lab domain controller)
"""

from kerberoast_detector.models import KerberoastableAccount
from kerberoast_detector.weak_crypto import assess_encryption

# UserAccountControl bit flags (MS-ADTS 2.2.16)
UF_ACCOUNTDISABLE = 0x0002

# LDAP filter: any account with an SPN set, excluding computer objects
# (computers always have SPNs by default and aren't the "Kerberoasting a
# misconfigured service account" scenario this tool targets).
KERBEROASTABLE_FILTER = (
    "(&(servicePrincipalName=*)(objectCategory=person)(objectClass=user))"
)

REQUIRED_ATTRIBUTES = [
    "sAMAccountName",
    "servicePrincipalName",
    "userAccountControl",
    "pwdLastSet",
    "msDS-SupportedEncryptionTypes",
]


def parse_ldap_entry(raw_attrs: dict) -> KerberoastableAccount:
    """
    Converts a raw LDAP attribute dict (as returned by ldap3's
    entry.entry_attributes_as_dict, or an equivalent plain dict in tests)
    into a KerberoastableAccount.

    Expected raw_attrs shape (ldap3 returns lists for most attributes):
        {
            "sAMAccountName": ["helpdesk_svc"],
            "servicePrincipalName": ["HTTP/helpdesk.phantom.corp", "HTTP/helpdesk"],
            "userAccountControl": [512],
            "pwdLastSet": ["2023-01-15T10:00:00+00:00"],
            "msDS-SupportedEncryptionTypes": [4],  # or missing/empty
        }
    """
    def first(key, default=None):
        val = raw_attrs.get(key, default)
        if isinstance(val, list):
            return val[0] if val else default
        return val

    sam_account_name = first("sAMAccountName", "")
    spns = raw_attrs.get("servicePrincipalName", []) or []
    uac = first("userAccountControl", 0) or 0
    pwd_last_set = first("pwdLastSet")
    enc_value = first("msDS-SupportedEncryptionTypes")

    enabled = not (int(uac) & UF_ACCOUNTDISABLE)
    encryption = assess_encryption(enc_value)

    return KerberoastableAccount(
        sam_account_name=sam_account_name,
        spns=list(spns),
        enabled=enabled,
        password_last_set=pwd_last_set,
        encryption=encryption,
    )


def enumerate_spn_accounts(
    server: str,
    domain: str,
    username: str,
    password: str,
    base_dn: str | None = None,
    port: int = 389,
    use_ssl: bool = False,
) -> list[KerberoastableAccount]:
    """
    Connects to a domain controller over LDAP and returns all accounts
    matching KERBEROASTABLE_FILTER, parsed into KerberoastableAccount
    objects with encryption risk already assessed.

    Requires: pip install ldap3
    Requires a live/lab domain controller -- not covered by unit tests.
    """
    try:
        from ldap3 import Server, Connection, ALL, NTLM
    except ImportError as e:
        raise ImportError(
            "ldap3 is required for live SPN enumeration. Install it with: pip install ldap3"
        ) from e

    if base_dn is None:
        # crude DN derivation from domain, e.g. phantom.corp -> DC=phantom,DC=corp
        base_dn = ",".join(f"DC={part}" for part in domain.split("."))

    ldap_server = Server(server, port=port, use_ssl=use_ssl, get_info=ALL)
    conn = Connection(
        ldap_server,
        user=f"{domain}\\{username}",
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )

    conn.search(
        search_base=base_dn,
        search_filter=KERBEROASTABLE_FILTER,
        attributes=REQUIRED_ATTRIBUTES,
    )

    accounts = []
    for entry in conn.entries:
        raw_attrs = entry.entry_attributes_as_dict
        accounts.append(parse_ldap_entry(raw_attrs))

    conn.unbind()
    return accounts
