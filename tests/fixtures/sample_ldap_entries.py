"""
Synthetic LDAP entry fixtures, modeled on ldap3's entry_attributes_as_dict
output shape, for testing kerberoast_detector parsing logic without a
live domain controller.
"""

# Weak: RC4-only, enabled, one SPN, old password
ENTRY_RC4_ONLY = {
    "sAMAccountName": ["helpdesk_svc"],
    "servicePrincipalName": ["HTTP/helpdesk.phantom.corp"],
    "userAccountControl": [512],  # normal enabled account
    "pwdLastSet": ["2021-03-04T09:12:00+00:00"],
    "msDS-SupportedEncryptionTypes": [4],  # RC4_HMAC only
}

# Weak: attribute unset entirely (defaults to RC4-capable)
ENTRY_UNSET_ENCRYPTION = {
    "sAMAccountName": ["legacy_app_svc"],
    "servicePrincipalName": ["MSSQLSvc/sql01.phantom.corp:1433"],
    "userAccountControl": [512],
    "pwdLastSet": ["2019-07-10T00:00:00+00:00"],
    # msDS-SupportedEncryptionTypes intentionally absent
}

# Weak: RC4 + AES both supported -- still roastable via etype downgrade
ENTRY_RC4_AND_AES = {
    "sAMAccountName": ["mixed_svc"],
    "servicePrincipalName": ["HTTP/mixed.phantom.corp"],
    "userAccountControl": [512],
    "pwdLastSet": ["2024-01-01T00:00:00+00:00"],
    "msDS-SupportedEncryptionTypes": [28],  # RC4(4) + AES128(8) + AES256(16) = 28
}

# Safe: AES-only, modern config
ENTRY_AES_ONLY = {
    "sAMAccountName": ["web_frontend_svc"],
    "servicePrincipalName": ["HTTP/web.phantom.corp"],
    "userAccountControl": [512],
    "pwdLastSet": ["2026-06-01T00:00:00+00:00"],
    "msDS-SupportedEncryptionTypes": [24],  # AES128(8) + AES256(16) = 24
}

# Disabled account -- still technically has an SPN, but lower priority
ENTRY_DISABLED_RC4 = {
    "sAMAccountName": ["old_disabled_svc"],
    "servicePrincipalName": ["HTTP/old.phantom.corp"],
    "userAccountControl": [514],  # 512 + UF_ACCOUNTDISABLE(2)
    "pwdLastSet": ["2018-01-01T00:00:00+00:00"],
    "msDS-SupportedEncryptionTypes": [4],
}

# Multiple SPNs on one account
ENTRY_MULTIPLE_SPNS = {
    "sAMAccountName": ["multi_svc"],
    "servicePrincipalName": [
        "HTTP/multi.phantom.corp",
        "HTTP/multi",
        "MSSQLSvc/multi.phantom.corp:1433",
    ],
    "userAccountControl": [512],
    "pwdLastSet": ["2022-05-05T00:00:00+00:00"],
    "msDS-SupportedEncryptionTypes": [4],
}
