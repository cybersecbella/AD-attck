"""
Windows Security Event Log parser.

Parses individual event XML records (the format python-evtx produces from
raw .evtx files) into structured dicts, and flags security-relevant
conditions:
  - 4769 with RC4 encryption -> Kerberoasting indicator
  - 4662 with DS-Replication-Get-Changes[-All] GUIDs -> DCSync indicator

Event IDs covered:
  4624 - successful logon
  4625 - failed logon
  4768 - TGT requested (AS-REQ)
  4769 - service ticket requested (TGS-REQ) -- Kerberoasting shows up here
  4662 - object access -- DCSync shows up here via replication GUIDs
"""

import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

RELEVANT_EVENT_IDS = {"4624", "4625", "4768", "4769", "4662"}

# Kerberos ticket encryption types (from MS-KILE / RFC 3961).
# RC4-HMAC is crackable far faster offline than AES -- this is the
# Kerberoasting tell in 4769 events.
ENCRYPTION_TYPES = {
    "0x1": "DES-CBC-CRC",
    "0x3": "DES-CBC-MD5",
    "0x11": "AES128-CTS-HMAC-SHA1",
    "0x12": "AES256-CTS-HMAC-SHA1",
    "0x17": "RC4-HMAC",
    "0x18": "RC4-HMAC-EXP",
}
WEAK_ENCRYPTION_TYPES = {"0x1", "0x3", "0x17", "0x18"}  # DES and RC4 variants

# Extended-rights GUIDs used to detect DCSync via 4662 events.
# A principal invoking both of these against a domain object (outside
# of actual Domain Controllers) is performing directory replication --
# the core DCSync primitive.
DCSYNC_GUIDS = {
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}": "DS-Replication-Get-Changes",
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}": "DS-Replication-Get-Changes-All",
}


class EventParseError(Exception):
    pass


def _extract_event_data(event_data_elem) -> dict:
    """Turns <EventData><Data Name='X'>Y</Data>...</EventData> into a dict."""
    fields = {}
    if event_data_elem is None:
        return fields
    for data in event_data_elem.findall("e:Data", NS):
        name = data.get("Name")
        if name:
            fields[name] = data.text or ""
    return fields


def parse_event_xml(xml_string: str) -> dict:
    """
    Parses a single Windows Event XML record into a structured dict:
        {
            "event_id": "4769",
            "time_created": "2026-07-09T14:32:10.123456Z",
            "computer": "DC01.phantom.corp",
            "fields": {...event-specific EventData fields...}
        }
    Raises EventParseError on malformed XML.
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        raise EventParseError(f"Could not parse event XML: {e}") from e

    system = root.find("e:System", NS)
    if system is None:
        raise EventParseError("Event XML missing <System> element")

    event_id_elem = system.find("e:EventID", NS)
    time_elem = system.find("e:TimeCreated", NS)
    computer_elem = system.find("e:Computer", NS)

    event_data_elem = root.find("e:EventData", NS)

    return {
        "event_id": event_id_elem.text if event_id_elem is not None else None,
        "time_created": time_elem.get("SystemTime") if time_elem is not None else None,
        "computer": computer_elem.text if computer_elem is not None else None,
        "fields": _extract_event_data(event_data_elem),
    }


def is_relevant_event(parsed_event: dict) -> bool:
    """Filters to just the event IDs this platform cares about."""
    return parsed_event.get("event_id") in RELEVANT_EVENT_IDS


def check_kerberoast_indicator(parsed_event: dict) -> dict | None:
    """
    For a 4769 (service ticket request) event, flags whether the
    encryption type used is weak (RC4/DES), which is the signature
    of a Kerberoasting attempt -- the ticket was requested specifically
    to be cracked offline.

    Returns None if not a 4769 event. Otherwise returns:
        {
            "account": "<ServiceName>",
            "encryption_type": "0x17",
            "encryption_name": "RC4-HMAC",
            "is_weak": True,
            "source_ip": "...",
            "time": "..."
        }
    """
    if parsed_event.get("event_id") != "4769":
        return None

    fields = parsed_event.get("fields", {})
    enc_type = fields.get("TicketEncryptionType", "").lower()

    return {
        "account": fields.get("ServiceName") or fields.get("TargetUserName"),
        "encryption_type": enc_type,
        "encryption_name": ENCRYPTION_TYPES.get(enc_type, "UNKNOWN"),
        "is_weak": enc_type in WEAK_ENCRYPTION_TYPES,
        "source_ip": fields.get("IpAddress"),
        "time": parsed_event.get("time_created"),
    }


def check_dcsync_indicator(parsed_event: dict) -> dict | None:
    """
    For a 4662 (object access) event, flags whether the access included
    DS-Replication-Get-Changes and/or DS-Replication-Get-Changes-All --
    the two extended rights that together enable DCSync.

    Returns None if not a 4662 event or no matching GUIDs found.
    """
    if parsed_event.get("event_id") != "4662":
        return None

    fields = parsed_event.get("fields", {})
    properties = fields.get("Properties", "")

    matched_rights = [
        name for guid, name in DCSYNC_GUIDS.items() if guid in properties
    ]

    if not matched_rights:
        return None

    return {
        "subject_account": fields.get("SubjectUserName"),
        "target_object": fields.get("ObjectName"),
        "rights_used": matched_rights,
        "full_dcsync_rights": len(matched_rights) == 2,
        "time": parsed_event.get("time_created"),
    }
