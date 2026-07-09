"""
Reads real .evtx files from disk and yields parsed event dicts.

Requires python-evtx (pip install python-evtx). This is a thin wrapper --
python-evtx handles the binary .evtx format and gives us XML per record,
which we hand off to parser.parse_event_xml().

Kept separate from parser.py so parser.py's logic can be fully unit
tested against static XML fixtures without ever touching a real file
or requiring python-evtx to be installed.
"""

from log_correlation.parser import parse_event_xml, is_relevant_event, EventParseError


def read_evtx_file(path: str, relevant_only: bool = True):
    """
    Generator that yields parsed event dicts from a .evtx file.

    Args:
        path: filesystem path to a .evtx file
        relevant_only: if True, only yields events matching
                       parser.RELEVANT_EVENT_IDS (4624/4625/4768/4769/4662)

    Raises ImportError with a helpful message if python-evtx isn't installed.
    """
    try:
        from Evtx.Evtx import Evtx
    except ImportError as e:
        raise ImportError(
            "python-evtx is required to read .evtx files. "
            "Install it with: pip install python-evtx"
        ) from e

    with Evtx(path) as log:
        for record in log.records():
            try:
                xml_string = record.xml()
            except Exception:
                # Some records can be corrupt/truncated in real-world .evtx
                # files (especially ones pulled from live/rotating logs).
                # Skip rather than crash the whole read.
                continue

            try:
                parsed = parse_event_xml(xml_string)
            except EventParseError:
                continue

            if relevant_only and not is_relevant_event(parsed):
                continue

            yield parsed
