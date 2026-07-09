"""
Synthetic Windows Security Event XML fixtures, modeled on the real schema
python-evtx produces from actual .evtx files (Microsoft-Windows-Security-Auditing
provider). Used to test log_correlation/parser.py without needing a real
.evtx file or a live domain controller.

Field names and structure match genuine Windows Security event layouts for:
  4768 - Kerberos TGT requested (AS-REQ)
  4769 - Kerberos service ticket requested (TGS-REQ)
  4624 - successful logon
  4625 - failed logon
  4662 - object access (used here for DCSync detection)
"""

EVENT_4769_RC4 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4769</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14337</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-09T14:32:10.123456Z"/>
    <EventRecordID>123456</EventRecordID>
    <Correlation/>
    <Execution ProcessID="600" ThreadID="700"/>
    <Channel>Security</Channel>
    <Computer>DC01.phantom.corp</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">helpdesk_svc</Data>
    <Data Name="TargetDomainName">PHANTOM.CORP</Data>
    <Data Name="ServiceName">helpdesk_svc</Data>
    <Data Name="ServiceSid">S-1-5-21-1111111111-2222222222-3333333333-1210</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">::ffff:10.10.10.55</Data>
    <Data Name="IpPort">51274</Data>
  </EventData>
</Event>"""

EVENT_4769_AES = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4769</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14337</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-09T14:35:02.998877Z"/>
    <EventRecordID>123457</EventRecordID>
    <Correlation/>
    <Execution ProcessID="600" ThreadID="700"/>
    <Channel>Security</Channel>
    <Computer>DC01.phantom.corp</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">web_frontend_svc</Data>
    <Data Name="TargetDomainName">PHANTOM.CORP</Data>
    <Data Name="ServiceName">web_frontend_svc</Data>
    <Data Name="ServiceSid">S-1-5-21-1111111111-2222222222-3333333333-1310</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="IpAddress">::ffff:10.10.10.60</Data>
    <Data Name="IpPort">51290</Data>
  </EventData>
</Event>"""

EVENT_4768 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4768</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14336</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-09T14:30:00.111222Z"/>
    <EventRecordID>123450</EventRecordID>
    <Correlation/>
    <Execution ProcessID="600" ThreadID="700"/>
    <Channel>Security</Channel>
    <Computer>DC01.phantom.corp</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetDomainName">PHANTOM.CORP</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="PreAuthType">2</Data>
    <Data Name="IpAddress">::ffff:10.10.10.55</Data>
    <Data Name="IpPort">51260</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>"""

EVENT_4624 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-09T14:28:45.555000Z"/>
    <EventRecordID>123440</EventRecordID>
    <Correlation/>
    <Execution ProcessID="600" ThreadID="700"/>
    <Channel>Security</Channel>
    <Computer>DC01.phantom.corp</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetDomainName">PHANTOM</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="WorkstationName">WKSTN01</Data>
    <Data Name="IpAddress">10.10.10.55</Data>
  </EventData>
</Event>"""

EVENT_4625 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-09T14:27:12.333000Z"/>
    <EventRecordID>123435</EventRecordID>
    <Correlation/>
    <Execution ProcessID="600" ThreadID="700"/>
    <Channel>Security</Channel>
    <Computer>DC01.phantom.corp</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="TargetDomainName">PHANTOM</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="WorkstationName">WKSTN07</Data>
    <Data Name="IpAddress">10.10.10.99</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="SubStatus">0xc000006a</Data>
  </EventData>
</Event>"""

# 4662 with DCSync rights (both GUIDs present) -- the actual attack signature
EVENT_4662_DCSYNC = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4662</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>14080</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-09T14:40:19.001122Z"/>
    <EventRecordID>123470</EventRecordID>
    <Correlation/>
    <Execution ProcessID="600" ThreadID="700"/>
    <Channel>Security</Channel>
    <Computer>DC01.phantom.corp</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserName">helpdesk_svc</Data>
    <Data Name="SubjectDomainName">PHANTOM</Data>
    <Data Name="ObjectServer">DS</Data>
    <Data Name="ObjectType">%{19195a5b-6da0-11d0-afd3-00c04fd930c9}</Data>
    <Data Name="ObjectName">DC=phantom,DC=corp</Data>
    <Data Name="Properties">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}</Data>
    <Data Name="AccessMask">0x100</Data>
  </EventData>
</Event>"""

# 4662 that is NOT DCSync -- ordinary object access, no replication GUIDs.
# Used to test that we don't false-positive on every 4662 event.
EVENT_4662_BENIGN = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4662</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>14080</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-09T14:41:00.445566Z"/>
    <EventRecordID>123471</EventRecordID>
    <Correlation/>
    <Execution ProcessID="600" ThreadID="700"/>
    <Channel>Security</Channel>
    <Computer>DC01.phantom.corp</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserName">bob</Data>
    <Data Name="SubjectDomainName">PHANTOM</Data>
    <Data Name="ObjectServer">DS</Data>
    <Data Name="ObjectType">%{bf967aba-0de6-11d0-a285-00aa003049e2}</Data>
    <Data Name="ObjectName">CN=Bob User,CN=Users,DC=phantom,DC=corp</Data>
    <Data Name="Properties">{bf967a05-0de6-11d0-a285-00aa003049e2}</Data>
    <Data Name="AccessMask">0x20</Data>
  </EventData>
</Event>"""

MALFORMED_XML = "<Event><System><EventID>4769</EventID></System>"  # missing closing tags