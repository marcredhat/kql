#!/usr/bin/env python3
"""Generate deterministic sample events for the KQL <-> PowerQuery proof.

Time windows (anchored to real wall-clock now so SDL accepts the events):

    BASELINE  : NOW - 8h  .. NOW - 2h
    RECENT    : NOW - 2h  .. NOW

A `time_anchor.json` is written alongside the events so rules.py uses the
same NOW / RECENT_START as the generator.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(20260531)

HERE = Path(__file__).parent
OUT = HERE / "events.jsonl"
ANCHOR = HERE / "time_anchor.json"

NOW = datetime.now(timezone.utc).replace(microsecond=0)
RECENT_START = NOW - timedelta(hours=2)
BASELINE_START = NOW - timedelta(hours=8)
BASELINE_END = RECENT_START

ANCHOR.write_text(json.dumps({
    "now": NOW.isoformat(),
    "recent_start": RECENT_START.isoformat(),
    "baseline_start": BASELINE_START.isoformat(),
}, indent=2))


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


events: list[dict] = []


def emit(event_type, ts, **fields):
    events.append({
        "event_type": event_type,
        "TimeGenerated": iso(ts),
        "ts_epoch_ms": int(ts.timestamp() * 1000),
        **fields,
    })


def in_baseline(offset_min: int):
    """Pick a time inside the baseline window using a minute offset."""
    span = (BASELINE_END - BASELINE_START).total_seconds() / 60
    return BASELINE_START + timedelta(minutes=offset_min % int(span))


def in_recent(offset_sec: int):
    return RECENT_START + timedelta(seconds=offset_sec)


# ---------------------------------------------------------------------------
# SigninLogs
# ---------------------------------------------------------------------------
USERS = ["alice@contoso.com", "bob@contoso.com", "carol@contoso.com",
         "dave@contoso.com", "eve@contoso.com"]
APPS = ["Office 365 Exchange Online", "Microsoft Teams", "Azure Portal"]
USER_HOME = {"alice@contoso.com": "US", "bob@contoso.com": "FR",
             "carol@contoso.com": "GB", "dave@contoso.com": "DE",
             "eve@contoso.com": "US"}

# Baseline (8h..2h ago): each user signs in 3x per app from their home country
for upn in USERS:
    home = USER_HOME[upn]
    for app in APPS[:2]:
        for i in range(3):
            emit("SigninLogs", in_baseline(i * 40 + 5 * USERS.index(upn)),
                 UserPrincipalName=upn, Identity=upn,
                 AppDisplayName=app, ResultType=0,
                 IPAddress=f"10.0.0.{20 + USERS.index(upn) * 10 + i}",
                 Location=home,
                 LocationDetails_country=home,
                 LocationDetails_state="HQ", LocationDetails_city="HQ",
                 UserAgent="Mozilla/5.0 (Windows NT 10.0) Edge/120.0",
                 DeviceDetail_os="Windows 10")

# Recent: eve burst across 10 NEW countries (anomalous + suspicious-travel +
# new-locations + rare-UA)
EVE_COUNTRIES = ["BR", "RU", "CN", "IR", "NG", "VN", "TR", "ID", "PK", "AR"]
for i, c in enumerate(EVE_COUNTRIES):
    emit("SigninLogs", in_recent(60 + i * 30),
         UserPrincipalName="eve@contoso.com", Identity="eve@contoso.com",
         AppDisplayName="Azure Portal", ResultType=0,
         IPAddress=f"203.0.113.{10 + i}", Location=c,
         LocationDetails_country=c,
         LocationDetails_state="NA", LocationDetails_city="NA",
         UserAgent="curl/8.4.0", DeviceDetail_os="Linux")

# Recent: slow brute force from one IP across many users (fires brute-force)
ATTACKER_IP = "198.51.100.7"
ATTACKER_TARGETS = USERS + ["frank@contoso.com"]
for u_idx, u in enumerate(ATTACKER_TARGETS):
    for k in range(4):
        emit("SigninLogs", in_recent(120 + u_idx * 60 + k * 10),
             UserPrincipalName=u, Identity=u,
             AppDisplayName="Office 365 Exchange Online", ResultType=50126,
             ResultDescription="Invalid username or password",
             IPAddress=ATTACKER_IP, Location="RU",
             LocationDetails_country="RU",
             LocationDetails_state="NA", LocationDetails_city="Moscow",
             UserAgent="Mozilla/5.0 (Windows NT 10.0) Edge/120.0",
             DeviceDetail_os="Windows 10")

# Recent: dave normal signin (joins with audit log priv-escalation)
emit("SigninLogs", in_recent(30),
     UserPrincipalName="dave@contoso.com", Identity="dave@contoso.com",
     AppDisplayName="Azure Portal", ResultType=0,
     IPAddress="203.0.113.99", Location="DE",
     LocationDetails_country="DE",
     LocationDetails_state="BE", LocationDetails_city="Berlin",
     UserAgent="Mozilla/5.0 (Windows NT 10.0) Edge/120.0",
     DeviceDetail_os="Windows 10")

# Recent: bob travels to 4 countries today (suspicious travel - small ambit
# of just dailies could fire on >3 countries threshold)
for i, c in enumerate(["FR", "DE", "IT", "ES"]):
    emit("SigninLogs", in_recent(20 + i * 5),
         UserPrincipalName="bob@contoso.com", Identity="bob@contoso.com",
         AppDisplayName="Microsoft Teams", ResultType=0,
         IPAddress=f"10.0.0.{60 + i}", Location=c,
         LocationDetails_country=c,
         LocationDetails_state="NA", LocationDetails_city="NA",
         UserAgent="Mozilla/5.0 (Windows NT 10.0) Edge/120.0",
         DeviceDetail_os="Windows 10")

# ---------------------------------------------------------------------------
# AuditLogs
# ---------------------------------------------------------------------------
# Baseline: HR-Sync "Update user"
for i in range(10):
    emit("AuditLogs", in_baseline(i * 30),
         OperationName="Update user", Category="UserManagement",
         CorrelationId=f"base-{i}",
         InitiatedBy_app_displayName="HR-Sync",
         InitiatedBy_app_ipAddress="10.0.0.5",
         InitiatedBy_user_userPrincipalName=None,
         InitiatedBy_user_ipAddress=None,
         TargetResources_0_userPrincipalName="alice@contoso.com",
         TargetResources_0_displayName="alice")

# Recent: rare ops
emit("AuditLogs", in_recent(180),
     OperationName="Add service principal", Category="ApplicationManagement",
     CorrelationId="corr-priv-esc-1",
     InitiatedBy_app_displayName=None,
     InitiatedBy_app_ipAddress=None,
     InitiatedBy_user_userPrincipalName="dave@contoso.com",
     InitiatedBy_user_ipAddress="203.0.113.99",
     TargetResources_0_userPrincipalName="svcprincipal@contoso.com",
     TargetResources_0_displayName="SuspiciousApp")
emit("AuditLogs", in_recent(240),
     OperationName="Consent to application", Category="ApplicationManagement",
     CorrelationId="corr-consent-1",
     InitiatedBy_app_displayName=None,
     InitiatedBy_app_ipAddress=None,
     InitiatedBy_user_userPrincipalName="eve@contoso.com",
     InitiatedBy_user_ipAddress="203.0.113.10",
     TargetResources_0_userPrincipalName="eve@contoso.com",
     TargetResources_0_displayName="MaliciousOAuthApp")

# ---------------------------------------------------------------------------
# AzureActivity
# ---------------------------------------------------------------------------
for i in range(6):
    emit("AzureActivity", in_recent(300 + i * 30),
         OperationNameValue="microsoft.compute/snapshots/write",
         ActivityStatusValue="Success",
         CallerIpAddress="198.51.100.50",
         Caller="attacker@external.com",
         CorrelationId=f"az-corr-{i}",
         ResourceGroup="prod-rg", SubscriptionId="sub-001")

# ---------------------------------------------------------------------------
# CommonSecurityLog
# ---------------------------------------------------------------------------
# Normal baseline traffic
for i in range(20):
    emit("CommonSecurityLog", in_baseline(i * 15),
         DeviceVendor="Palo Alto Networks", Activity="TRAFFIC",
         DeviceName="pa-fw-01", SourceUserID="alice",
         SourceIP=f"10.0.1.{10 + i}", SourcePort=49000 + i,
         DestinationIP="142.250.74.110", DestinationPort=443,
         SentBytes=2048, ReceivedBytes=16384,
         Message="allow web access to 142.250.74.110",
         DeviceEventClassID="end", LogSeverity=3,
         DeviceAction="allow", DeviceProduct="PAN-OS")

# Beacon: 60 evenly-spaced events
for i in range(60):
    emit("CommonSecurityLog", in_recent(60 * i),
         DeviceVendor="Palo Alto Networks", Activity="TRAFFIC",
         DeviceName="pa-fw-01", SourceUserID="dave",
         SourceIP="10.0.2.42", SourcePort=51000 + i,
         DestinationIP="185.220.101.7", DestinationPort=8443,
         SentBytes=512, ReceivedBytes=128,
         Message="beacon to C2 185.220.101.7",
         DeviceEventClassID="end", LogSeverity=5,
         DeviceAction="allow", DeviceProduct="PAN-OS")

# IOC match
emit("CommonSecurityLog", in_recent(500),
     DeviceVendor="Palo Alto Networks", Activity="TRAFFIC",
     DeviceName="pa-fw-01", SourceUserID="carol",
     SourceIP="10.0.3.11", SourcePort=49888,
     DestinationIP="185.220.101.7", DestinationPort=443,
     SentBytes=1024, ReceivedBytes=2048,
     Message="allow access to 185.220.101.7",
     DeviceEventClassID="end", LogSeverity=5,
     DeviceAction="allow", DeviceProduct="PAN-OS")

# Firewall logs for brute-force enrichment
for i in range(3):
    emit("CommonSecurityLog", in_recent(700 + i * 60),
         DeviceVendor="Palo Alto Networks", Activity="TRAFFIC",
         DeviceName="pa-fw-01", SourceUserID="-",
         SourceIP=ATTACKER_IP, SourcePort=44000 + i,
         DestinationIP="10.0.0.10", DestinationPort=443,
         SentBytes=256, ReceivedBytes=512,
         Message=f"deny session from {ATTACKER_IP}",
         DeviceEventClassID="deny", LogSeverity=6,
         DeviceAction="deny", DeviceProduct="PAN-OS",
         AdditionalExtensions=f"src={ATTACKER_IP} dst=10.0.0.10")

# ---------------------------------------------------------------------------
# ThreatIntelIndicators
# ---------------------------------------------------------------------------
emit("ThreatIntelIndicators", in_baseline(60),
     Id="ti-ioc-001", ObservableKey="ipv4-addr:value",
     ObservableValue="185.220.101.7",
     IsActive=True,
     ValidUntil=iso(NOW + timedelta(days=30)),
     Confidence=85, Tags="c2,tor-exit",
     AdditionalFields_TLPLevel="AMBER")

# ---------------------------------------------------------------------------
# SecurityEvent
# ---------------------------------------------------------------------------
# Baseline 4688: stable processes
for i in range(40):
    proc = ["svchost.exe", "explorer.exe", "chrome.exe", "outlook.exe"][i % 4]
    emit("SecurityEvent", in_baseline(i * 8),
         EventID=4688, Computer="WIN-WS01",
         Account="CONTOSO\\alice",
         NewProcessName=f"C:\\Windows\\System32\\{proc}",
         CommandLine=f"\"{proc}\"",
         ParentProcessName="C:\\Windows\\explorer.exe")

# Recent NEW process
emit("SecurityEvent", in_recent(900),
     EventID=4688, Computer="WIN-WS02",
     Account="CONTOSO\\dave",
     NewProcessName="C:\\Users\\dave\\AppData\\Local\\Temp\\mimikatz.exe",
     CommandLine="mimikatz.exe sekurlsa::logonpasswords",
     ParentProcessName="C:\\Windows\\System32\\cmd.exe")

# Recent normal processes
for proc in ["svchost.exe", "explorer.exe", "chrome.exe", "outlook.exe"]:
    emit("SecurityEvent", in_recent(1000 + hash(proc) % 100),
         EventID=4688, Computer="WIN-WS01", Account="CONTOSO\\alice",
         NewProcessName=f"C:\\Windows\\System32\\{proc}",
         CommandLine=f"\"{proc}\"",
         ParentProcessName="C:\\Windows\\explorer.exe")

# Baseline 4624: alice logs in at "business hours" (use the actual hour
# values seen in baseline window so off-hours later fires properly)
# In our compressed model, "business hours" = hour within first 4h of
# baseline window; recent off-hours = a fixed flag we set explicitly.
for i in range(15):
    emit("SecurityEvent", in_baseline(i * 20),
         EventID=4624, Activity="An account was successfully logged on",
         LogonTypeName="2 - Interactive", AccountType="User",
         TargetUserName="CONTOSO\\alice", TargetDomainName="CONTOSO",
         SubjectUserName="alice", Computer="WIN-WS01",
         WorkstationName="WIN-WS01", IpAddress="10.0.0.20",
         ProcessName="C:\\Windows\\System32\\winlogon.exe",
         PrivilegeList="-", Status="0x0", SubStatus="0x0",
         is_off_hours=False)

# Recent off-hours logon (we mark it via a dedicated boolean so neither
# engine has to know real clock semantics)
emit("SecurityEvent", in_recent(60),
     EventID=4624, Activity="An account was successfully logged on",
     LogonTypeName="10 - RemoteInteractive", AccountType="User",
     TargetUserName="CONTOSO\\alice", TargetDomainName="CONTOSO",
     SubjectUserName="alice", Computer="WIN-WS01",
     WorkstationName="ATTACKER-PC", IpAddress="198.51.100.7",
     ProcessName="C:\\Windows\\System32\\winlogon.exe",
     PrivilegeList="SeDebugPrivilege", Status="0x0", SubStatus="0x0",
     is_off_hours=True)

# ---------------------------------------------------------------------------
# OfficeActivity (SharePoint anomaly)
# ---------------------------------------------------------------------------
for i in range(3):
    emit("OfficeActivity", in_baseline(60 + i * 90),
         RecordType="SharePointFileOperation", Operation="FileDownloaded",
         UserId="dave@contoso.com", UserType="Regular",
         Site_Url="https://contoso.sharepoint.com/sites/finance",
         ClientIP="10.0.0.30", UserAgent="OneDrive/22.0",
         OfficeObjectId="https://contoso.sharepoint.com/sites/finance/report.xlsx",
         OfficeWorkload="SharePoint")

for i in range(200):
    emit("OfficeActivity", in_recent(300 + i * 2),
         RecordType="SharePointFileOperation", Operation="FileDownloaded",
         UserId="dave@contoso.com", UserType="Regular",
         Site_Url="https://contoso.sharepoint.com/sites/finance",
         ClientIP="10.0.0.30", UserAgent="python-requests/2.31",
         OfficeObjectId=f"https://contoso.sharepoint.com/sites/finance/secret-{i}.xlsx",
         OfficeWorkload="SharePoint")

# ---------------------------------------------------------------------------
# DeviceFileEvents
# ---------------------------------------------------------------------------
for fn in ["Q4-Confidential.docx", "MergerPlan.pdf", "RestrictedSalary.xlsx"]:
    for action in ["FileAccessed", "FileCopied", "FileMoved"]:
        emit("DeviceFileEvents", in_recent(800),
             FileName=fn, FolderPath=f"C:\\Confidential\\{fn}",
             ActionType=action,
             InitiatingProcessAccountName="CONTOSO\\dave",
             DeviceName="WIN-WS02")


OUT.write_text("\n".join(json.dumps(e, default=str) for e in events) + "\n")
print(f"NOW = {NOW.isoformat()}")
print(f"BASELINE = {BASELINE_START.isoformat()} .. {BASELINE_END.isoformat()}")
print(f"RECENT = {RECENT_START.isoformat()} .. {NOW.isoformat()}")
print(f"Wrote {len(events)} events -> {OUT}")
print(f"Wrote anchor -> {ANCHOR}")
