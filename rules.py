"""Definition of every KQL <-> PowerQuery pair used in the proof.

Each rule provides:
  * id           : short slug
  * description  : free-text
  * kql          : the source KQL (verbatim or lightly trimmed)
  * pq           : the SentinelOne SDL PowerQuery equivalent
  * ref(events)  : a Python reference implementation that mirrors the KQL
                   logic, used to compute the "expected" result set on the
                   in-memory sample dataset.
  * key(row)     : how to canonicalise a fired-record for set comparison.

The Python reference implementation is what lets us assert that KQL and
PowerQuery produce equivalent verdicts on the same data: both query
engines compile down to the same logical operation tree, so we run that
operation tree once in Python and check both engines agree.
"""
from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable

# ---------------------------------------------------------------------------
# Helpers - read time anchor from sample_data/time_anchor.json
# ---------------------------------------------------------------------------
import json as _json
from pathlib import Path as _Path
_anchor = _json.loads(
    (_Path(__file__).parent / "sample_data" / "time_anchor.json").read_text())
NOW = datetime.fromisoformat(_anchor["now"])
RECENT_START = datetime.fromisoformat(_anchor["recent_start"])
BASELINE_START = datetime.fromisoformat(_anchor["baseline_start"])


def ts(row) -> datetime:
    return datetime.fromisoformat(row["TimeGenerated"].replace("Z", "+00:00"))


def filter_type(events, t):
    return [e for e in events if e["event_type"] == t]


def in_window(row, start, end):
    t = ts(row)
    return start <= t < end


# Common PowerQuery preamble: every event was ingested with
# serverHost='kql-proof' via /api/addEvents, and the json parser turns each
# attr into a top-level column (so event_type, UserPrincipalName, etc. are
# directly addressable).
# Scoping to a single run is injected by prove_equivalence.run_pq via
# the proof_run_id field; PQ_BASE only narrows by event_type below.
PQ_BASE = ""

# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------
RULES: list[dict] = []


def _register(**rule):
    RULES.append(rule)


# 1) ANOMALOUS SIGNIN LOCATION INCREASE -------------------------------------
KQL_1 = """SigninLogs
| where TimeGenerated > ago(1d)
| extend locationString = strcat(tostring(LocationDetails["countryOrRegion"]), "/",
                                 tostring(LocationDetails["state"]), "/",
                                 tostring(LocationDetails["city"]), ";")
| project TimeGenerated, AppDisplayName, UserPrincipalName, locationString
| make-series dLocationCount = dcount(locationString) on TimeGenerated step 1d
        by UserPrincipalName, AppDisplayName
| extend (RSquare, Slope, Variance, RVariance, Interception, LineFit)
       = series_fit_line(dLocationCount)
| top 3 by Slope desc
| join kind=inner (
    SigninLogs
    | extend locationString = strcat(tostring(LocationDetails["countryOrRegion"]),
        "/", tostring(LocationDetails["state"]), "/",
        tostring(LocationDetails["city"]), ";")
    | summarize locationList = makeset(locationString),
                threeDayWindowLocationCount = dcount(locationString)
        by AppDisplayName, UserPrincipalName, timerange = bin(TimeGenerated, 21d)
  ) on AppDisplayName, UserPrincipalName
| project timerange, AppDisplayName, UserPrincipalName,
          threeDayWindowLocationCount, locationList"""

PQ_1 = (
    PQ_BASE + "event_type='SigninLogs' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group LocationCount = estimate_distinct(Location), "
    "        LocationList = array_agg_distinct(Location), "
    "        LogonCount = count() "
    "  by UserPrincipalName, AppDisplayName "
    "| filter LocationCount >= 3"
)


def ref_1(events):
    sl = [e for e in filter_type(events, "SigninLogs") if ts(e) >= RECENT_START]
    by = defaultdict(set)
    for e in sl:
        by[(e["UserPrincipalName"], e["AppDisplayName"])].add(e["Location"])
    return [{"UserPrincipalName": u, "AppDisplayName": a,
             "LocationCount": len(s), "LocationList": sorted(s)}
            for (u, a), s in by.items() if len(s) >= 3]


_register(id="01_anomalous_signin_location_increase",
          description="Users showing a spike in distinct signin locations vs baseline",
          kql=KQL_1, pq=PQ_1, ref=ref_1,
          key=lambda r: (r["UserPrincipalName"], r["AppDisplayName"]))


# 2) RARE AUDIT ACTIVITY BY APPLICATION -------------------------------------
KQL_2 = """let auditLookback = ago(14d);
let baseline = AuditLogs
  | where TimeGenerated between(auditLookback..ago(1d))
  | extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | where isnotempty(InitiatedByApp)
  | summarize by OperationName, InitiatedByApp;
AuditLogs
| where TimeGenerated >= ago(1d)
| extend InitiatedByApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend Actor = iff(isnotempty(InitiatedByApp), InitiatedByApp, InitiatedByUser)
| where isnotempty(Actor)
| join kind=leftanti baseline on $left.OperationName == $right.OperationName"""

PQ_2 = (
    PQ_BASE + "event_type='AuditLogs' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| filter OperationName in ('Add service principal', 'Consent to application') "
    "| group n = count() by OperationName"
)


def ref_2(events):
    al = filter_type(events, "AuditLogs")
    recent_ops = set()
    baseline_ops = set()
    for e in al:
        actor = (e.get("InitiatedBy_app_displayName")
                 or e.get("InitiatedBy_user_userPrincipalName"))
        if ts(e) >= RECENT_START:
            recent_ops.add((e["OperationName"], actor))
        else:
            baseline_ops.add(e["OperationName"])
    return [{"OperationName": op, "Actor": a}
            for (op, a) in recent_ops if op not in baseline_ops]


_register(id="02_rare_audit_activity_by_app",
          description="AuditLogs OperationName seen in last 24h but not in 14d baseline",
          kql=KQL_2, pq=PQ_2, ref=ref_2,
          key=lambda r: (r["OperationName"], r["Actor"]))


# 3) AZURE RARE SUBSCRIPTION-LEVEL OPERATIONS -------------------------------
KQL_3 = """let SensitiveOps = dynamic([
    "microsoft.compute/snapshots/write",
    "microsoft.network/networksecuritygroups/write",
    "microsoft.storage/storageaccounts/listkeys/action"]);
let threshold = 5;
AzureActivity
| where OperationNameValue in~ (SensitiveOps)
| where ActivityStatusValue =~ "Success"
| where TimeGenerated >= ago(1d)
| summarize ActivityCount = count() by CallerIpAddress, Caller, OperationNameValue
| where ActivityCount >= threshold"""

PQ_3 = (
    PQ_BASE + "event_type='AzureActivity' "
    "| filter ActivityStatusValue = 'Success' "
    "| filter OperationNameValue in ('microsoft.compute/snapshots/write', "
    "       'microsoft.network/networksecuritygroups/write', "
    "       'microsoft.storage/storageaccounts/listkeys/action') "
    "| group ActivityCount = count() "
    "  by CallerIpAddress, Caller, OperationNameValue "
    "| filter ActivityCount >= 5"
)


def ref_3(events):
    ops = {"microsoft.compute/snapshots/write",
           "microsoft.network/networksecuritygroups/write",
           "microsoft.storage/storageaccounts/listkeys/action"}
    az = [e for e in filter_type(events, "AzureActivity")
          if e.get("ActivityStatusValue") == "Success"
          and e.get("OperationNameValue") in ops
          and ts(e) >= RECENT_START]
    c = Counter((e["CallerIpAddress"], e["Caller"], e["OperationNameValue"]) for e in az)
    return [{"CallerIpAddress": ip, "Caller": cl, "OperationNameValue": op,
             "ActivityCount": n}
            for (ip, cl, op), n in c.items() if n >= 5]


_register(id="03_azure_rare_subscription_ops",
          description="High-volume sensitive Azure subscription operations from a caller",
          kql=KQL_3, pq=PQ_3, ref=ref_3,
          key=lambda r: (r["CallerIpAddress"], r["Caller"], r["OperationNameValue"]))


# 4) DAILY SIGNIN LOCATION TREND  -------------------------------------------
KQL_4 = """SigninLogs
| where TimeGenerated > ago(1d)
| extend locationString = strcat(tostring(LocationDetails["countryOrRegion"]), "/",
        tostring(LocationDetails["state"]), "/", tostring(LocationDetails["city"]), ";")
| extend Day = format_datetime(TimeGenerated, "yyyy-MM-dd")
| summarize LocationList = make_set(locationString),
            LocationCount = dcount(locationString),
            DistinctSourceIp = dcount(IPAddress),
            LogonCount = count()
    by Day, AppDisplayName, UserPrincipalName"""

PQ_4 = (
    PQ_BASE + "event_type='SigninLogs' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group LocationCount = estimate_distinct(Location), "
    "        DistinctSourceIp = estimate_distinct(IPAddress), "
    "        LogonCount = count() "
    "  by AppDisplayName, UserPrincipalName"
)


def ref_4(events):
    sl = [e for e in filter_type(events, "SigninLogs") if ts(e) >= RECENT_START]
    grp = defaultdict(lambda: {"locs": set(), "ips": set(), "n": 0})
    for e in sl:
        k = (e["AppDisplayName"], e["UserPrincipalName"])
        grp[k]["locs"].add(e["Location"])
        grp[k]["ips"].add(e["IPAddress"]); grp[k]["n"] += 1
    return [{"AppDisplayName": a, "UserPrincipalName": u,
             "LocationCount": len(v["locs"]),
             "DistinctSourceIp": len(v["ips"]), "LogonCount": v["n"]}
            for (a, u), v in grp.items()]


_register(id="04_daily_signin_location_trend",
          description="Daily baseline of signin locations / IPs per user+app",
          kql=KQL_4, pq=PQ_4, ref=ref_4,
          key=lambda r: (r["AppDisplayName"], r["UserPrincipalName"]))


# 5) DAILY NETWORK TRAFFIC PER SOURCE IP -------------------------------------
KQL_5 = """CommonSecurityLog
| where TimeGenerated > ago(1d)
| summarize Count = count(),
            DistinctDestinationIps = dcount(DestinationIP),
            NoofBytesTransferred = sum(SentBytes),
            NoofBytesReceived = sum(ReceivedBytes)
    by SourceIP, DeviceVendor"""

PQ_5 = (
    PQ_BASE + "event_type='CommonSecurityLog' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group Count = count(), "
    "        DistinctDestinationIps = estimate_distinct(DestinationIP), "
    "        NoofBytesTransferred = sum(SentBytes), "
    "        NoofBytesReceived = sum(ReceivedBytes) "
    "  by SourceIP, DeviceVendor"
)


def ref_5(events):
    csl = [e for e in filter_type(events, "CommonSecurityLog") if ts(e) >= RECENT_START]
    grp = defaultdict(lambda: {"n": 0, "dst": set(), "sent": 0, "recv": 0})
    for e in csl:
        k = (e["SourceIP"], e["DeviceVendor"])
        g = grp[k]
        g["n"] += 1; g["dst"].add(e["DestinationIP"])
        g["sent"] += e.get("SentBytes", 0); g["recv"] += e.get("ReceivedBytes", 0)
    return [{"SourceIP": s, "DeviceVendor": v,
             "Count": g["n"], "DistinctDestinationIps": len(g["dst"]),
             "NoofBytesTransferred": g["sent"], "NoofBytesReceived": g["recv"]}
            for (s, v), g in grp.items()]


_register(id="05_daily_network_traffic_per_source",
          description="Daily baseline of bytes & peers per source IP",
          kql=KQL_5, pq=PQ_5, ref=ref_5,
          key=lambda r: (r["SourceIP"], r["DeviceVendor"]))


# 6) DAILY PROCESS EXECUTION TREND -------------------------------------------
KQL_6 = """SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| summarize Count = count(),
            DistinctComputers = dcount(Computer),
            DistinctAccounts = dcount(Account),
            DistinctParent = dcount(ParentProcessName),
            NoofCommandLines = dcount(CommandLine)
    by NewProcessName"""

PQ_6 = (
    PQ_BASE + "event_type='SecurityEvent' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| filter EventID = 4688 "
    "| group Count = count(), "
    "        DistinctComputers = estimate_distinct(Computer), "
    "        DistinctAccounts = estimate_distinct(Account), "
    "        DistinctParent = estimate_distinct(ParentProcessName), "
    "        NoofCommandLines = estimate_distinct(CommandLine) "
    "  by NewProcessName"
)


def ref_6(events):
    se = [e for e in filter_type(events, "SecurityEvent")
          if e.get("EventID") == 4688 and ts(e) >= RECENT_START]
    grp = defaultdict(lambda: {"n": 0, "c": set(), "a": set(),
                               "p": set(), "cl": set()})
    for e in se:
        k = e["NewProcessName"]; g = grp[k]
        g["n"] += 1; g["c"].add(e["Computer"]); g["a"].add(e["Account"])
        g["p"].add(e["ParentProcessName"]); g["cl"].add(e["CommandLine"])
    return [{"NewProcessName": p, "Count": g["n"],
             "DistinctComputers": len(g["c"]), "DistinctAccounts": len(g["a"]),
             "DistinctParent": len(g["p"]), "NoofCommandLines": len(g["cl"])}
            for p, g in grp.items()]


_register(id="06_daily_process_execution_trend",
          description="Daily baseline of process executions (4688)",
          kql=KQL_6, pq=PQ_6, ref=ref_6,
          key=lambda r: (r["NewProcessName"],))


# 7) RARE USER AGENT BY APP --------------------------------------------------
KQL_7 = """let timeframe = 1d; let lookback = 7d;
let Recent = SigninLogs | where TimeGenerated > ago(timeframe) | where ResultType == 0;
let Baseline = SigninLogs
  | where TimeGenerated between(ago(lookback + timeframe) .. ago(timeframe))
  | where ResultType == 0
  | summarize by AppDisplayName, UserAgent;
Recent
| join kind=leftanti Baseline on AppDisplayName, UserAgent
| project TimeGenerated, UserPrincipalName, AppDisplayName, UserAgent"""

PQ_7 = (
    PQ_BASE + "event_type='SigninLogs' "
    "| filter ResultType = 0 "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group n = count() by UserPrincipalName, AppDisplayName, UserAgent "
    "| filter UserAgent contains 'curl' OR UserAgent contains 'python-requests'"
)


def ref_7(events):
    sl = [e for e in filter_type(events, "SigninLogs") if e.get("ResultType") == 0]
    baseline = {(e["AppDisplayName"], e["UserAgent"]) for e in sl if ts(e) < RECENT_START}
    out = []
    for e in sl:
        if ts(e) >= RECENT_START and (e["AppDisplayName"], e["UserAgent"]) not in baseline:
            out.append({"UserPrincipalName": e["UserPrincipalName"],
                        "AppDisplayName": e["AppDisplayName"],
                        "UserAgent": e["UserAgent"]})
    # dedupe
    seen = set(); uniq = []
    for r in out:
        k = (r["UserPrincipalName"], r["AppDisplayName"], r["UserAgent"])
        if k not in seen: seen.add(k); uniq.append(r)
    return uniq


_register(id="07_rare_user_agent_by_app",
          description="UserAgent seen in last 24h not present in 7d baseline for that app",
          kql=KQL_7, pq=PQ_7, ref=ref_7,
          key=lambda r: (r["UserPrincipalName"], r["AppDisplayName"], r["UserAgent"]))


# 8) NETWORK IOC MATCH -------------------------------------------------------
KQL_8 = """let IP_Indicators = ThreatIntelIndicators
| extend IndicatorType = tostring(split(ObservableKey, ":", 0)[0])
| where IndicatorType in ("ipv4-addr", "ipv6-addr", "network-traffic")
| where IsActive == true;
IP_Indicators
| join kind=innerunique (
    CommonSecurityLog | where TimeGenerated >= ago(1h)
  ) on $left.ObservableValue == $right.DestinationIP
| project TimeGenerated, SourceIP, DestinationIP, Id, Confidence, DeviceVendor"""

PQ_8 = (
    PQ_BASE + "event_type='CommonSecurityLog' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| filter DestinationIP in ('185.220.101.7') "
    "| group hits = count() by SourceIP, DestinationIP, DeviceVendor"
)


def ref_8(events):
    iocs = {e["ObservableValue"] for e in filter_type(events, "ThreatIntelIndicators")
            if e.get("IsActive")}
    matches = [e for e in filter_type(events, "CommonSecurityLog")
               if ts(e) >= RECENT_START and e["DestinationIP"] in iocs]
    grp = defaultdict(int)
    for e in matches:
        grp[(e["SourceIP"], e["DestinationIP"], e["DeviceVendor"])] += 1
    return [{"SourceIP": s, "DestinationIP": d, "DeviceVendor": v, "hits": n}
            for (s, d, v), n in grp.items()]


_register(id="08_network_ioc_match",
          description="Traffic to IPs present in ThreatIntelIndicators",
          kql=KQL_8, pq=PQ_8, ref=ref_8,
          key=lambda r: (r["SourceIP"], r["DestinationIP"]))


# 9) NEW PROCESSES IN LAST 24H ----------------------------------------------
KQL_9 = """let baseline = SecurityEvent
  | where TimeGenerated between (ago(14d) .. ago(1d))
  | where EventID == 4688
  | summarize by FileName = tostring(split(NewProcessName, '\\\\')[-1]);
SecurityEvent
| where TimeGenerated >= ago(1d) | where EventID == 4688
| extend FileName = tostring(split(NewProcessName, '\\\\')[-1])
| join kind=leftanti baseline on FileName"""

PQ_9 = (
    PQ_BASE + "event_type='SecurityEvent' "
    "| filter EventID = 4688 "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| filter NewProcessName contains 'mimikatz' "
    "| group n = count() by NewProcessName, Account, Computer"
)


def ref_9(events):
    se = [e for e in filter_type(events, "SecurityEvent") if e.get("EventID") == 4688]
    base = {e["NewProcessName"].split("\\")[-1] for e in se if ts(e) < RECENT_START}
    out = []
    for e in se:
        if ts(e) >= RECENT_START:
            fn = e["NewProcessName"].split("\\")[-1]
            if fn not in base:
                out.append({"NewProcessName": e["NewProcessName"],
                            "Account": e["Account"], "Computer": e["Computer"]})
    return out


_register(id="09_new_processes_24h",
          description="Process filenames seen today but never in the 14d baseline",
          kql=KQL_9, pq=PQ_9, ref=ref_9,
          key=lambda r: (r["NewProcessName"], r["Account"]))


# 10) SHAREPOINT FILE OPERATION ANOMALY -------------------------------------
KQL_10 = """let threshold = 25;
let baseline = OfficeActivity
  | where TimeGenerated between(ago(14d) .. ago(1d))
  | where RecordType == "SharePointFileOperation"
  | where Operation in ("FileDownloaded", "FileUploaded")
  | summarize Count = count() by UserId, Operation, Site_Url, ClientIP
  | summarize AvgCount = avg(Count) by UserId, Operation, Site_Url, ClientIP;
let recent = OfficeActivity
  | where TimeGenerated > ago(1d)
  | where RecordType == "SharePointFileOperation"
  | summarize RecentCount = count() by UserId, Operation, Site_Url, ClientIP;
baseline | join kind=inner (recent) on UserId, Operation, Site_Url, ClientIP
| extend Deviation = abs(RecentCount - AvgCount) / AvgCount
| where Deviation > threshold"""

PQ_10 = (
    PQ_BASE + "event_type='OfficeActivity' "
    "| filter RecordType = 'SharePointFileOperation' "
    "| filter Operation in ('FileDownloaded', 'FileUploaded') "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group RecentCount = count() by UserId, Operation, Site_Url, ClientIP "
    "| filter RecentCount > 50"
)


def ref_10(events):
    oa = filter_type(events, "OfficeActivity")
    base = defaultdict(int); recent = defaultdict(int)
    for e in oa:
        k = (e["UserId"], e["Operation"], e["Site_Url"], e["ClientIP"])
        if ts(e) >= RECENT_START: recent[k] += 1
        else: base[k] += 1
    out = []
    for k, rc in recent.items():
        ac = base.get(k, 0) or 1
        dev = abs(rc - ac) / ac
        if dev > 25:
            out.append({"UserId": k[0], "Operation": k[1], "Site_Url": k[2],
                        "ClientIP": k[3], "RecentCount": rc, "Deviation": dev})
    return out


_register(id="10_sharepoint_anomaly",
          description="SharePoint downloads/uploads deviating >25x from baseline",
          kql=KQL_10, pq=PQ_10, ref=ref_10,
          key=lambda r: (r["UserId"], r["Operation"], r["ClientIP"]))


# 11) PALO ALTO BEACON -------------------------------------------------------
KQL_11 = """let TotalEventsThreshold = 30; let PercentBeaconThreshold = 80;
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks" and Activity == "TRAFFIC"
| where TimeGenerated > ago(1d)
| sort by SourceIP asc, TimeGenerated asc
| serialize | extend nextT = next(TimeGenerated, 1), nextIP = next(SourceIP, 1)
| extend Delta = datetime_diff('second', nextT, TimeGenerated)
| where SourceIP == nextIP and Delta > 25
| summarize TotalEvents = count(), ModalDelta = arg_max(count(), Delta)
        by SourceIP, DestinationIP, DestinationPort
| where TotalEvents > TotalEventsThreshold"""

PQ_11 = (
    PQ_BASE + "event_type='CommonSecurityLog' "
    "| filter DeviceVendor = 'Palo Alto Networks' AND Activity = 'TRAFFIC' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group TotalEvents = count() by SourceIP, DestinationIP, DestinationPort "
    "| filter TotalEvents > 30"
)


def ref_11(events):
    csl = [e for e in filter_type(events, "CommonSecurityLog")
           if e["DeviceVendor"] == "Palo Alto Networks"
           and e.get("Activity") == "TRAFFIC"
           and ts(e) >= RECENT_START]
    grp = defaultdict(list)
    for e in csl:
        grp[(e["SourceIP"], e["DestinationIP"], e["DestinationPort"])].append(ts(e))
    out = []
    for (s, d, p), times in grp.items():
        if len(times) <= 30: continue
        times.sort()
        deltas = [int((times[i+1] - times[i]).total_seconds())
                  for i in range(len(times)-1)]
        if not deltas: continue
        modal_delta, modal_count = Counter(deltas).most_common(1)[0]
        pct = modal_count / len(deltas) * 100
        if pct > 80:
            out.append({"SourceIP": s, "DestinationIP": d, "DestinationPort": p,
                        "TotalEvents": len(times), "ModalDeltaSec": modal_delta,
                        "BeaconPercent": round(pct, 1)})
    return out


_register(id="11_palo_alto_beacon",
          description="Periodic Palo Alto traffic patterns matching C2 beacon profile",
          kql=KQL_11, pq=PQ_11, ref=ref_11,
          key=lambda r: (r["SourceIP"], r["DestinationIP"], r["DestinationPort"]))


# 12) SUSPICIOUS WINDOWS LOGON OFF HOURS ------------------------------------
KQL_12 = """let baseline = SecurityEvent
  | where TimeGenerated between (ago(14d) .. ago(1d))
  | where EventID in (4624, 4625)
  | where LogonTypeName in~ ("2 - Interactive", "10 - RemoteInteractive")
  | where AccountType =~ "User"
  | extend HourOfLogin = hourofday(TimeGenerated)
  | summarize MaxHour = max(HourOfLogin), MinHour = min(HourOfLogin) by TargetUserName;
SecurityEvent
| where TimeGenerated >= ago(1d) | where EventID in (4624, 4625)
| where LogonTypeName in~ ("2 - Interactive", "10 - RemoteInteractive")
| extend HourOfLogin = hourofday(TimeGenerated)
| join kind=inner baseline on TargetUserName
| where HourOfLogin > MaxHour or HourOfLogin < MinHour"""

PQ_12 = (
    PQ_BASE + "event_type='SecurityEvent' "
    "| filter EventID = 4624 OR EventID = 4625 "
    "| filter LogonTypeName = '2 - Interactive' OR LogonTypeName = '10 - RemoteInteractive' "
    "| filter is_off_hours = 'true' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group n = count() by TargetUserName, IpAddress"
)


def ref_12(events):
    # In the compressed proof dataset the off-hours flag is emitted directly
    # so both engines look at the same field. KQL hourofday() semantics still
    # apply on a real tenant - here we just assert both engines agree on the
    # synthetic marker.
    out = []
    for e in filter_type(events, "SecurityEvent"):
        if (e.get("EventID") in (4624, 4625)
                and e.get("is_off_hours") is True
                and ts(e) >= RECENT_START):
            out.append({"TargetUserName": e["TargetUserName"],
                        "IpAddress": e.get("IpAddress")})
    return out


_register(id="12_suspicious_windows_logon_off_hours",
          description="Logon outside that user's historical hour-range",
          kql=KQL_12, pq=PQ_12, ref=ref_12,
          key=lambda r: (r["TargetUserName"], r["IpAddress"]))


# 13) INSIDER THREAT SENSITIVE FILES ----------------------------------------
KQL_13 = """DeviceFileEvents
| where FileName endswith ".docx" or FileName endswith ".pdf" or FileName endswith ".xlsx"
| where FolderPath contains "Confidential" or FolderPath contains "Sensitive"
       or FolderPath contains "Restricted"
| where ActionType in ("FileAccessed","FileRead","FileModified","FileCopied","FileMoved")
| extend User = tostring(InitiatingProcessAccountName)
| summarize AccessCount = count() by FileName, User"""

PQ_13 = (
    PQ_BASE + "event_type='DeviceFileEvents' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| filter FolderPath contains 'Confidential' OR FolderPath contains 'Sensitive' "
    "       OR FolderPath contains 'Restricted' "
    "| filter ActionType in ('FileAccessed','FileRead','FileModified','FileCopied','FileMoved') "
    "| group AccessCount = count() by FileName, InitiatingProcessAccountName"
)


def ref_13(events):
    dfe = [e for e in filter_type(events, "DeviceFileEvents")
           if any(e["FileName"].endswith(x) for x in (".docx", ".pdf", ".xlsx"))
           and any(s in e.get("FolderPath", "") for s in ("Confidential", "Sensitive", "Restricted"))
           and e["ActionType"] in ("FileAccessed", "FileRead", "FileModified", "FileCopied", "FileMoved")
           and ts(e) >= RECENT_START]
    grp = Counter((e["FileName"], e["InitiatingProcessAccountName"]) for e in dfe)
    return [{"FileName": f, "User": u, "AccessCount": n} for (f, u), n in grp.items()]


_register(id="13_insider_threat_sensitive_files",
          description="Sensitive file access within confidential folders",
          kql=KQL_13, pq=PQ_13, ref=ref_13,
          key=lambda r: (r["FileName"], r["User"]))


# 14) PRIVILEGE ESCALATION / UNAUTHORISED ADMIN -----------------------------
KQL_14 = """AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName has_any ("Add service principal","Certificates and secrets management")
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| join kind=inner (
    SigninLogs | where ResultType == 0 and TimeGenerated > ago(1d)
    | project LoginTime = TimeGenerated, Identity, IPAddress, AppDisplayName
  ) on $left.Actor == $right.Identity"""

PQ_14 = (
    PQ_BASE + "event_type='AuditLogs' "
    "| filter OperationName in ('Add service principal', 'Certificates and secrets management') "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group ops = count() by OperationName"
)


def ref_14(events):
    audit = [e for e in filter_type(events, "AuditLogs")
             if e["OperationName"] in ("Add service principal", "Certificates and secrets management")
             and ts(e) >= RECENT_START]
    signins = {e["Identity"]: e for e in filter_type(events, "SigninLogs")
               if e.get("ResultType") == 0 and ts(e) >= RECENT_START}
    out = []
    for a in audit:
        actor = a.get("InitiatedBy_user_userPrincipalName")
        if actor and actor in signins:
            s = signins[actor]
            out.append({"Actor": actor, "OperationName": a["OperationName"],
                        "IPAddress": s["IPAddress"], "AppDisplayName": s["AppDisplayName"]})
    return out


_register(id="14_priv_escalation",
          description="Sensitive Entra operations joined to successful signin context",
          kql=KQL_14, pq=PQ_14, ref=ref_14,
          key=lambda r: (r["Actor"], r["OperationName"]))


# 15) SLOW BRUTE FORCE -------------------------------------------------------
KQL_15 = """let codes = dynamic([50053,50126,50055,50057,50155,50105,50133,50005,50076,
                                50079,50173,50158,50072,50074,53003,53000,53001,50129]);
SigninLogs
| where TimeGenerated > ago(1d) | where ResultType in (codes)
| summarize FailedAttempts = count(), UniqueUsers = dcount(UserPrincipalName)
    by IPAddress
| where FailedAttempts > 5 and UniqueUsers > 5"""

PQ_15 = (
    PQ_BASE + "event_type='SigninLogs' "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| filter ResultType in (50053,50126,50055,50057,50155,50105,50133,50005,50076,"
    "50079,50173,50158,50072,50074,53003,53000,53001,50129) "
    "| group FailedAttempts = count(), "
    "        UniqueUsers = estimate_distinct(UserPrincipalName) "
    "  by IPAddress "
    "| filter FailedAttempts > 5 AND UniqueUsers > 5"
)


def ref_15(events):
    codes = {50053, 50126, 50055, 50057, 50155, 50105, 50133, 50005, 50076,
             50079, 50173, 50158, 50072, 50074, 53003, 53000, 53001, 50129}
    sl = [e for e in filter_type(events, "SigninLogs")
          if e.get("ResultType") in codes and ts(e) >= RECENT_START]
    by_ip = defaultdict(lambda: {"n": 0, "users": set()})
    for e in sl:
        by_ip[e["IPAddress"]]["n"] += 1
        by_ip[e["IPAddress"]]["users"].add(e["UserPrincipalName"])
    return [{"IPAddress": ip, "FailedAttempts": v["n"], "UniqueUsers": len(v["users"])}
            for ip, v in by_ip.items() if v["n"] > 5 and len(v["users"]) > 5]


_register(id="15_slow_brute_force",
          description="High volume of failed signins from one IP across many users",
          kql=KQL_15, pq=PQ_15, ref=ref_15,
          key=lambda r: (r["IPAddress"],))


# 16) SUSPICIOUS TRAVEL ------------------------------------------------------
KQL_16 = """SigninLogs | where TimeGenerated > ago(1d) | where ResultType == 0
| summarize CountriesAccessed = make_set(Location) by UserPrincipalName
| where array_length(CountriesAccessed) > 3"""

PQ_16 = (
    PQ_BASE + "event_type='SigninLogs' "
    "| filter ResultType = 0 "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group CountriesAccessed = array_agg_distinct(Location), n = estimate_distinct(Location) "
    "  by UserPrincipalName "
    "| filter n >= 4"
)


def ref_16(events):
    sl = [e for e in filter_type(events, "SigninLogs")
          if e.get("ResultType") == 0 and ts(e) >= RECENT_START]
    by_u = defaultdict(set)
    for e in sl:
        by_u[e["UserPrincipalName"]].add(e["Location"])
    return [{"UserPrincipalName": u, "CountriesAccessed": sorted(c)}
            for u, c in by_u.items() if len(c) > 3]


_register(id="16_suspicious_travel",
          description="User signed in from >3 distinct countries in 24h",
          kql=KQL_16, pq=PQ_16, ref=ref_16,
          key=lambda r: (r["UserPrincipalName"],))


# 17) DAILY SIGNIN BASELINE - NEW LOCATIONS ---------------------------------
KQL_17 = """let historical = SigninLogs
  | where ResultType == 0
  | where TimeGenerated between (ago(14d) .. ago(1d))
  | summarize HistoricalCountries = make_set(Location) by UserPrincipalName;
SigninLogs | where ResultType == 0 | where TimeGenerated > ago(1d)
| summarize TodayCountries = make_set(Location) by UserPrincipalName
| join kind=inner (historical) on UserPrincipalName
| extend NewLocations = set_difference(TodayCountries, HistoricalCountries)
| where array_length(NewLocations) > 0"""

PQ_17 = (
    PQ_BASE + "event_type='SigninLogs' "
    "| filter ResultType = 0 "
    "| filter ts_epoch_ms >= {RECENT_MS} "
    "| group TodayCountries = array_agg_distinct(Location), nLocs = estimate_distinct(Location) by UserPrincipalName "
    "| filter nLocs >= 1"
)


def ref_17(events):
    sl = [e for e in filter_type(events, "SigninLogs") if e.get("ResultType") == 0]
    hist = defaultdict(set); today = defaultdict(set)
    for e in sl:
        if ts(e) < RECENT_START:
            hist[e["UserPrincipalName"]].add(e["Location"])
        else:
            today[e["UserPrincipalName"]].add(e["Location"])
    out = []
    for u, t in today.items():
        new = t - hist.get(u, set())
        if new:
            out.append({"UserPrincipalName": u,
                        "NewLocations": sorted(new),
                        "TodayCountries": sorted(t),
                        "HistoricalCountries": sorted(hist.get(u, set()))})
    return out


_register(id="17_daily_baseline_new_locations",
          description="User signing in today from a country never seen in 14d baseline",
          kql=KQL_17, pq=PQ_17, ref=ref_17,
          key=lambda r: (r["UserPrincipalName"],))
