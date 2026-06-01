// Rule: 04_daily_signin_location_trend
// Daily baseline of signin locations / IPs per user+app
//
// Source KQL: see ../kql/04_daily_signin_location_trend.kql
//
// HOW TO RUN
//   curl POST {sdl}/api/powerQuery with this body, OR paste in
//   the SDL console. Set startTime = '2h' (or wider) so the API
//   scans the freshly-ingested epochs that contain the events.
//
// Time anchor at export: NOW = 2026-05-31T20:10:05+00:00
// Recent-window cutoff:  2026-05-31T18:10:05+00:00
//   (`ts_epoch_ms` below is that cutoff expressed in ms.
//   Re-run harness/export_rules.py to refresh after regenerating
//   sample_data/events.jsonl.)
//
// Fields referenced: AppDisplayName, DistinctSourceIp, IPAddress, Location, LocationCount, LogonCount, RECENT_MS, SigninLogs, UserPrincipalName
//
// EDITING NOTE
//   Every line that starts with `|` is a pipeline stage. Each `|`
//   is REQUIRED. If you delete one (e.g. while changing a literal
//   on the same line as a stage), SDL re-parses the keyword that
//   follows as a search term and rejects the query with errors
//   like `'estimate_distinct' is a grouping function`.

event_type='SigninLogs'
| filter ts_epoch_ms >= 1780251005000
| group LocationCount = estimate_distinct(Location),
        DistinctSourceIp = estimate_distinct(IPAddress),
        LogonCount = count()
    by AppDisplayName, UserPrincipalName
