// Rule: 15_slow_brute_force
// High volume of failed signins from one IP across many users
//
// Source KQL: see ../kql/15_slow_brute_force.kql
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
// Fields referenced: FailedAttempts, IPAddress, RECENT_MS, ResultType, SigninLogs, UniqueUsers, UserPrincipalName
//
// EDITING NOTE
//   Every line that starts with `|` is a pipeline stage. Each `|`
//   is REQUIRED. If you delete one (e.g. while changing a literal
//   on the same line as a stage), SDL re-parses the keyword that
//   follows as a search term and rejects the query with errors
//   like `'estimate_distinct' is a grouping function`.

event_type='SigninLogs'
| filter ts_epoch_ms >= 1780251005000
| filter ResultType in (50053,50126,50055,50057,50155,50105,50133,50005,50076,50079,50173,50158,50072,50074,53003,53000,53001,50129)
| group FailedAttempts = count(),
        UniqueUsers = estimate_distinct(UserPrincipalName)
    by IPAddress
| filter FailedAttempts > 5 AND UniqueUsers > 5
