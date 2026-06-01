// Rule: 09_new_processes_24h
// Process filenames seen today but never in the 14d baseline
//
// Source KQL: see ../kql/09_new_processes_24h.kql
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
// Fields referenced: Account, Computer, EventID, NewProcessName, RECENT_MS, SecurityEvent
//
// EDITING NOTE
//   Every line that starts with `|` is a pipeline stage. Each `|`
//   is REQUIRED. If you delete one (e.g. while changing a literal
//   on the same line as a stage), SDL re-parses the keyword that
//   follows as a search term and rejects the query with errors
//   like `'estimate_distinct' is a grouping function`.

event_type='SecurityEvent'
| filter EventID = 4688
| filter ts_epoch_ms >= 1780251005000
| filter NewProcessName contains 'mimikatz'
| group n = count()
    by NewProcessName, Account, Computer
