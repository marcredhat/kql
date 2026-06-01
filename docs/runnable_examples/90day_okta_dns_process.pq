// Same 90-day cross-source hunt expressed in SentinelOne SDL PowerQuery.
//
// Paste into a SDL tenant (e.g. https://xdr.us1.sentinelone.net) with
// `startTime = "90d"`. Replace the synthetic domain regex if you have
// a real IOC list.
//
// Why this looks different from the KQL:
//   * one schema (OCSF) instead of three runtime parser unions
//   * one engine path; 90d is more epochs scanned in parallel, NOT a
//     different code path (no Basic/Auxiliary/Archive tiers)
//   * the join is a single named-input join; no shuffle hint required
//     because reduction is already distributed
//
// NOTE on `loginIsSuccessful = 'false'`:
//   SDL stores booleans as lowercase strings. On a tenant whose OCSF
//   parser emits true/false as native booleans, drop the quotes:
//       AND event.login.loginIsSuccessful = false

| join
    failed_signins = (
        event.category = 'logins'
        AND event.login.loginIsSuccessful = 'false'
        | columns userName = event.login.userName,
                  host     = endpoint.name
        | group n_fails = count() by userName, host
    ),
    bad_dns = (
        event.type = 'DNS Resolved'
        AND dns.question.name matches '(c2|suspect)\.example\.'
        | columns userName = src.endpoint.user.name,
                  host     = endpoint.name,
                  domain   = dns.question.name
        | group dns_hits = count(),
                domains  = array_agg_distinct(domain, 20)
          by userName, host
    ),
    susp_proc = (
        event.type = 'Process Creation'
        AND src.process.cmdline matches '(?i)(powershell|rundll32|mshta)'
        | columns userName = src.process.user,
                  host     = endpoint.name,
                  cmdline  = src.process.cmdline
        | group proc_hits = count(),
                cmdlines  = array_agg_distinct(cmdline, 20)
          by userName, host
    )
  on userName, host
| columns userName,
          host,
          hits      = n_fails + dns_hits + proc_hits,
          n_fails,
          dns_hits,
          proc_hits,
          domains,
          cmdlines
// If your tenant complains about bare field names after the join, use the
// fully-prefixed form instead:
//   | columns userName, host,
//             hits = failed_signins.n_fails + bad_dns.dns_hits + susp_proc.proc_hits,
//             failed_signins.n_fails, bad_dns.dns_hits, susp_proc.proc_hits,
//             bad_dns.domains, susp_proc.cmdlines
| sort -hits
| limit 100
