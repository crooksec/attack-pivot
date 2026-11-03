# Source licence and ToS review

Status of every source in `sources.seed.yaml` (SPEC §6.1). A source stays `enabled: false` until a row below is complete and `afp sources enable NAME --reviewed-by WHO --licence TEXT` records it. `enable` refuses a source whose licence is empty or still reads "verify".

## Checklist (per source)

1. **Licence / ToS:** does it permit automated retrieval and our use (private analysis of the text; storing a hash, a local copy, and ≤ 200-character evidence quotes with the URL)? Record the licence name and the URL of the terms page checked.
2. **robots.txt:** fetch `/robots.txt`; the paths we collect must be allowed for our user agent. Record the crawl-delay if one is set (the collector uses the larger of that and 5 s).
3. **Feed:** the RSS/sitemap/API URL still works and lists dated entries (so `published_at` can be recorded; the time-split evaluation needs dates).
4. **Access:** no login, paywall or bot challenge is needed. If one is, the source stays disabled or becomes `manual`.
5. **TLP:** the default TLP for what we store (public web content is `clear`; ISAC and member material takes the TLP stamped on the document).
6. **Redistribution:** whether derived data (technique-transition counts and short quotes) may appear in public exports. If unclear, the report is stored with the source's TLP raised to `amber` so public exports exclude it (fail closed).

Decision values: `enable`, `manual only`, `reject`. Nothing below has been reviewed yet: the **Licence (seed)** column is what the seed file claims, not a verified fact.

| Source | Class | Collector | Start URL | Licence (seed) | ToS | robots | Feed | Decision | Reviewer / date |
|---|---|---|---|---|---|---|---|---|---|
| MITRE CAR | detection_repo | github_repo | https://github.com/mitre-attack/car | Apache-2.0 | ☐ | ☐ | ☐ | seed-enabled (structured source) |  |
| VERIS Community Database | structured_dataset | github_repo | https://github.com/vz-risk/VCDB | verify (repo licence file) | ☐ | ☐ | ☐ | seed-enabled (structured source) |  |
| CTID VERIS-ATT&CK mapping | structured_dataset | github_repo | https://github.com/center-for-threat-informed-defense/attack_to_veris | Apache-2.0 (verify) | ☐ | ☐ | ☐ | seed-enabled (structured source) |  |
| Attack Flow upstream corpus | independent | manual | https://github.com/center-for-threat-informed-defense/attack-flow/tree/main/corpus | Apache-2.0 | ☐ | ☐ | ☐ | seed-enabled (structured source) |  |
| ATT&CK Campaigns | independent | github_repo | https://github.com/mitre-attack/attack-stix-data | ATT&CK Terms of Use | ☐ | ☐ | ☐ | unreviewed |  |
| CTID Adversary Emulation Library | emulation | github_repo | https://github.com/center-for-threat-informed-defense/adversary_emulation_library | Apache-2.0 | ☐ | ☐ | ☐ | unreviewed |  |
| CISA Cybersecurity Advisories | government | rss | https://www.cisa.gov/news-events/cybersecurity-advisories | US public domain | ☐ | ☐ | ☐ | unreviewed |  |
| FBI / IC3 Flash & PIN | government | sitemap | https://www.ic3.gov/CSA | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| NSA Cybersecurity Advisories | government | sitemap | https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| UK NCSC | government | rss | https://www.ncsc.gov.uk/section/keep-up-to-date/reports-advisories | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| ASD ACSC Advisories | government | rss | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Canadian Centre for Cyber Security | government | rss | https://www.cyber.gc.ca/en/alerts-advisories | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| CERT-EU Threat Intelligence | government | rss | https://cert.europa.eu/publications/threat-intelligence | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| JPCERT/CC Eyes | government | rss | https://blogs.jpcert.or.jp/en/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| The DFIR Report | independent | rss | https://thedfirreport.com | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Huntress Blog | vendor | rss | https://www.huntress.com/blog | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Red Canary Blog | vendor | rss | https://redcanary.com/blog/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Google Threat Intelligence / Mandiant | vendor | rss | https://cloud.google.com/blog/topics/threat-intelligence | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Microsoft Threat Intelligence | vendor | rss | https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Unit 42 (public blog) | vendor | rss | https://unit42.paloaltonetworks.com | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| CrowdStrike Blog | vendor | rss | https://www.crowdstrike.com/en-us/blog/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Cisco Talos | vendor | rss | https://blog.talosintelligence.com | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Sophos X-Ops | vendor | rss | https://news.sophos.com/en-us/category/threat-research/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| SentinelLABS | vendor | rss | https://www.sentinelone.com/labs/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Securelist (Kaspersky) | vendor | rss | https://securelist.com | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| ESET WeLiveSecurity | vendor | rss | https://www.welivesecurity.com/en/research/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Check Point Research | vendor | rss | https://research.checkpoint.com | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Trend Micro Research | vendor | rss | https://www.trendmicro.com/en_us/research.html | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Proofpoint Threat Insight | vendor | rss | https://www.proofpoint.com/us/blog/threat-insight | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Symantec / Broadcom Threat Intelligence | vendor | rss | https://www.security.com/threat-intelligence | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Elastic Security Labs | vendor | rss | https://www.elastic.co/security-labs | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Recorded Future Insikt | vendor | rss | https://www.recordedfuture.com/research | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Volexity Threat Intelligence | vendor | rss | https://www.volexity.com/blog/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Zscaler ThreatLabz | vendor | rss | https://www.zscaler.com/blogs/security-research | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Arctic Wolf Labs | vendor | rss | https://arcticwolf.com/resources/blog/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Rapid7 Research | vendor | rss | https://www.rapid7.com/blog/ | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Secureworks CTU | vendor | rss | https://www.secureworks.com/research | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| APTnotes | community | github_repo | https://github.com/aptnotes/data | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| ORKL | community | api | https://orkl.eu | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Health-ISAC | isac | manual | n/a | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| FS-ISAC | isac | manual | n/a | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| MS-ISAC / CIS | isac | rss | https://www.cisecurity.org/insights/advisory | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| E-ISAC | isac | manual | n/a | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| REN-ISAC | isac | manual | n/a | unknown | ☐ | ☐ | ☐ | unreviewed |  |
| Auto-ISAC | isac | manual | n/a | unknown | ☐ | ☐ | ☐ | unreviewed |  |

## Notes

- The four seed-enabled entries are the structured sources read from public repositories by `afp car sync` and `afp vcdb sync` (and the upstream Attack Flow corpus). Their licences were read from the repositories in P0: CAR Apache-2.0; VCDB CC BY-SA 4.0 (share-alike matters if a derived dataset is published, PRD Q3); `attack_to_veris` Apache-2.0 (archived).
- ISAC entries are `manual`: files the owner already has access to, TLP set from the document. MS-ISAC/CIS advisories are public, but member content is not.
- Fill a row, run `afp sources enable`, and commit this file with the change.
