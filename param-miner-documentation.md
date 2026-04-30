# Param Miner — Complete Reference Documentation

> Source: exhaustive static analysis of param-miner v1.57 — `BurpExtender.java`, `Lenscrack.java`, `Lensmine.java`, and decompiled strings from `Scan.class`, `BulkScan.class`, `ScanItem.class`, `LiveScan.class`, `BulkScanLauncher.class`, `Probe.class` in `bulkScan-all.jar`.

## Table of Contents

1. [Attack Config Reference](#1-attack-config-reference)
   - [Scan Control](#scan-control)
   - [Request Deduplication (Key)](#request-deduplication-key)
   - [Filtering](#filtering)
   - [Reporting](#reporting)
   - [Statistical Detection](#statistical-detection)
   - [Cachebusters](#cachebusters)
   - [Word Mining & Wordlists](#word-mining--wordlists)
   - [Attack Behaviour](#attack-behaviour)
   - [Request Sizing & Timing](#request-sizing--timing)
   - [Header Options](#header-options)
   - [Advanced / Internal](#advanced--internal)
   - [Scoped-SSRF Settings](#scoped-ssrf-settings)
2. [Right-Click Context Menu Attacks](#2-right-click-context-menu-attacks)

## 1  Attack Config Reference

The Attack Config panel is the primary control surface for all Param Miner scans. Settings are persisted between sessions. **Checkbox** fields are On/Off toggles; **Number** fields accept integers; **Text** fields accept free-form strings.

> **Note on setting scope:** Some settings are registered globally in `Scan.class` (applying to the bulk-scan engine) and some are registered per-attack in `BurpExtender.java` (`guessSettings` or `configSettings`). Where a setting appears in both, the `guessSettings` value takes precedence for context-menu attacks.

### Scan Control

| Option | Type | Default | Description |
|---|---|---|---|
| `per-thread throttle` | Number | `0` | Milliseconds to pause before sending each request, per thread. Set to `0` for no throttle. Useful for rate-limiting against sensitive targets or avoiding detection. |
| `thread pool size` | Number | `8` | Maximum number of concurrent worker threads. Roughly correlates with concurrent HTTP requests. Increase for faster attacks on stable targets; decrease to reduce system and server load. |
| `live scan` | Checkbox | Off | Auto-scan all in-scope proxied traffic in real time as it passes through Burp's proxy. Requires a manual scan to already be configured and running; silently does nothing otherwise. |
| `infinite scan` | Checkbox | Off | Repeat all scan items indefinitely until the extension is manually unloaded. Intended for long-running continuous monitoring scenarios. |

### Request Deduplication (Key)

Param Miner can skip re-testing equivalent endpoints by computing a composite key from configurable request and response attributes. Any request whose key matches one already seen is skipped. The key always includes hostname and protocol as a baseline; the options below add further dimensions.

| Option | Type | Default | Description |
|---|---|---|---|
| `use key` | Checkbox | On | Enable deduplication. When active, requests whose composite key matches a previously processed request are skipped entirely. |
| `key method` | Checkbox | On | Include the HTTP request method (GET, POST, etc.) in the deduplication key. |
| `key path` | Checkbox | Off | Include the URL path in the key. When enabled, requests to the same host but different paths are treated as distinct targets. |
| `key status` | Checkbox | On | Include the HTTP response status code in the key. |
| `key content-type` | Checkbox | On | Include the response `Content-Type` value in the key. |
| `key server` | Checkbox | On | Include the value of the response `Server` header in the key. |
| `key input name` | Checkbox | On | Include the name of the parameter currently under test in the key. Prevents skipping endpoints simply because a different parameter was already tested there. |
| `key header names` | Checkbox | Off | Include all response header names (but not their values) in the key. Useful for distinguishing endpoints that return structurally different response envelopes. |

### Filtering

| Option | Type | Default | Description |
|---|---|---|---|
| `filter` | Text | *(empty)* | Only scan requests whose URL or content contains this string. Leave blank to scan all requests in scope. |
| `mimetype-filter` | Text | *(empty)* | Only scan responses whose `Content-Type` header contains this string (e.g., `json`, `html`, `text`). Narrows attacks to specific response types. |
| `resp-filter` | Text | *(empty)* | Only scan requests whose responses contain this string anywhere in the body or headers. More granular than `mimetype-filter`; useful for targeting specific application states. |
| `filter HTTP` | Checkbox | Off | When enabled, only scan HTTPS requests — plain HTTP endpoints are skipped entirely. |
| `skip vulnerable hosts` | Checkbox | Off | Stop scanning hosts already flagged as vulnerable during this scan run. Useful for avoiding redundant work on large scans. Flags clear on extension reload. |
| `skip flagged hosts` | Checkbox | Off | Do not report new issues on hosts that already have any issue listed in Burp's sitemap. Distinct from `skip vulnerable hosts`: this suppresses reporting rather than skipping scanning. |

### Reporting

| Option | Type | Default | Description |
|---|---|---|---|
| `flag new domains` | Checkbox | Off | Adjust issue titles to highlight when a finding is on a host with no prior issues in the sitemap, making novel-host discoveries more visible during triage. |
| `report to organizer` | Checkbox | Off | Forward detected vulnerabilities to Burp's Organizer tab for centralised triage. Requires Burp Suite Pro. |
| `name in issue` | Checkbox | Off | Include the discovered parameter name in the Burp issue title. Makes individual findings easier to identify in the Issues panel without opening each one. |

### Statistical Detection

Param Miner uses differential analysis to detect whether a parameter influenced the response. These settings control the statistical rigour of that analysis.

| Option | Type | Default | Description |
|---|---|---|---|
| `confirmations` | Number | `5` | Number of times a behaviour must be reproduced before being reported. Higher values reduce false positives from transient server-side noise at the cost of additional requests. |
| `require consistent evidence` | Checkbox | On | Suppress lower-confidence findings that do not meet the repeatability threshold set by `confirmations`. Reduces false positives at the cost of potentially missing genuinely noisy-but-real issues. |
| `quantile factor` | Number | `2` | Scale of 1–10. Higher values demand stronger statistical separation before reporting (fewer FPs, more FNs). Lower values are more sensitive (more FPs, fewer FNs). |
| `quantitative diff keys` | Text | `time` | Specifies which quantitative dimensions to use for differential detection. The default value `time` enables timing-based detection. Clearing this field disables timing as a signal and makes scans faster. Described in source as experimental. |
| `quantitative confirmations` | Number | `50` | Number of confirmation requests used to verify quantitative (timing- or size-based) differences are consistent. Higher values increase confidence and reduce false positives from variable network conditions. |

### Cachebusters

These settings control how Param Miner varies each request to prevent receiving stale cached responses during testing. At least one cachebuster dimension should be active when testing cacheable targets.

| Option | Type | Default | Description |
|---|---|---|---|
| `include query-param in cachebusters` | Checkbox | On | Append a unique random query parameter to each outbound request to bust caches and ensure fresh responses from the origin. |
| `include origin in cachebusters` | Checkbox | On | Include a randomised `Origin` header value in cache-busting requests to vary the cache key on targets that key on `Origin`. |
| `include path in cachebusters` | Checkbox | Off | Include a random path segment in cache-busting requests. Useful when query-param cachebusters are stripped or ignored by the target's cache layer. |
| `include via in cachebusters` | Checkbox | On | Include a `Via` header variation in cache-busting requests to vary the cache key on targets that include this header in their key. |
| `misc header cachebusters` | Checkbox | Off | Include a set of miscellaneous header-based cache-busters beyond the individually configurable options above. |
| `custom header cachebuster` | Text | *(empty)* | Specify a custom request header name to inject as a cache-buster. Sent with a unique value on each request. |

### Word Mining & Wordlists

| Option | Type | Default | Description |
|---|---|---|---|
| `learn observed words` | Checkbox | Off | During passive scanning, extract all words observed in responses and add them to the working candidate list. Produces highly targeted guesses but can significantly grow the candidate set over time. |
| `skip boring words` | Checkbox | On | When mining headers, skip well-known headers present on almost every request that are rarely indicative of interesting server-side behaviour. The skip list is loaded from the bundled `boring_headers` resource file. |
| `response-headers` | Checkbox | On | Extract words from the target's response headers and use them as parameter name candidates. |
| `response-body` | Checkbox | On | Extract words from the target's response body and use them as parameter name candidates. |
| `request` | Checkbox | On | Extract words from the target request itself — existing parameter names, path segments, values — and use them as candidates. Produces the most targeted guesses; highly recommended. |
| `use basic wordlist` | Checkbox | On | Include Param Miner's built-in core wordlist of common parameter names. |
| `use bonus wordlist` | Checkbox | Off | Include an additional generic wordlist beyond the core one. |
| `use assetnote params` | Checkbox | Off | Include the Assetnote mega-wordlist compiled from large-scale web crawling. Very large; significantly slows scans. Best reserved for thorough coverage passes on high-value targets. |
| `use custom wordlist` | Checkbox | Off | Load an additional wordlist from the path specified in `custom wordlist path`. |
| `custom wordlist path` | Text | `/usr/share/dict/words` | Filesystem path to the custom wordlist file. Only used when `use custom wordlist` is enabled. |
| `dynamic keyload` | Checkbox | Off | Extract words from every response observed during the attack (not just the initial target request) and add them to the live candidate set. Source code describes this as "very powerful and quite buggy." |

### Attack Behaviour

| Option | Type | Default | Description |
|---|---|---|---|
| `bruteforce` | Checkbox | Off | After exhausting all configured wordlists, continue with a never-ending brute-force attack generating arbitrary strings. Will run indefinitely — use with explicit intent. |
| `skip uncacheable` | Checkbox | Off | Skip endpoints whose responses do not appear to be cacheable. Useful when exclusively hunting cache poisoning vectors. |
| `only report unique params` | Checkbox | Off | Only report a given parameter name once globally, regardless of how many different endpoints it is found on. Reduces noise in large multi-endpoint scans. |
| `max one per host` | Checkbox | Off | Perform only one attack per hostname, then stop. Useful for quickly establishing whether a host warrants deeper investigation. |
| `max one per host+status` | Checkbox | Off | Perform only one attack per unique hostname + HTTP status code combination. |
| `probe identified params` | Checkbox | On | After discovering a parameter, attempt to characterise what type of input it expects (boolean, numeric, string, etc.). Adds depth to findings. |
| `scan identified params` | Checkbox | Off | Launch a full Burp active scan against every parameter Param Miner discovers. Requires Burp Suite Pro. |
| `fuzz detect` | Checkbox | Off | Detect hidden parameters by injecting a fuzz string designed to trigger server-side errors rather than relying on input reflection. Useful when the application silently ignores unknown parameters but errors on malformed input. |
| `carpet bomb` | Checkbox | Off | Send all parameter candidates without attempting to identify or report which ones produce a detectable response. Useful for OAST/out-of-band techniques where a callback — not the response — is the signal. |
| `try cache poison` | Checkbox | On | After discovering a parameter, automatically test whether it can be used to poison the cache for subsequent users. |
| `twitchy cache poison` | Checkbox | Off | Extend cache poison detection to cover non-reflected input — parameters that alter response behaviour (headers, size, timing) without appearing in the body. Increases false-positive rate. |
| `identify smuggle mutations` | Checkbox | Off | Test header name mutations (extra whitespace, tab separators, duplicate headers, non-standard casing) that may survive front-end rewriting and reach the back-end in unexpected forms. Core to HTTP request smuggling reconnaissance. |
| `try -_ bypass` | Checkbox | Off | Resend all header name candidates with hyphens converted to underscores (e.g., `X-Forwarded-For` → `X_Forwarded_For`). Bypasses front-end filters that normalise hyphenated names. |
| `poison only` | Checkbox | Off | Do not report a discovered parameter unless it can also be used for cache poisoning. Focuses results exclusively on cache attack surface. |

### Request Sizing & Timing

| Option | Type | Default | Description |
|---|---|---|---|
| `force bucketsize` | Number | `-1` | Manually fix the number of parameters sent per request. Set to `-1` to let Param Miner auto-detect the optimal bucket size per target by probing with trial payloads. |
| `max bucketsize` | Number | `65536` | Upper cap on parameters per request, even if the target appears to accept more. Prevents unbounded growth during auto-detection. |
| `max param length` | Number | `32` | Maximum character length of generated parameter names during bucket-size detection probes. Used to size trial payloads accurately. |
| `rotation interval` | Number | `999` | Intended to control wordlist rotation frequency. **Source code comments explicitly state: "This doesn't work."** |
| `rotation increment` | Number | `4` | Intended to control the step size of wordlist rotation. **Source code comments explicitly state: "This doesn't work."** |
| `baseline size` | Number | `4` | Number of requests sent to build the baseline response fingerprint before the attack begins. Higher values produce a more stable fingerprint on variable endpoints. |

### Header Options

| Option | Type | Default | Description |
|---|---|---|---|
| `lowercase headers` | Checkbox | On | Send all header names in lowercase (e.g., `content-type` instead of `Content-Type`). Consistent with HTTP/2 normalisation. |
| `include Hyphenated-Pascal-Case headers` | Checkbox | Off | Additionally send headers in Hyphenated-Pascal-Case (e.g., `X-Forwarded-For` alongside `x-forwarded-for`) to account for case-sensitive back-end parsers. Overrides `lowercase headers` when enabled. |

### Advanced / Internal

These settings expose low-level internals and should generally be left at defaults unless you have a specific reason to change them.

| Option | Type | Default | Description |
|---|---|---|---|
| `canary` | Text | `zwrtxqva` | Fixed string prefix prepended to injected values to detect input reflection. Change this if the default is somehow blocked or filtered by the target. |
| `force canary` | Text | *(empty)* | Override the dynamically generated canary with a fixed value. Useful in carpet-bomb mode where a predictable payload value is needed for out-of-band correlation. |
| `tunnelling retry count` | Number | `20` | When mining a tunnelled (nested) request, the maximum number of consecutive failures to receive a nested response before giving up. |
| `abort on tunnel failure` | Checkbox | On | When the `tunnelling retry count` is exceeded, abort the tunnel mining attempt entirely rather than continuing indefinitely. |

### Scoped-SSRF Settings

These settings appear in the Attack Config when using the **Detect scoped-SSRF** or **Exploit scoped-SSRF** context menu attacks. They are registered per-attack by `Lenscrack.java` and `Lensmine.java`.

| Option | Type | Default | Description |
|---|---|---|---|
| `overlong-detection` | Checkbox | On | Use overlong DNS labels (exceeding the 63-character limit) as part of SSRF detection probes. Helps identify wildcard-routing setups that forward arbitrary hostnames to the origin. |
| `auto-scan for proxyable destinations` | Checkbox | On | If wildcard routing is detected, automatically attempt to enumerate reachable internal hostnames using the subdomain wordlists. |
| `mining: filter 500s` | Checkbox | On | Do not report internal hostnames that return a 5xx status code. Reduces noise from hosts that exist on the network but are erroring. |
| `subdomains-builtin` | Checkbox | On | Use the extension's bundled subdomain wordlist when enumerating proxyable destinations. |
| `subdomains-generic` | Text | *(empty)* | Path to a generic subdomain wordlist file to use during SSRF enumeration. |
| `subdomains-specific` | Text | *(empty)* | Path to a target-specific subdomain wordlist. Expected format: `/subdomains/$domain` — see `proxy.md` in the repository for full details. |
| `external subdomain lookup` | Checkbox | Off | Look up known subdomains via an external service. **Warning:** discloses the top-level private domain being tested to a third party. |
| `deep-scan` | Checkbox | Off | Prevent early exit when nothing interesting is found within the first ~100 attempts. Forces exhaustive iteration through all enabled wordlists regardless of intermediate results. |
| `inherit request path` | Checkbox | Off | Use the path from the selected request rather than defaulting to `/` when constructing SSRF probe requests. |
| `I read the docs` | Checkbox | Off | Acknowledgement checkbox. Check after reading the scoped-SSRF documentation at `proxy.md` to suppress the nag prompt. No functional effect beyond hiding the warning. |

## 2  Right-Click Context Menu Attacks

These attacks are available by right-clicking any request in Burp's Proxy, Repeater, Target, or Scanner panels and navigating to **Extensions → Param Miner**. Each attack operates on the selected request and respects the active Attack Config settings.

### Guess headers

Brute-forces HTTP request header names using the configured wordlists. Candidates are batched and sent with a canary value; differential analysis against the baseline detects whether a given header name influenced the server. The primary use case is discovering headers honoured by back-end systems, CDN layers, or load balancers that are absent from normal client traffic — e.g., `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, and internal routing headers.

### Guess query params

Brute-forces URL query string parameter names. Parameters are injected in batches alongside a unique canary; a response differential flags any name that affected the server. Uncovers hidden API parameters, feature flags, debug switches, and admin-only options not surfaced in the application UI.

### Guess cookies

Brute-forces cookie names by sending batched candidates in the `Cookie` header. Useful for finding undocumented session modifiers, A/B-test toggles, role-escalation cookies, or privileged mode flags the server reads but never sets in normal responses.

### Guess body params

Brute-forces parameter names in the request body. Adapts the injection format to the detected content type — form-urlencoded, JSON, or XML. Finds hidden server-side parameters not present in the front-end UI or API documentation.

### Guess everything!

Convenience attack that runs all four guessing modes — headers, query params, cookies, and body params — sequentially on the selected request. Comprehensive parameter coverage in a single action.

### Detect scoped-SSRF

Actively tests for server-side request forgery where the application connects only to a restricted set of destinations. Uses overlong DNS labels and controlled-domain callbacks to determine whether outbound requests can be influenced by attacker-supplied input. If wildcard routing is detected, optionally enumerates reachable internal hostnames against the configured subdomain wordlists.

### Exploit scoped-SSRF

Follows up on a confirmed scoped-SSRF finding by iterating over subdomain wordlists to enumerate internal destinations reachable through the vulnerable endpoint. Maps the internal network surface accessible via the SSRF vector.

### Detect server-side injection

Tests existing parameters for server-side template injection (SSTI) and related code-execution primitives by injecting structured syntax payloads — escape sequences (`\u0061` vs `\v0061`), quote pairs, SQL apostrophe variants — and comparing responses. Detection is timing- and reflection-based. Parameters that respond differently to structurally distinct but semantically similar payloads are flagged.

### port-DoS

Tests whether an attacker-controlled port number injected via the `Host` header is reflected into cacheable responses. If confirmed and the response is cached, subsequent visitors will receive the poisoned response and their browsers will attempt to connect to the attacker-specified non-existent port, causing a denial-of-service without per-victim interaction.

### Unkeyed param

Checks whether an existing query parameter is excluded from the cache key while still influencing the response. Sends the parameter with a canary value, then issues a fresh cacheless request without the parameter and checks whether the poisoned version is returned — confirming Web Cache Poisoning exploitable against other users.

### fat GET

Tests whether the server processes body parameters on GET requests. Converts the selected GET to POST (body contains a canary-tagged version of an existing parameter), then re-issues the request as GET with the body still present. Body parameter influence on the response confirms "fat GET" support — a common source of cache poisoning gadgets and request-smuggling primitives.

### input transformation

Checks whether a parameter's value is transformed server-side (URL-decoded, HTML-decoded, serialised) before being reflected. Confirms reflection first, then sends encoding variants to determine whether transformation changes the reflected form. Identifies filter bypasses, double-encoding gadgets, and dangerous transformation chains.

### normalised param

Determines whether the application URL-decodes parameter values before computing the cache key. Sends a percent-encoded canary (e.g., `kkvjq%61mdk` where `%61` = `a`), then checks whether a subsequent request with the decoded form (`kkvjqamdk`) receives the poisoned cached response — confirming URL normalisation of the cache key.

### normalised path

Checks whether the server URL-decodes the path before computing the cache key (e.g., treating `%3f` as `?`). A mismatch between the key used for cache storage and the key used for retrieval allows poisoning the cache entry for the normal decoded URL by requesting the percent-encoded variant.

### rails param cloaking scan

Tests for the Rails UTM parameter-cloaking behaviour in which Rails automatically strips certain query parameters (`utm_source`, `utm_medium`, etc.) from the cache key while still processing them server-side. An unkeyed UTM parameter that influences the response constitutes a Web Cache Poisoning vulnerability requiring no unusual attacker capability.

### identify header smuggling mutations

Attempts to discover which header name mutation forms survive front-end rewriting and reach the back-end unmodified — extra whitespace, tab separators, duplicate headers, non-standard casing, HTTP/2 pseudo-header abuse. Used to find desync-exploitable header variants that bypass WAF rules or load-balancer normalisations; a prerequisite for constructing HTTP request smuggling and H2.TE/H2.CL exploit chains.

*Param Miner by James Kettle (PortSwigger Web Security) — https://github.com/PortSwigger/param-miner*
