# Param Miner — Reference Documentation

> Source: static analysis of param-miner v1.57 — `BurpExtender.java`, `Scan.class` (bulkScan-all.jar), and individual attack class files.

---

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
   - [Request Sizing](#request-sizing)
   - [Header Options](#header-options)
2. [Right-Click Context Menu Attacks](#2-right-click-context-menu-attacks)

---

## 1  Attack Config Reference

The Attack Config panel is the primary control surface for all Param Miner scans. Settings are persisted between sessions. **Checkbox** fields are On/Off toggles; **Number** fields accept integers; **Text** fields accept free-form strings.

---

### Scan Control

| Option | Type | Default | Description |
|---|---|---|---|
| `per-thread throttle` | Number | `0` | Milliseconds to pause before each request per thread. Set to `0` for no throttle. Useful for rate-limiting to avoid detection or overloading targets. |
| `thread pool size` | Number | `8` | Maximum number of concurrent worker threads (roughly equivalent to concurrent HTTP requests). Increase for faster attacks; decrease to reduce load. |
| `live-scan` | Checkbox | Off | Auto-scan all in-scope proxied traffic in real time as it passes through Burp's proxy. Requires a manual scan to be configured and running first. |

---

### Request Deduplication (Key)

Param Miner can avoid re-testing equivalent endpoints by building a composite key from configurable request and response attributes. Requests whose computed key has already been seen are skipped.

| Option | Type | Default | Description |
|---|---|---|---|
| `use key` | Checkbox | On | Enable deduplication. When active, requests whose composite key matches a previously seen request are skipped entirely. |
| `key path` | Checkbox | Off | Include the URL path as a key component. When enabled, requests to the same host but different paths are treated as distinct targets. |
| `key status` | Checkbox | On | Include the HTTP response status code in the deduplication key. |
| `key server` | Checkbox | On | Include the value of the response `Server` header in the key. |
| `key input name` | Checkbox | On | Include the name of the parameter currently under test in the key. Prevents skipping endpoints just because a different parameter was already found there. |

---

### Filtering

| Option | Type | Default | Description |
|---|---|---|---|
| `filter` | Text | *(empty)* | Only scan requests whose URL or content contains this string. Leave blank to scan all requests. |
| `mimetype-filter` | Text | *(empty)* | Only scan responses whose `Content-Type` contains this string (e.g., `json`, `html`). Useful for narrowing attacks to specific response types. |
| `filter HTTP` | Checkbox | Off | When enabled, only scan HTTPS requests — plain HTTP endpoints are skipped. |
| `skip vulnerable hosts` | Checkbox | Off | Stop scanning hosts already flagged as vulnerable during this scan run. Flags clear on extension reload. |

---

### Reporting

| Option | Type | Default | Description |
|---|---|---|---|
| `flag new domains` | Checkbox | Off | Adjust issue titles to highlight when a finding is on a host with no prior issues in the sitemap — makes novel discoveries more visible during triage. |
| `report to organizer` | Checkbox | Off | Forward detected vulnerabilities to Burp's Organizer tab for centralised triage. Requires Burp Suite Pro. |

---

### Statistical Detection

Param Miner uses differential analysis to detect parameter influence. These settings control the statistical rigour of that analysis.

| Option | Type | Default | Description |
|---|---|---|---|
| `require consistent evidence` | Checkbox | On | Suppress lower-confidence findings that don't meet repeatability thresholds. Reduces false positives at the cost of potentially missing noisy-but-real issues. |
| `quantile factor` | Number | `2` | Scale of 1–10. Higher values demand stronger statistical separation before reporting (fewer FPs, more FNs). Lower values are more sensitive (more FPs, fewer FNs). |
| `quantitative confirmations` | Number | `50` | Number of confirmation requests used to verify quantitative differences (e.g., timing- or size-based) are consistent. Higher values increase confidence and reduce false positives. |

---

### Cachebusters

These settings control how Param Miner varies requests to avoid receiving stale cached responses during testing.

| Option | Type | Default | Description |
|---|---|---|---|
| `include query-param in cachebusters` | Checkbox | On | Append a unique random query parameter to each request to bust caches and ensure fresh responses. |
| `include path in cachebusters` | Checkbox | Off | Include a random path segment in cache-busting requests. Useful when query-param cachebusters are stripped or ignored by the target. |
| `include via in cachebusters` | Checkbox | On | Include a `Via` header variation in cache-busting requests to vary the cache key on targets that key on this header. |
| `custom header cachebuster` | Text | *(empty)* | Specify a custom request header name to use as an additional cache-buster. The header is injected with a unique value on each request. |

---

### Word Mining & Wordlists

| Option | Type | Default | Description |
|---|---|---|---|
| `learn observed words` | Checkbox | Off | During passive scanning, extract all words seen in responses and add them to the working candidate list. Produces highly targeted guesses but can significantly grow the wordlist. |
| `only report unique params` | Checkbox | Off | Only report a given parameter name once globally, regardless of how many endpoints it appears on. Reduces noise in large multi-endpoint scans. |
| `response-headers` | Checkbox | On | Extract words from the target's response headers and use them as parameter name candidates. |
| `request` | Checkbox | On | Extract words from the target request itself (existing parameter names, path segments, etc.) and use them as candidates. Highly recommended — produces the most targeted guesses. |
| `use basic wordlist` | Checkbox | On | Include Param Miner's built-in core wordlist of common parameter names. |
| `use assetnote params` | Checkbox | Off | Include the Assetnote mega-wordlist compiled from large-scale web crawling. Very large — will significantly slow scans. |
| `use custom wordlist` | Checkbox | Off | Load an additional wordlist from the path configured in the `custom wordlist path` field (default: `/usr/share/dict/words`). |

---

### Attack Behaviour

| Option | Type | Default | Description |
|---|---|---|---|
| `bruteforce` | Checkbox | Off | After exhausting all configured wordlists, continue with a never-ending brute-force attack generating arbitrary strings. Use with caution — will run indefinitely. |
| `skip uncacheable` | Checkbox | Off | Skip endpoints whose responses do not appear to be cacheable. Useful when exclusively hunting for cache poisoning vectors and not interested in non-cached params. |
| `max one per host` | Checkbox | Off | Perform only one attack per hostname, then stop. Useful for quickly confirming whether a host is worth deeper investigation. |
| `max one per host+status` | Checkbox | Off | Perform only one attack per unique hostname + HTTP status code combination. |
| `scan identified params` | Checkbox | Off | Launch a Burp active scan against every parameter discovered by Param Miner. Requires Burp Suite Pro. |
| `fuzz detect` | Checkbox | Off | Detect hidden parameters by injecting a fuzz string designed to trigger server-side errors rather than relying solely on input reflection. |
| `try cache poison` | Checkbox | On | After discovering a parameter, automatically test whether it can be used to poison the cache and affect other users' responses. |
| `twitchy cache poison` | Checkbox | Off | Extend cache poison detection to cover non-reflected input (e.g., parameters that alter response behaviour without appearing in the body). Increases false-positive rate. |
| `try -_ bypass` | Checkbox | Off | Convert hyphens to underscores in header names before sending (e.g., `X-Forwarded-For` → `X_Forwarded_For`). Bypasses some front-end header-rewriting filters. |
| `rotation interval` | Number | `999` | Controls wordlist rotation logic. **Note: the author's own code comments indicate this setting does not currently work.** |

---

### Request Sizing

| Option | Type | Default | Description |
|---|---|---|---|
| `force bucketsize` | Number | `-1` | Manually fix the number of parameters sent per request. Set to `-1` to let Param Miner auto-detect the optimal bucket size per target by probing with trial payloads. |
| `max bucketsize` | Number | `65536` | Upper cap on the number of parameters Param Miner will batch into a single request, even if the server appears to accept more. |

---

### Header Options

| Option | Type | Default | Description |
|---|---|---|---|
| `lowercase headers` | Checkbox | On | Send all header names in lowercase (e.g., `content-type` instead of `Content-Type`). Consistent with HTTP/2 normalisation and more efficient for modern targets. |
| `include Hyphenated-Pascal-Case headers` | Checkbox | Off | Additionally send headers in Hyphenated-Pascal-Case (e.g., `X-Forwarded-For` alongside `x-forwarded-for`) to catch case-sensitive parsers. Overrides the `lowercase headers` setting when enabled. |

---

## 2  Right-Click Context Menu Attacks

These attacks are available by right-clicking any request in Burp's Proxy, Repeater, Target, or Scanner panels and selecting **Param Miner** from the context menu. Each attack operates on the selected request and respects the settings configured in the Attack Config panel.

---

### Guess headers

Brute-forces HTTP request header names using the configured wordlists. Candidates are batched and sent with a canary value; differential analysis between the baseline and probe responses detects whether a given header name influenced the server. The primary use case is discovering headers honoured by back-end systems or CDN layers that are not present in normal client traffic (e.g., `X-Original-URL`, `X-Forwarded-Host`, internal routing headers).

---

### Guess query params

Brute-forces URL query string parameter names. Parameters are injected in batches alongside a unique canary value; a response differential flags any name that affected the server. Ideal for uncovering hidden API parameters, feature flags, debug switches, and admin-only options not surfaced in the application's UI.

---

### Guess cookies

Brute-forces cookie names by sending batched candidates in the `Cookie` header alongside canary values. Useful for finding undocumented session modifiers, A/B-test toggles, role escalation cookies, or privileged mode flags that the server reads but never sets in normal responses.

---

### Guess body params

Brute-forces parameter names in the request body. Adapts the injection format to the detected content type (form-urlencoded, JSON, XML). Finds hidden server-side parameters that are processed by the application but never appear in the front-end UI or API documentation.

---

### Guess everything!

Convenience attack that runs all four guessing modes — headers, query params, cookies, and body params — sequentially on the selected request. Provides comprehensive parameter coverage in a single action.

---

### Detect scoped-SSRF

Actively tests for server-side request forgery where the application will only connect to a restricted set of destinations. Uses overlong DNS labels and controlled-domain callbacks to determine whether the server's outbound requests can be influenced by attacker-controlled input. If wildcard routing is detected, optionally enumerates reachable internal hostnames against the configured subdomain wordlists.

---

### Exploit scoped-SSRF

Follows up on a confirmed scoped-SSRF finding by iterating over subdomain wordlists to enumerate internal destinations reachable through the vulnerable endpoint. Used to map the internal network surface accessible via the SSRF vector.

---

### Detect server-side injection

Tests existing parameters for server-side template injection (SSTI) and related code-execution primitives by injecting structured syntax payloads — escape sequences, quote pairs, SQL apostrophe variants — and comparing responses. Detection is timing- and reflection-based. Parameters that respond differently to structurally distinct payloads are flagged as potential injection points.

---

### port-DoS

Tests whether an attacker-controlled port number injected via the `Host` header is reflected into cacheable responses. If the poisoned response is cached, subsequent visitors will receive it and their browsers will attempt to connect to a non-existent port, resulting in a denial-of-service condition without requiring any interaction from the victim beyond a normal page load.

---

### Unkeyed param

Checks whether an existing query parameter is excluded from the cache key while still influencing the response content. Sends the parameter with a canary value, then issues a fresh request without it and checks whether the poisoned version is returned — confirming a Web Cache Poisoning vulnerability exploitable against other users.

---

### fat GET

Tests whether the server processes body parameters on GET requests. Converts the selected GET to POST (with the body containing a canary-tagged version of an existing parameter), then re-issues the request as GET with the body still present. If the body parameter influences the response, the server supports "fat GET" — a common source of cache poisoning gadgets and request-smuggling attack primitives.

---

### input transformation

Checks whether an existing parameter's value is transformed (URL-decoded, HTML-decoded, serialised, or otherwise mutated) server-side before being reflected. Confirms input reflection exists first, then sends encoding variants to determine whether server-side transformation changes the reflected form. Useful for identifying filter bypasses, double-encoding gadgets, and dangerous transformation chains.

---

### normalised param

Determines whether the application URL-decodes parameter values before computing the cache key. Sends a percent-encoded canary (e.g., `kkvjq%61mdk` where `%61` = `a`), then checks whether a subsequent request with the decoded form (`kkvjqamdk`) receives the poisoned response — confirming that URL normalisation of the cache key enables Web Cache Poisoning.

---

### normalised path

Checks whether the server URL-decodes the path component (e.g., treating `%3f` as `?`) before computing the cache key. A mismatch between the key used for cache storage and the key used for retrieval can allow an attacker to poison the cache entry for the normal decoded URL by requesting the percent-encoded variant.

---

### rails param cloaking scan

Tests for the Rails UTM parameter-cloaking behaviour in which Rails automatically strips certain query parameters (`utm_source`, `utm_medium`, etc.) from the cache key while still processing them server-side. An unkeyed UTM parameter that influences the response body or headers constitutes a Web Cache Poisoning vulnerability requiring no unusual attacker capability.

---

### identify header smuggling mutations

Attempts to discover which header name mutations survive front-end rewriting and reach the back-end unmodified. Tests variants including extra whitespace, duplicate values, non-standard casing, tab-separated values, and HTTP/2 pseudo-header abuse. Used to find desync-exploitable header forms that bypass WAF rules or load-balancer normalisations — a prerequisite for many HTTP request smuggling and cache poisoning exploit chains.

---

*Param Miner by James Kettle (PortSwigger) — https://github.com/PortSwigger/param-miner*
