# Top 10 Param Miner Tuning Techniques

Practical configuration moves that meaningfully improve discovery rate, reduce noise, and cut scan time. Each technique is actionable in under a minute.

## 1. Seed the wordlist from the app itself

**Settings:** `request: On` · `response-headers: On` · `response-body: On` · `learn observed words: On`

The best parameter names for any target are the ones already in use by that target. Browse the application thoroughly before running a scan — every request and response that passes through the proxy grows the live candidate list. By the time you launch a Guess attack, Param Miner is already testing field names extracted from JSON responses, path segments, existing query parameters, and response headers. These in-context candidates will out-perform any generic wordlist on a bespoke application.

## 2. Layer wordlists by target type

**Settings:** `use basic wordlist` · `use bonus wordlist` · `use assetnote params` · `use custom wordlist`

Don't enable everything at once. A stacked wordlist produces diminishing returns and a much longer scan. Use a tiered approach:

- **Quick pass:** basic wordlist only — covers ~80% of common findings in a fraction of the time.
- **Thorough pass:** add `use bonus wordlist` and a technology-specific custom wordlist (Rails, Spring, Laravel, Django — each has a distinct set of meaningful parameter names).
- **Deep pass:** add `use assetnote params` only on high-value endpoints where time is not a constraint.

Keep `use assetnote params` off by default. It is enormous and rarely the source of the winning candidate.

## 3. Set `quantile factor` based on target stability

**Setting:** `quantile factor` (default: `2`, range: 1–10)

This is the single most impactful knob for controlling false positive rate. The default of 2 is calibrated for stable, deterministic targets. Raise it when:

- The target is behind a CDN with variable response sizes.
- Response bodies contain timestamps, nonces, or random tokens.
- You are getting candidates that don't reproduce on manual verification.

A value of 4–5 eliminates the majority of noise-driven false positives on dynamic targets. Don't go above 6 without a specific reason — you will start suppressing real findings on endpoints with low signal-to-noise.

## 4. Let Param Miner size its own buckets — but cap the ceiling

**Settings:** `force bucketsize: -1` · `max bucketsize: 256`

Auto-detection (`force bucketsize: -1`) is almost always the right call. Param Miner probes the target to find the largest request it will accept without behavioural change, which maximises throughput. However, the default ceiling of `65536` is unrealistically high for most targets and the auto-detector can occasionally land on an inflated value.

Setting `max bucketsize` to `256–512` is a practical upper bound for the vast majority of web targets. If you genuinely need higher, the auto-detector will tell you by probing up to your ceiling — you lose nothing by capping it conservatively first.

## 5. Use `skip boring words` for header scans, disable it for everything else

**Setting:** `skip boring words` (default: On)

The bundled `boring_headers` list filters out ubiquitous headers (`Accept`, `Accept-Encoding`, `Connection`, etc.) that almost never produce interesting server-side behaviour. Leave it On for header-guessing runs — it meaningfully cuts candidate count with negligible impact on discovery rate.

Disable it for body and query parameter scans where it has no effect anyway, and on second-pass header runs against targets that behaved unusually — the "boring" list occasionally excludes a header that a non-standard stack does care about.

## 6. Enable `dynamic keyload` on API endpoints — carefully

**Setting:** `dynamic keyload: On`

When Param Miner discovers that a parameter causes a different response, that response often contains new field names. `dynamic keyload` feeds those names back into the live candidate list mid-scan, compounding discovery. On JSON APIs with rich response bodies, this can surface parameters that no static wordlist contains.

The source code explicitly calls this "very powerful and quite buggy." Run it on targeted single-endpoint scans rather than broad multi-endpoint passes. If it crashes or produces garbage output, disable and re-run with static wordlists.

## 7. Match your cachebusters to the target's cache model

**Settings:** `include query-param` · `include origin` · `include via` · `include path` · `custom header cachebuster`

Using the wrong cachebuster doesn't just fail to bust the cache — it can itself become part of the cache key and skew results. Map your cachebuster choice to the target's observed caching behaviour:

- **Standard CDN (Cloudflare, Fastly, Akamai):** query-param cachebuster is sufficient and reliable.
- **Origin-keyed cache:** add `include origin` — some caches key on `Origin` and a randomised value guarantees a fresh response.
- **Aggressive normalisation (strips query params):** switch to `include path` or set a `custom header cachebuster` using a header you've confirmed the CDN passes through.
- **No caching:** turn all cachebusters off — they add unnecessary bytes and can trigger WAF rules on some targets.

## 8. Run `try -_ bypass` and Pascal-Case headers as a second pass

**Settings:** `try -_ bypass: On` · `include Hyphenated-Pascal-Case headers: On`

These are not first-pass settings. They double the number of header name variants sent and add meaningful scan time. Their value is specific: some front-ends normalise `x-forwarded-for` to `X-Forwarded-For` before forwarding, meaning the back-end only sees the Pascal-Case form. Others convert hyphens to underscores internally (`X_FORWARDED_FOR`). 

Run a clean first pass with defaults. If it returns nothing on a target you have reason to believe has interesting headers — based on its stack, infrastructure fingerprint, or prior experience — run a second pass with both options enabled.

## 9. Use `carpet bomb` + `force canary` for out-of-band discovery

**Settings:** `carpet bomb: On` · `force canary: <your-collaborator-id>`

When a parameter's effect is not visible in the HTTP response — it triggers a DNS lookup, an email, a webhook, a back-end HTTP request — reflection-based detection is blind to it. Carpet bomb mode sends every candidate without attempting to identify winners from the response. Pair it with a fixed Burp Collaborator (or interactsh) payload in `force canary` so every injected parameter value contains your callback domain.

Any out-of-band interaction that arrives at your collaborator can then be correlated back to the parameter name via the canary string. This is particularly effective against internal service integrations, notification pipelines, and audit log consumers.

## 10. Tune `confirmations` and `baseline size` together

**Settings:** `confirmations` (default: `5`) · `baseline size` (default: `4`)

These two settings control opposite ends of the detection pipeline. `baseline size` determines how many requests are used to build the fingerprint of a "normal" response before the attack starts. `confirmations` determines how many times a candidate must reproduce a deviation before it is reported.

On endpoints with high natural variance (content that changes per-request), raise `baseline size` to `8–10` to build a stable fingerprint. On very stable endpoints where you trust the signal completely, drop `confirmations` to `3` to cut confirmation overhead significantly. Never lower `baseline size` below `3` — a fingerprint built on fewer than three samples is statistically unreliable and will generate spurious candidates regardless of other settings.

*For the complete setting reference, see `param-miner-documentation.md`.*
