# Param Miner — Top Use Cases & Ideal Configurations

---

## Use Case 1: Web Cache Poisoning Discovery

### Overview

Web cache poisoning is the highest-impact finding Param Miner was purpose-built to surface. The attack primitive is straightforward: a parameter exists that influences the response content but is excluded from the cache key. An attacker who can inject a malicious value into that parameter poisons the cached response, which is then served to every subsequent user who requests the same URL — no per-victim interaction required.

Param Miner operationalises this by discovering the unkeyed parameters first (via `Guess headers` and `Guess query params`), then automatically testing each discovered parameter for cache poisoning behaviour via its `try cache poison` logic. The extension sends the parameter with a canary value, then makes a fresh cacheless request and checks whether the canary appears in the response — confirming the poisoned entry was stored and served.

The most commonly discovered vectors are HTTP headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, and similar routing headers that CDNs and reverse proxies strip from the cache key before forwarding to the origin. When the origin reflects the header value into the response (e.g., into a `<link>` canonical tag, a redirect `Location`, or a JavaScript variable), and the CDN caches that response, the poisoning primitive is complete.

### Ideal Configuration

```
per-thread throttle:                 500–1000ms
thread pool size:                    3–4
live-scan:                           Off

use key:                             On
key path:                            On
key status:                          On
key server:                          Off
key input name:                      On

filter HTTP:                         On   ← HTTPS targets only; caches rarely sit in front of plain HTTP
skip vulnerable hosts:               Off  ← you want full coverage per endpoint
mimetype-filter:                     (empty)

require consistent evidence:         On
quantile factor:                     4    ← tighter than default to reduce FPs on noisy CDN responses
quantitative confirmations:          50

include query-param in cachebusters: On
include via in cachebusters:         On
include path in cachebusters:        Off
custom header cachebuster:           (empty)

learn observed words:                On   ← picks up header names the target references in its own responses
response-headers:                    On
request:                             On
use basic wordlist:                  On
use assetnote params:                Off  ← overkill for header guessing; adds noise
use custom wordlist:                 Off

bruteforce:                          Off
skip uncacheable:                    Off  ← let Param Miner make this determination per-endpoint
max one per host:                    Off
scan identified params:              Off
fuzz detect:                         Off
try cache poison:                    On   ← essential — this is the whole point
twitchy cache poison:                Off  ← start with Off; enable only if initial pass finds nothing
try -_ bypass:                       Off

force bucketsize:                    -1
max bucketsize:                      65536
lowercase headers:                   On
include Hyphenated-Pascal-Case:      Off  ← enable on a second pass if initial pass is clean
```

**Recommended attack sequence:**

1. Send the target request to Repeater and confirm a baseline response.
2. Right-click → Param Miner → **Guess headers** — the primary vector class for cache poisoning.
3. Right-click → Param Miner → **Guess query params** — catches unkeyed query parameters.
4. For any candidate found, manually confirm using **Unkeyed param** from the context menu.
5. If the target has route-based caching, also run **normalised path** and **normalised param** to catch cache-key normalisation issues.

**Key notes:**

- Set a meaningful cachebuster (`include query-param in cachebusters: On`) on every request to avoid accidentally poisoning the live cache during testing.
- A throttle of 500–1000ms significantly reduces the risk of your probe responses themselves being cached during the bucket-send phase.
- If the target uses a CDN that strips `Via`, enabling `include via in cachebusters` adds another reliable cache-busting dimension.
- Enable `twitchy cache poison` on a second pass only — it catches non-reflected poisoning (e.g., where the parameter affects response size or sets a header) but produces meaningfully more false positives.

---

## Use Case 2: Hidden Parameter Discovery on APIs and Web Applications

### Overview

Modern web applications and APIs routinely accept parameters that are never documented, never surfaced in the UI, and never appear in any client-side JavaScript — but are actively processed server-side. These parameters often represent development shortcuts: debug flags (`debug=true`, `verbose=1`), environment overrides (`env=staging`), feature toggles (`beta=1`, `admin=true`), internal routing hints, or legacy compatibility switches. Finding them can yield everything from information disclosure to authentication bypass to full privilege escalation.

Param Miner's differential analysis engine is designed precisely for this. It batches candidate names into a single request, compares the response against a baseline, and uses statistical analysis to identify which specific name (within the batch) caused a difference. This makes it dramatically faster than sending one parameter per request, which is the naive approach.

This is the highest-signal use of Param Miner in a standard web application pentest. It should be run against every interesting endpoint — authenticated and unauthenticated, GET and POST, JSON and form-encoded.

### Ideal Configuration

```
per-thread throttle:                 0–200ms
thread pool size:                    8        ← default; increase to 12–16 on stable targets
live-scan:                           Off

use key:                             On
key path:                            On
key status:                          On
key server:                          Off
key input name:                      On

filter HTTP:                         Off      ← test everything, HTTP and HTTPS
skip vulnerable hosts:               Off
mimetype-filter:                     (empty)

require consistent evidence:         On
quantile factor:                     2        ← default; balanced sensitivity
quantitative confirmations:          50

include query-param in cachebusters: On
include via in cachebusters:         Off      ← not relevant here; caching is not the target
include path in cachebusters:        Off
custom header cachebuster:           (empty)

learn observed words:                On       ← critical for APIs; mines field names from JSON responses
response-headers:                    On
request:                             On       ← mines existing param names as seed candidates
use basic wordlist:                  On
use assetnote params:                On       ← worth enabling for thorough API coverage
use custom wordlist:                 On       ← load an app-specific or technology-specific wordlist
bruteforce:                          Off

skip uncacheable:                    Off
only report unique params:           Off      ← you want per-endpoint results
max one per host:                    Off
max one per host+status:             Off
scan identified params:              Off      ← enable if you have Burp Pro and want auto active-scan follow-up
fuzz detect:                         Off      ← enable separately on a targeted pass if you suspect error-only triggers
try cache poison:                    Off      ← not the goal here; reduces noise
twitchy cache poison:                Off

try -_ bypass:                       Off
force bucketsize:                    -1
max bucketsize:                      65536
lowercase headers:                   On
include Hyphenated-Pascal-Case:      Off
```

**Recommended attack sequence:**

1. Authenticate to the application and capture a representative set of requests covering all major functional areas.
2. For each interesting endpoint, right-click → Param Miner → **Guess everything!** for broad initial coverage.
3. For JSON API endpoints specifically, run **Guess body params** individually — Param Miner will adapt to the JSON structure automatically.
4. Review findings in the Output tab; for any candidate, manually test with `debug=true`, `admin=1`, `test=1`, `verbose=true` to confirm the behaviour.
5. On a second pass, enable `use assetnote params` and `fuzz detect` on endpoints that returned nothing in the first pass but behave unusually.

**Key notes:**

- `learn observed words: On` is particularly powerful against JSON APIs — Param Miner will extract field names from every response it sees and use them as candidates on subsequent requests. An API that returns `{"userId": ..., "accountType": ...}` will have those exact names tested as parameter candidates on the next endpoint.
- Build a custom wordlist tailored to the technology stack. A Rails app wordlist should include `authenticity_token`, `_method`, `format`; a Spring app wordlist should include `_csrf`, `jsessionid`; a Laravel app wordlist should include `_token`, `page`, `paginate`.
- Leave `only report unique params: Off` during a pentest — the same parameter name appearing on two different endpoints with different effects is two separate findings.
- `fuzz detect` uses error-triggering payloads rather than canary-reflection to detect parameters. It should be run as a second pass because it dramatically changes the detection methodology and is most useful when the application fails silently on unrecognised inputs (no reflection, no size change, no timing difference — but does throw an error with the right fuzz string).

---

## Use Case 3: HTTP Request Smuggling — Header Mutation Reconnaissance

### Overview

HTTP request smuggling exploits disagree between front-end and back-end HTTP parsers about where one request ends and the next begins. But before constructing a full smuggling attack, the attacker needs to understand how the front-end (CDN, load balancer, WAF) rewrites or strips headers before forwarding to the origin. A header that reaches the back-end unmodified when sent through a mutation is a smuggling gadget — and Param Miner's `identify header smuggling mutations` attack, combined with targeted header guessing, is the most systematic way to map this surface.

The specific goal is twofold. First, identify which headers the front-end rewrites or drops (so you know what you cannot rely on). Second, identify mutation forms — extra whitespace, tab separators, duplicate headers, non-standard capitalisation, HTTP/2 pseudo-headers — that bypass the front-end rewrite and land on the back-end in an unexpected form. These mutations are what make `Transfer-Encoding` smuggling attacks work when `Transfer-Encoding: chunked` alone is blocked or normalised.

This use case pairs Param Miner with manual smuggling tools (Burp's HTTP Request Smuggler, or manual Repeater work). Param Miner does the reconnaissance; you do the exploitation.

### Ideal Configuration

```
per-thread throttle:                 200–500ms  ← smuggling-adjacent probes should be slow and deliberate
thread pool size:                    4          ← low; connection-level mutations are sensitive to concurrency

use key:                             Off        ← you want to test every request independently; no dedup
key path:                            Off
key status:                          Off
key server:                          Off
key input name:                      Off

filter HTTP:                         On         ← HTTP/2 downgrade smuggling targets are HTTPS only
skip vulnerable hosts:               Off
mimetype-filter:                     (empty)

require consistent evidence:         On
quantile factor:                     3
quantitative confirmations:          50

include query-param in cachebusters: On
include via in cachebusters:         Off
include path in cachebusters:        Off
custom header cachebuster:           (empty)

learn observed words:                Off        ← not useful here; mutations are structural, not wordlist-driven
response-headers:                    On         ← useful for detecting which headers the back-end sees
request:                             Off
use basic wordlist:                  On         ← needed as the base candidate set for header guessing
use assetnote params:                Off
use custom wordlist:                 Off

bruteforce:                          Off
skip uncacheable:                    Off
max one per host:                    Off
scan identified params:              Off
fuzz detect:                         Off
try cache poison:                    Off
twitchy cache poison:                Off

try -_ bypass:                       On         ← explicitly relevant: tests header name normalisation
identify smuggle mutations:          On         ← core to this use case

force bucketsize:                    -1
max bucketsize:                      65536
lowercase headers:                   On
include Hyphenated-Pascal-Case:      On         ← tests whether the front-end treats X-Forwarded-For
                                                   differently from x-forwarded-for; surfaces parser differentials
```

**Recommended attack sequence:**

1. Capture a stable baseline request through the proxy to the target endpoint.
2. Right-click → Param Miner → **identify header smuggling mutations** — this is the primary reconnaissance action. It tests mutation forms of existing headers (whitespace, tab, duplicate, case variants) and reports which ones produce distinct back-end responses.
3. Right-click → Param Miner → **Guess headers** — identifies which additional headers reach the back-end at all. Headers that pass through are potential smuggling gadgets.
4. Cross-reference results with known `Transfer-Encoding` mutation payloads: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked` (space before colon), `Transfer-Encoding\t:\tchunked`, `X: X\nTransfer-Encoding: chunked`. Test any mutation form Param Miner reports as producing a different response.
5. Feed confirmed pass-through headers and mutation forms into Burp's HTTP Request Smuggler extension for full TE.CL / CL.TE / H2.TE exploitation.

**Key notes:**

- Turn `use key: Off` entirely for this use case. Deduplication will suppress exactly the variation you need to observe — each mutated form of a header is a deliberately distinct probe, not a duplicate.
- `try -_ bypass: On` and `include Hyphenated-Pascal-Case: On` together test two of the most common front-end normalisation patterns. A hyphen-to-underscore normalisation in the front-end that the back-end does not apply is a classic smuggling-enabling differential.
- Low thread count (`4`) and a throttle (`200–500ms`) are important. Smuggling-adjacent probes involve connection-level state, and high concurrency can cause connection reuse across probes, contaminating results.
- If the target is HTTP/2 capable, Param Miner's header guessing will naturally test pseudo-headers (`:path`, `:method`, `:scheme`, `:authority`) which are a distinct and productive attack surface for H2.TE and H2.CL smuggling variants.
- After this reconnaissance phase, the actual smuggling exploitation is out of scope for Param Miner — hand off to HTTP Request Smuggler with the mutation forms identified here.

---

*Param Miner by James Kettle (PortSwigger) — https://github.com/PortSwigger/param-miner*
