# Tips & Tricks

Practical advice, common gotchas, and debugging techniques.

## Viewing the Actual Sent Request

**Problem**: Repeater shows tagged content, not what was sent.

**Solution**: Check **Logger**. The logged request shows the converted result.

Alternatively, right-click → **Hackvertor → Convert tags** to see the result in place (destructive—removes tags).

## Tag Execution Order

Tags execute **inside-out**:

```
<@base64><@urlencode>test</@urlencode></@base64>
```

1. `urlencode` runs first → `test`
2. `base64` runs on result → `dGVzdA==`

## Context Tags Security

Context tags (`context_url`, `context_header`, etc.) require a **tag execution key**.

**Why?** Prevents malicious servers from injecting harmful tags in responses that execute on your machine.

The key is generated per session. If tags aren't executing:
1. Check Settings → Tag permissions
2. Verify the execution key is present
3. Use the "rehydrate" button if needed

## Content-Length Auto-Update

Hackvertor auto-fixes Content-Length after conversion. If a request fails:
1. Check Settings → Auto update content length
2. Manually verify the body length

## Large Requests

Requests over 3MB (default) only convert headers, not body.

Adjust in Settings → Maximum body length.

## Python Path Issues

Python tags fail with import errors?

1. Set **Settings → Python module path** to your modules directory
2. Jython uses Python 2.7 syntax
3. Some Python 3 modules won't work

## Tags Not Working in Proxy

Tags in Proxy are disabled by default.

**Enable with caution**: Settings → Allow tags in Proxy

Risk: Malicious responses could contain tags that execute on your system.

## Smart Decode

Quick way to decode unknown encodings:

1. Select encoded text
2. `Ctrl+Alt+D` or right-click → Smart decode
3. Hackvertor attempts to identify and decode

Uses `auto_decode_no_decrypt` internally.

## Debugging Custom Tags

Your custom tag not working?

1. Enable **Settings → AI → Debug AI requests** (for AI tags)
2. Check Burp's **Extender → Extensions → Hackvertor → Errors**
3. Add `System.out.println()` (Java) or `print()` (Python) for logging
4. Test the code logic in the Hackvertor tab before using in Repeater

## Repeater Tab Naming

When using Hackvertor tags, the first-layer tag name becomes the Repeater tab name. Useful for organization.

## Copying Converted URLs

Need the converted URL for testing elsewhere?

Right-click → **Hackvertor → Copy URL**

Copies the URL with all tags converted.

## Popular Tags

The context menu shows your most-used tags. Enable in Settings → Count tag usage.

Tags are tracked per context (GET, POST, JSON) and globally.

## Insert Last Tag

Quickly re-apply your most recent tag:

Right-click → **Hackvertor → Insert last tag**

## Performance Tips

1. Avoid HTTP Handler automation rules when possible
2. Keep Tag Automator rules minimal
3. Large bodies slow conversion—adjust max body length
4. Disable unused AI features

## WebSocket Tags

Enable in Settings → Allow tags in WebSockets.

Tags in WebSocket messages convert before sending, just like HTTP.

## Export/Import Rules

Tag Automator rules can be exported:

1. Open Tag Automator
2. Select rule
3. Export to Clipboard
4. Share JSON with teammates

Import via "Import from Clipboard."

## Tag Finder

Search for tags by name:

1. Use the Tag Finder window
2. Or search within the Hackvertor Panel tabs
3. Faster than browsing categories

## Unique Tag Instances

Need the same tag with different behaviors in one request?

Append `_N` to create unique instances:

```
<@random_1(10)>abc</@random_1>
<@random_2(10)>abc</@random_2>
```

Both execute independently.

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| "Unsupported Tag" | Typo or missing custom tag | Check tag name spelling |
| Tags not converting | Tool not enabled | Check Settings → Tag permissions |
| Code execution disabled | Security setting | Enable "Allow code execution tags" |
| Context tag fails | Missing execution key | Check key is present |
| Python import error | Missing module | Set Python module path |

## Getting Help

- **Report bugs**: Hackvertor menu → Report bug/request feature
- GitHub: https://github.com/hackvertor/hackvertor

