# Hackvertor Editor

The main Hackvertor tab provides a live encoding/decoding workspace.

## Interface Layout

- **Input pane**: Enter text and tags here
- **Output pane**: Shows converted result (updates live)
- **Hex view**: Shows output in hex format
- **Tag tabs**: Categories of available tags (Encode, Decode, Hash, etc.)

## Basic Usage

1. Type or paste text in the input pane
2. Select the text you want to transform
3. Click a tag button from the category tabs
4. The tag wraps your selection; output updates immediately

Example:
```
Input:  <@base64>hello world</@base64>
Output: aGVsbG8gd29ybGQ=
```

## Tag Tabs

Tags are organized by category. Click a category tab to see available tags:

- **Encode/Decode**: Base64, URL, HTML entities, hex, etc.
- **Hash**: MD5, SHA variants, HMAC
- **String**: Case changes, find/replace, substring
- **Convert**: Number base conversions
- **Encrypt/Decrypt**: AES, XOR, ciphers
- **Math**: Random generation, arithmetic
- **And more...**

## Nesting Tags

Tags process from innermost to outermost:

```
<@base64><@urlencode>test&value</@urlencode></@base64>
```

1. First: `test&value` → `test%26value` (URL encoded)
2. Then: `test%26value` → `dGVzdCUyNnZhbHVl` (Base64 encoded)

## History

Hackvertor remembers your recent conversions. Access history using the arrow keys.

## Message Editor Tab

Hackvertor also appears as a message editor tab in request/response viewers throughout Burp. Select "Hackvertor" from the editor tabs to use the interface directly on any request.

The message editor version has a setting to show/hide the output pane (Settings → Show the output panel in the message editor).

## Tabbed Interface

You can open multiple Hackvertor panels as tabs. Each tab maintains its own input/output and history.