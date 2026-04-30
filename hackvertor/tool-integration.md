# Repeater

Hackvertor tags work inside Repeater, Intruder, Scanner, and other Burp tools. Tags are converted when the request is sent.

## Using Tags in Repeater

1. Open a request in Repeater
2. Select the text you want to transform
3. Right-click → **Hackvertor** → choose a tag
4. The tag wraps your selection
5. Send the request—Hackvertor converts before sending

Example:
```
GET /api?token=<@base64>admin:password</@base64> HTTP/1.1
```

When sent, the server receives:
```
GET /api?token=YWRtaW46cGFzc3dvcmQ= HTTP/1.1
```

## Viewing Converted Requests

**Important**: The Repeater window shows the *tagged* request, not what was actually sent.

To see the converted request:
- Check **Logger** (the actual sent request is logged)
- Or use **Convert tags** from the context menu before sending

## Context Menu Options

Right-click in a request to access:

| Option | Description |
|--------|-------------|
| **Send to Hackvertor** | Open in Hackvertor tab |
| **Insert last tag** | Quick insert of most recent tag |
| **Copy URL** | Copy URL after tag conversion |
| **Convert tags** | Convert all tags in place |
| **Clear tags** | Remove all Hackvertor tags |
| **Smart decode** | Auto-decode selected text |
| **Multi Encoder** | Open multi-encoder window |
| **Apply Tag Automation** | Run automation rules |
| **Popular tags** | Quick access to frequently used tags |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Alt+D` | Smart decode selection |
| `Ctrl+Alt+M` | Open Multi Encoder |

## Intruder

Tags work in Intruder payloads:

1. Set up your Intruder attack
2. In payload positions or payload processing, include Hackvertor tags
3. Tags are converted for each request

Example payload position:
```
GET /api?id=<@base64>§payload§</@base64> HTTP/1.1
```
## Scanner

Tags in Scanner requests are converted before scanning. 

## Payload Processor

Hackvertor can process Intruder payloads:

1. In Intruder, go to Payloads tab
2. Add a Payload Processing rule
3. Select "Invoke Burp extension" → Hackvertor
4. Your payloads will be processed through Hackvertor

## WebSocket Support

Enable in Settings → Allow tags in WebSockets.

Tags in WebSocket messages are converted before sending.

## Proxy Note

By default, tags in Proxy are **disabled** for safety. The Proxy processes requests you didn't explicitly send, so automatic tag execution could be dangerous.

Enable with: **Settings → Allow tags in Proxy**