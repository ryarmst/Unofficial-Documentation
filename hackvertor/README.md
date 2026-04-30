# Unofficial Hackvertor Documentation

Hackvertor is a tag-based conversion extension for Burp Suite by Gareth Hayes (available [here](https://github.com/hackvertor/hackvertor)). This documentation was created with the assistance of an LLM-integrated IDE. While I (Ryan) reviewed the content and made some corrections/changes, there may nevertheless be some errors. 

## Tag Syntax

Tags use the format `<@tagname>content</@tagname>`. Arguments are passed in parentheses:

```
<@base64>hello</@base64>
<@find("\\w+")>abc123</@find>
```

Arguments can be strings (single or double quoted), booleans (`true`/`false`), or numbers (including hex like `0xff`).
## Documentation

| Document | Description |
|----------|-------------|
| [Editor](editor.md) | Main Hackvertor tab interface |
| [Tags Reference](tags.md) | Built-in tag categories and functions |
| [Custom Tags](custom-tags.md) | Creating tags in JS, Python, Groovy, Java |
| [Code Execution Tags](code-execution-tags.md) | Inline code in requests |
| [Tag Store](tag-store.md) | Installing community tags |
| [Repeater Integration](repeater-integration.md) | Using tags in Repeater, Intruder, etc. |
| [Global Variables](global-variables.md) | Storing and reusing values |
| [Tag Automator](tag-automator.md) | Automatic tag application rules |
| [Multi Encoder](multi-encoder.md) | Testing multiple encodings at once |
| [AI Features](ai-features.md) | AI-powered code generation |
| [Settings](settings.md) | Configuration options |
| [Tips & Tricks](tips-and-tricks.md) | Gotchas, debugging, best practices |

## Quick Start

1. Install Hackvertor from BApp Store (Extender → BApp Store → Hackvertor)
2. Open the Hackvertor tab
3. Type text in the input pane
4. Select text and click a tag button (e.g., base64 under Encode)
5. View output in the output pane

For Repeater usage:
1. Right-click in a request → Hackvertor → select a tag
2. The tag wraps your selection
3. When you send the request, Hackvertor converts the tagged content
4. Check Logger to see the actual sent request

