# Multi Encoder

Easily add and modify multiple encodings.

## Accessing Multi Encoder

1. Select text in a request
2. Right-click → **Hackvertor → Multi Encoder**
3. Or use keyboard shortcut: `Ctrl+Alt+M`

Also accessible from the Hackvertor extension panel.

## Interface

- **Input**: The selected text
- **Tag categories**: Checkboxes to include/exclude tag types
- **Layers**: Number of encoding layers to apply
- **Results table**: All encoding variations with output

## How It Works

Multi Encoder applies every selected tag to your input and shows all results. With layers > 1, it chains tags (e.g., base64 → url encode).

Example with "test" and 1 layer:
- `base64` → `dGVzdA==`
- `urlencode` → `test` (no change)
- `hex` → `74 65 73 74`
- `html_entities` → `test`
- ...
## Layers

Layers determine nesting depth:

| Layers | Effect                                        |
| ------ | --------------------------------------------- |
| 1      | Single encoding: `<@tag>input</@tag>`         |
| 2      | Double: `<@tag1><@tag2>input</@tag2></@tag1>` |

