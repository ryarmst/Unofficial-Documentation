# Code Execution Tags

Run code directly inline within requests without creating a saved custom tag.

## Requirements

1. Enable **Settings → Allow code execution tags**
2. For Python: Configure Jython in Burp's Extensions settings (download Jython JAR and set the path)

## Available Language Tags

| Tag | Engine |
|-----|--------|
| `python` | Jython (Python 2.7) |
| `javascript` | GraalJS |
| `groovy` | GroovyShell |
| `java` | BeanShell |

## Basic Syntax

```
<@python('output = "result"', 'EXECUTION_KEY')></@python>
```

The tag takes two arguments:
1. **Code** - Your code as a string. Must set `output` variable.
2. **Execution key** - Auto-generated security token

## Adding a Code Tag

1. Go to the Hackvertor tab
2. Select **Languages** from the tag categories
3. Click the language (e.g., `python`)
4. The tag is inserted with an auto-generated execution key

## Viewing Output

Use the **Hackvertor tab** to test code tags before using in requests. The output pane shows your result immediately.

## Examples

### Generate a List (Python)

Generate JSON dynamically instead of writing it manually:

```
<@python('import json
json_array = []
for n in range(1,6):
    json_array.append({"id": "10004567"+str(n),"type":"User"})
output = json.dumps(json_array)', 'EXECUTION_KEY')></@python>
```

Result:
```json
[{"id": "100045671", "type": "User"}, {"id": "100045672", "type": "User"}, ...]
```

### Calculate a Signature

Compute an MD5 hash of request parameters:

```
POST /api HTTP/1.1
Host: example.com

id=123&name=test&hash=<@md5><@get("params")></@get></@md5>

<@set("params")>id=123&name=test</@set>
```

### Read a File

```
<@python('
with open("/path/to/file.txt", "r") as f:
    output = f.read()
', 'EXECUTION_KEY')></@python>
```

### Parameter Generation Example

Instead of sending 1000 requests, include 1000 variations in one request:

```
<@python('
items = []
for i in range(1, 1001):
    items.append("user_" + str(i) + "=test")
output = ",".join(items)
','EXECUTION_KEY')></@python>
```

Python relies on indentation. In Hackvertor tags, use newlines to maintain proper spacing:

```
<@python('
output = "Numbers: "
for n in range(5):
    output += str(n)
','EXECUTION_KEY')></@python>
```
Note also that there is no tolerance for whitespace between tag parameters and the comma separator.
## Checking Sent Requests

View Logger to confirm the code executed and see the actual values sent.

## Security Warning

Code execution tags can access the filesystem and network. Only enable when needed and never use with untrusted input.

## Combining with Variables

Use `set` and `get` tags alongside code:

```
<@set("computed")><@python('output = str(123 * 456)', 'KEY')></@python></@set>

Result: <@get("computed")></@get>
```
