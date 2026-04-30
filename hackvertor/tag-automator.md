# Tag Automator

Automatically apply transformations to requests based on rules. Formerly called "Profiles."

## Overview

Tag Automator lets you define rules that:
- Analyze requests using Python
- Modify requests by wrapping content in Hackvertor tags
- Apply to specific tools (Repeater, Intruder, etc.)
- Run on requests, responses, or both

## Opening Tag Automator

**Hackvertor menu → Tag Automator**

## Creating a Rule

1. Click "New Rule"
2. Configure:
   - **Name**: Descriptive rule name
   - **Enabled**: Toggle rule on/off
   - **Type**: When to apply (Context Menu, HTTP Handler)
   - **Context**: Request, Response, or both
   - **Tools**: Which Burp tools (Repeater, Intruder, etc.)
   - **Analysis**: Python code to detect where to apply
   - **Modification**: Python code to apply Hackvertor tags

## Rule Types

| Type | Description |
|------|-------------|
| Context Menu | Manual trigger via right-click menu |
| HTTP Handler | Automatic on every matching request |

**Warning**: HTTP Handler rules run on every request. Use sparingly to avoid performance issues.

## Analysis Code

Python code that determines which parameters to modify.

Available variables:
- `request` - Full request string
- `headers` - List of headers
- `body` - Request body
- `params` - Dictionary of parameters

Must set `matchedParams` to a list of parameter names to modify.

Example:
```python
# Match 'data' parameter if it looks base64 encoded
import re
matchedParams = []
if 'data' in params:
    if re.match(r'^[A-Za-z0-9+/=]+$', params['data']):
        matchedParams.append('data')
```

## Modification Code

Python code that wraps matched parameters in Hackvertor tags.

Available variables:
- `paramName` - Current parameter name
- `paramValue` - Current parameter value

Must set `taggedParamValue` to the modified value.

Example:
```python
# Wrap in base64 decode tag
taggedParamValue = '<@d_base64>' + paramValue + '</@d_base64>'
```

## Example Rules

### Base64 Decode Detection

Automatically decode base64-looking parameters:

**Analysis:**
```python
import re
matchedParams = []
for name, value in params.items():
    if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', value):
        matchedParams.append(name)
```

**Modification:**
```python
taggedParamValue = '<@d_base64>' + paramValue + '</@d_base64>'
```

### URL Encode All Parameters

**Analysis:**
```python
matchedParams = list(params.keys())
```

**Modification:**
```python
taggedParamValue = '<@urlencode>' + paramValue + '</@urlencode>'
```

## Applying Rules

### Via Context Menu
1. Right-click in a request
2. **Hackvertor → Apply Tag Automation**
3. Select the rule to apply

### Via HTTP Handler
Rules with type "HTTP Handler" run automatically when:
- The tool matches (Repeater, Intruder, etc.)
- The context matches (request/response)