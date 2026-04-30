# Global Variables

Store values that persist across conversions and can be referenced anywhere in Hackvertor/Burp.

## Creating a Global Variable

1. Go to **Hackvertor menu → Global variables**
2. Enter a variable name
3. Enter the value
4. Click "Create/Update variable"

## Using Variables

### Set a Variable in Tags

```
<@set("myvar")>some value</@set>
```

Or with the legacy syntax:
```
<@set_myvar>some value</@set_myvar>
```

To make it global (persists across requests):
```
<@set("myvar",true)>some value</@set>
```

### Get a Variable

```
<@get("myvar")></@get>
```

Or legacy:
```
<@get_myvar></@get_myvar>
```

If the variable doesn't exist, the tag content is returned as default:
```
<@get("undefined_var")>default value</@get>
```
→ Returns "default value"

## Variable Scope

| Type | Scope | Persistence |
|------|-------|-------------|
| Local variable | Single conversion | No |
| Global variable | All conversions | Yes (saved in project) |
Local variables (created without `true` argument) are reset each time you convert.

Global variables persist until deleted or Burp closes.

## Auto-Increment Variables

For fuzzing or iteration:

```
<@increment_var(0,"counter",true)></@increment_var>
```

Arguments:
1. Start value
2. Variable name
3. Enabled (boolean)

Each conversion increments the counter:
- First conversion: 0
- Second: 1
- Third: 2
- ...

Similarly, `decrement_var` counts down.

## Managing Global Variables

### Edit a Variable
1. Open **Global variables** window
2. Select the variable from the list
3. Click "Edit"
4. Update the value
5. Click "Create/Update variable"

### Delete a Variable
1. Open **Global variables** window
2. Select the variable
3. Click "Delete"

## Use Cases

### Session Tokens
Store a session token and reuse across requests:
```
<@get("session_token")></@get>
```

### Incrementing IDs
```
GET /api/user/<@increment_var(100,"user_id",true)></@increment_var>
```

### Computed Values
Store intermediate results:
```
<@set("hash")><@md5>password</@md5></@set>
Token: <@get("hash")></@get>
```

## In Globals Tab

The Globals tab in the Hackvertor interface shows all defined global variables. Click a variable to insert a `get` tag for it.

