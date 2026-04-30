# Settings

Configure Hackvertor behavior via **Hackvertor menu → Settings**.
## Tag Permissions

Control where Hackvertor tags are processed.
### Security Notes

**Proxy disabled by default**: Proxy handles requests you didn't explicitly send. Automatic tag execution could be dangerous with malicious responses.

**Code execution disabled by default**: System commands and custom code could compromise your machine. Only enable when using trusted tags.

## Requests

| Setting | Default | Description |
|---------|---------|-------------|
| Auto update content length | ✓ | Fix Content-Length after conversion |
| Maximum body length | 3 MB | Skip conversion if body exceeds this |

Large body limit prevents performance issues with big requests.

## Statistics

| Setting | Default | Description |
|---------|---------|-------------|
| Count tag usage | ✓ | Track which tags you use most |

Tag counts power the "Popular tags" context menu. Data stays local.

## AI

| Setting | Default | Description |
|---------|---------|-------------|
| Use AI to generate code | ✗ | Enable AI code generation |
| Use AI to summarise custom tags code | ✗ | Auto-describe custom tags |
| Use AI in tags | ✗ | Allow AI-powered tags |
| Debug AI requests | ✗ | Log AI conversations |
| Use AI to learn from Repeater | ✗ | Pattern detection |

See [AI Features](ai-features.md) for details.
## Misc

| Setting | Default | Description |
|---------|---------|-------------|
| Alphabetically sort tag categories | ✓ | Sort categories A-Z |
| Auto convert clipboard | ✗ | Convert clipboard on paste |
| Show output in message editor | ✗ | Display output pane in editor tab |
## System

| Setting | Default | Description |
|---------|---------|-------------|
| Python module path | (empty) | Path to Python modules for Jython |

Set this if your Python custom tags need to import external modules.

## Reset Settings

Click "Reset" to restore all defaults. Requires confirmation.

## Project-Specific Settings

Some settings (like global variables and Tag Automator rules) are saved per Burp project. Others (like permissions) are global to your Burp installation.

