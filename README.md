Conf Sync allows for syncing your local files with a confluence page attachments using attachments API.

# Environment variables

## Required variables

```sh
CONF_USERNAME="confluence username"
CONF_PASSWORD="confluence password"
CONF_SYNC_DIR="~/local_dir_to_sync"
CONF_HOST="https://confluence.host.com"
```

## Optional variables

```sh
# full url or just path to your preferred page
# by default the application assumes that you have personal space with page named "Files"
CONF_PAGE_URL="/display/~YourLogin/Files"
# ignore patterns. Useful for not syncing temporaty files created by editors for example
CONF_IGNORE_FILES=".DS_Store,.vscode,.idea"
# interval in seconds how often to make requests to confluence server in order to sync state between upstream and downstream
# default 5
CONF_POLL_INTERVAL=5
```
