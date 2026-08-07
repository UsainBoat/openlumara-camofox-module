# openlumara-camofox-module

CamofoxModule: anti-detection browser automation module for the
[openlumara](https://github.com/UsainBoat/openlumara) AI agent framework.

It drives a [camofox-browser](https://github.com/jo-inc/camofox-browser) anti-detection
browser through its REST API (default `http://localhost:9377`).

## Requirements

- openlumara (provides the `core.module.Module` base class)
- `aiohttp`
- A running Camofox server with its REST API enabled

## Install

Copy `camofox_module.py` into your openlumara `user_modules/` directory
(or symlink it there):

```bash
ln -s /path/to/camofox_module.py ~/openlumara/user_modules/camofox_module.py
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `base_url` | `http://localhost:9377` | Base URL of the Camofox server. |
| `access_key` | *(empty)* | `CAMOFOX_ACCESS_KEY` / `CAMOFOX_API_KEY` if the server requires auth. |
| `user_id` | `default_user_123` | Session owner id (isolates cookies, localStorage and tabs). |

## Tools

- **Navigation:** `navigate`, `go_back`, `go_forward`, `refresh_page`, `stop_browser`, `start_browser`
- **Interaction:** `click`, `type_text`, `press_key`, `scroll`, `wait`
- **Extraction:** `extract`, `get_snapshot`, `get_links`, `get_images`, `get_downloads`
- **Browser:** `screenshot`, `set_viewport`, `evaluate`
- **Session:** `import_cookies`, `health_check`, `pressure_cleanup`, `close_group_tabs`
- **Traces / metrics:** `list_traces`, `download_trace`, `delete_trace`, `get_metrics`

## Security note

Responses pulled from live web pages are untrusted and may contain
prompt-injection attempts. The module prefixes such content with an
`UNSAFE` banner so the agent treats it strictly as data.
