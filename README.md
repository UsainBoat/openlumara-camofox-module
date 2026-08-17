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
| `cookie_dir` | *(empty)* | Directory allowed for cookie import validation. |

### Per-function toggles

All public methods can be toggled via `enable_<method>` settings. Defaults are `true`.

| Toggle | Method |
|---|---|
| enable_create_tab | create_tab |
| enable_navigate | navigate |
| enable_go_back | go_back |
| enable_go_forward | go_forward |
| enable_refresh_page | refresh_page |
| enable_click | click |
| enable_type_text | type_text |
| enable_press_key | press_key |
| enable_scroll | scroll |
| enable_set_viewport | set_viewport |
| enable_get_snapshot | get_snapshot |
| enable_extract | extract |
| enable_get_links | get_links |
| enable_get_images | get_images |
| enable_get_downloads | get_downloads |
| enable_evaluate | evaluate |
| enable_get_tab_stats | get_tab_stats |
| enable_screenshot | screenshot |
| enable_close_tab | close_tab |
| enable_close_session | close_session |
| enable_import_cookies | import_cookies |
| enable_list_tabs | list_tabs |
| enable_health_check | health_check |
| enable_wait | wait |
| enable_start_browser | start_browser |
| enable_stop_browser | stop_browser |
| enable_get_metrics | get_metrics |
| enable_pressure_cleanup | pressure_cleanup |
| enable_close_group_tabs | close_group_tabs |
| enable_list_traces | list_traces |
| enable_download_trace | download_trace |
| enable_delete_trace | delete_trace |

Disabled methods return `"<method> is disabled by config"` with success=False.

## Tools

- **Navigation:** `navigate`, `go_back`, `go_forward`, `refresh_page`, `stop_browser`, `start_browser`, `create_tab`, `close_tab`, `list_tabs`, `close_session`
- **Interaction:** `click`, `type_text`, `press_key`, `scroll`, `set_viewport`, `wait`
- **Extraction:** `extract`, `get_snapshot`, `get_links`, `get_images`, `get_downloads`, `evaluate`, `get_tab_stats`, `screenshot`
- **Session / System:** `import_cookies`, `health_check`, `pressure_cleanup`, `close_group_tabs`, `get_metrics`, `list_traces`, `download_trace`, `delete_trace`

## Security note

Responses pulled from live web pages are untrusted and may contain
prompt-injection attempts. The module prefixes such content with an
`UNSAFE` banner so the agent treats it strictly as data.
