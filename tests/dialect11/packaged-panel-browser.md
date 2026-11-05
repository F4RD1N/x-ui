# Packaged panel browser and restore checks

The browser smoke loads the HTML and JavaScript embedded in a supplied panel binary. It does not render repository templates or substitute API responses. Run as a user permitted to create network namespaces, with Python `requests`, Node.js, an existing Playwright installation, Chromium, `ip`, and `unshare` available.

```bash
PLAYWRIGHT_MODULE=/path/to/node_modules/playwright \
CHROME=/path/to/chromium \
python3 -B tests/dialect11/packaged-panel-browser.py --netns \
  --panel /path/to/unpacked/x-ui/x-ui \
  --core /path/to/unpacked/x-ui/bin/xray-linux-amd64 \
  --client-core /path/to/unchanged-client-core \
  --work /path/to/new-private-test-directory
```

`--repo` can select the checkout containing the shared `panel-e2e.py` helper; by default it is the checkout containing this script. Every executable path is explicit. The packaged panel starts in a fresh database and a private network namespace with loopback only. The source checkout, installed service and production database are not modified.

Five initial inbounds (OpenVPN, AnyTLS, ShadowTLS, DNSTT and Mieru) are generated and created through the real panel API. The authenticated API session is carried into Playwright. The test then checks actual rendered inbounds, new-protocol dialogs, typed edits saved through modal buttons, full JSON copy buttons using native clipboard or the real fallback, and outbound dialogs followed by a real Save/reload. The immutable client parses all five copied full configurations. Page/console errors, loaded asset paths, screenshots and exact binary hashes are recorded. This is a UI/storage smoke; traffic and comprehensive setting combinations are covered by the protocol integration suites. The login form itself is not exercised.

Before saving an outbound, every original protocol and chaining field must survive modal serialization. An omitted stream block may acquire only the editor's existing no-op TCP default. The reloaded outbound must then match the serialized modal output exactly. This catches lost SS2022 UDP-over-TCP versions and explicit zero user levels without treating harmless default serialization as corruption.

All credentials are synthetic, freshly generated test material. The session cookie, copied configs and screenshots stay in the private work directory and must not be included in public source archives.

To independently compare a completed `default-profiles-e2e.py` backup with its restored database:

```bash
python3 -B tests/dialect11/verify-restored-user-data.py \
  --backup /path/to/generated-profiles/profiles-backup.zip \
  --restored /path/to/generated-profiles/panel-restored/db/x-ui.db \
  --output /path/to/private-report.json
```

The comparator opens SQLite read-only and verifies administrator password hashes, inbound metadata, every saved client field, server material, unknown fields and selected panel settings. It expects the one extra OpenVPN client intentionally issued after restoration by the generated-profile suite. It does not require byte-identical database files because the traffic tests legitimately update counters. Reports omit secret values.

Offline tests (no listeners, browser or namespace starts):

```bash
python3 -B tests/dialect11/test_packaged_panel_harness.py
```
