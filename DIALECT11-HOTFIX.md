# Dialect11.1 UI hotfix

Installed locally as `2.9.0-dialect.11.1` on 2026-11-03 and included in the
subsequent `.11.2` release. This hotfix's runtime changes are confined
to browser templates and the GUI share-link model. Core handlers, backend
logic, database schema and protocol wire formats are unchanged.

## Missing inbound list

The global toolbar used `dbInbound`, a variable available only inside a table
row slot. Vue raised `ReferenceError: dbInbound is not defined` while rendering
the card title, leaving only the top statistics card visible. Inbound records
were still present in the API and database.

Global controls now use page-level subscription settings. Row-specific export
and native subscription conditions run inside their actual row scope.

The live installation was checked with an authenticated browser before and
after replacing its panel executable:

| Observation | Before | After |
| --- | --- | --- |
| Inbounds loaded into the page model | 2 | 2 |
| Visible page cards | 1 | 2 |
| Inbound tables | 0 | 1 |
| Visible inbound rows | 0 | 2 |
| Add Inbound buttons | 0 | 1 |
| Vue rendering exception | `dbInbound is not defined` | None |

A pre-update SQLite snapshot and panel binary were preserved privately. The
post-update inbound IDs and settings hashes match the originals. The installed
core binary is unchanged and the service is active. An unrelated pre-existing
missing-resource HTTP 404 remains in the browser console; it is not a Vue
rendering error and does not prevent the table or controls from rendering.

## Related UI corrections

- The outbound modal now invokes `outModal.ok()` with its receiver preserved.
  Its old unbound callback raised `this.check is not a function` on an actual
  OK-button click.
- Native clients now participate in client counts and status filters.
  Filtering native clients preserves other settings, including certificates,
  credentials and advanced fields.
- GUI VMess and Trojan share links retain enabled `rawUuidAuth` and
  `uuidHashPrefix` flags using the same syntax as backend exports.
- SS2022 GUI links normalize optional UUID identities into their proper binary
  base64 keys. The server PSK is preserved, explicit false overrides inheritance,
  and ordinary links remain unchanged. Invalid flag types fail explicitly.

## Verification

The earlier `.11` browser checks exercised editor fixtures and direct method
calls. They did not cover the complete Inbounds page or the actual outbound
OK event. New tests close those specific gaps:

- Complete Go-rendered Inbounds template with real Vue/Ant assets and controlled
  HTTP data: empty, legacy-only, native-only and mixed datasets pass. Checks
  exercise actual table/toolbars, global and row actions, expansion, counts,
  search, disabled/online filters, settings retention and subscription modes.
- The original template fails the negative-control test with the same
  `ReferenceError` reproduced on the live installation.
- Outbound browser suite: 16 grouped scenarios pass, including 13 real OK-button
  submissions across native desktop/mobile cases and legacy SOCKS. The original
  callback fails its negative control. Invalid JSON disables the real button.
- Node checks: 110 inbound checks, 45 outbound/restore tests, and 13 focused
  decoded share-link tests pass. Ordinary links are pinned to prior output.
- Linux AMD64 and ARM64 panel bundles build successfully. The ARM64 version
  command passes under QEMU. Both core executables match `.11` byte for byte;
  no protocol test rerun is implied by this frontend-only correction.
- Authenticated live AMD64 browser verification confirms the deployed panel
  renders both existing inbounds and the Add button. Database settings and
  the core binary were checked for preservation.

Sources: `tests/dialect11/inbounds-page-ui.js`,
`tests/dialect11/outbound-native-ui.js`, and
`tests/dialect11/inbound-share-links.test.js`. The full-page harness uses mocked
API data; the separate live check covers the installed page without changing
inbound configuration. This is bounded regression coverage, not a claim that
every UI state or future defect is ruled out.

Evidence on the build host is under `/root/x-ui-dialect11-work/agents/`:
`inbounds-page-ui-before.log`, `inbounds-page-ui-fixed-final.log`,
`outbound-modal-before-11.1-test.log`, `outbound-ui-11.1-results.json`, and
`inbound-share-links-hotfix-tests-final.log`. Live observations and preservation
checks are under `/root/x-ui-dialect11-work/hotfix-inbounds/`; private backups
and live configuration are excluded from delivered source archives.

## Executable hashes

| Executable | SHA-256 |
| --- | --- |
| AMD64 panel, deployed and verified | `14b037d9b0064dfcee7787a3032f38c8a8163ae1b6c96ef5352b2f5f71416dac` |
| ARM64 panel | `75fa83b5ddc4491d41e8f73649628d58a66a88213cd7b76c7e5154bf30d503ce` |
| AMD64 core, unchanged | `eedc29ec3176743533e489b00914e3435c9d8c11e05d1ef3b2bdfac4b1a6d3cd` |
| ARM64 core, unchanged | `87fe205bc66d3f786b3ebbb8632b2761f1561beb72aa101f8d67cb23393a6af2` |

Archive checksums accompany the release. Existing protocol compatibility limits
and the inherited stock SS2022 UDP dependency race remain described in
[DIALECT11.md](DIALECT11.md) and
[DIALECT11-VERIFICATION.md](DIALECT11-VERIFICATION.md).
