# Slow-download and CLI update fixes — dialect11.6

A roughly 70 MiB release takes about sixteen minutes at 75 KiB/s. The previous
installer imposed a fifteen-minute transfer limit, so a productive slow
connection could time out near completion. Its built-in retries could then
restart the download. The initial `curl: (23) Failure writing output to
destination` message was a separate issue: a release-tag filter stopped reading
before curl had finished writing the metadata response.

## Changes

- Both release lookups consume the entire response before selecting the tag,
  eliminating the early-closed-pipe warning. Metadata retrieval still has
  connection, transfer and retry bounds.
- `x-ui update -y` and `x-ui update --yes` now skip confirmation. The CLI passes
  these arguments to the update function; unknown flags are rejected. Without
  either flag, the existing confirmation/default behavior remains.
- The CLI pins the version it displayed and the user approved, instead of asking
  for `latest` again during installation. Download/installer errors return a
  nonzero process status; success is reported only after the installer succeeds.
- Archive transfers retain partial bytes across up to five automatic attempts.
  Curl checks the server's Range response. A server that ignores Range or sends
  an inconsistent offset causes a clean retry, never an unsafe manual append.
- A progressing archive transfer has no fixed total-time cutoff. Connections
  have a twenty-second connect timeout; less than 1 KiB/s for 120 seconds ends
  that attempt and allows a resume. These limits allow the observed slow but
  productive connection to complete while still bounding stalled attempts.
- The selected tag's `SHA256SUMS` must contain exactly one valid checksum for
  the architecture's archive. SHA256, gzip integrity and a nonempty tar listing
  must all pass before extraction or stopping the installed panel. A complete
  file can be accepted after a late socket error or HTTP 416 only if it passes
  those checks.
- The browser can monitor an active update for up to sixty minutes, instead of
  stopping after fifteen. Its restart handling, terminal failure reporting,
  shared lock and no-automatic-POST-retry behavior remain intact.

Resume applies to automatic attempts within the same installer run. An entirely
new invocation still uses fresh staging. These changes improve reliability;
they do not guarantee higher throughput from GitHub on a particular server.

## Compatibility

Upgrading an installed dialect10 panel to a current release works: the checksum
comes from the destination release, not from the installed version. Older
releases deliberately selected for downgrade may not publish `SHA256SUMS`.
The remote installer now fails clearly for those rather than skipping integrity
checks; an independently verified archive can still be installed with
`XUI_LOCAL_TARBALL`. Local archives are checked for gzip/tar integrity.

An already-running older CLI or installer retains its old behavior. Once this
release is installed, its `x-ui` command recognizes `-y`. The current installer
from the repository also contains the resume fix; do not start a second install
while an existing one holds the update lock.

No protocol implementation, credential-generation logic or stored inbound data
was changed in this patch. The bundled cores must remain byte-identical to
those in dialect11.5.

## Verification

- 21 tests used real curl against controlled loopback HTTP endpoints. They
  covered interrupted transfers, resumed 206 responses, ignored Range, invalid
  offsets, complete and incomplete 416 responses, checksum failures, malformed
  or missing manifests, large release metadata, an idle timeout and a paced
  approximately 75 KiB/s transfer. Corrupt/empty archives and unsuccessful
  downloads failed before simulated live-installation mutations.
- 13 tests executed the complete CLI dispatcher with inert local curl/installer
  substitutes. They covered both yes flags, interactive acceptance/cancellation,
  same-version reinstall policy, unknown options, large metadata, tag pinning,
  temporary-file cleanup, malformed installer syntax and exit-status propagation.
- 28 updater UI lifecycle tests passed, including a download progressing beyond
  seventeen minutes and the new bounded sixty-minute monitoring deadline.
- The installer shared-lock regression passed. Shell syntax and whitespace
  checks passed. No live system services or external downloads were invoked by
  these fixture tests.

Build identities, package checks and any live deployment results are recorded
separately after packaging. Earlier dialect11.5 protocol verification remains
historical; it is not relabeled as a new test run of every protocol.
