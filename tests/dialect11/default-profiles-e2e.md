# Automatic native profile integration checks

Run `run-default-profiles-e2e.sh` with `--panel`, `--core`, `--client-core`, and a fresh `--work` directory. The wrapper requires Linux network namespace support and assigns a benchmark-range address only inside its disposable namespace. It never opens the installed panel database, publishes ports, changes host routes or firewall rules, or contacts a provider.

The runner imports the ordinary panel E2E helpers. Python `requests`, OpenSSL, curl, iproute2, and unshare must already be available. It disables Python bytecode generation so running it does not create source-tree caches.

The six initial profiles are generated through the authenticated HTTP credential API with only `kind` and `protocol`. ShadowTLS additionally receives the owned loopback cover address; its cover port is adapted to the local test listener. Orbit's first request deliberately uses `Host: localhost` to exercise domain-hosted endpoint resolution; a second fresh request uses the numeric loopback host. DNSTT omits its domain and must generate a direct UDP-compatible synthetic tunnel name. No protocol credential, certificate, or exported outbound is repaired by the test.

The controlled ShadowTLS cover has its own test CA. `SSL_CERT_FILE` provides that CA to test processes while certificate validation stays enabled. This is separate from a public deployment's normal system roots. The existing customized 25.3.6 client is used unchanged, with its existing `xray.endpoint.mapping=off` option for raw endpoints. All exported outbound objects and carrier chains are preserved; only local test inbounds and routing are supplied.

Checks include fresh account material, persisted settings, explicit exported protocol/endpoint selection, absence of server-only key material, a second client for every protocol, rejection of wrong credentials, more than 1 MiB of HTTP response content, UDP payload equality, and use of the same exports as native server outbounds. ShadowTLS receives the same explicit outer/inner account supplement as the frontend. OpenVPN uses the issuance helper and normal panel account metadata.

A portable backup is restored into a fresh isolated panel. Both clients per protocol are exported and exercised again. Finally, a third OpenVPN client is issued using the restored CA signing material and must carry actual HTTP and UDP traffic. Results include binary hashes, individual check outcomes, namespace scope, and compatibility environment settings.

This is controlled integration testing, not an assertion about arbitrary Internet reachability. Direct DNSTT testing does not prove recursive DNS delegation. The ShadowTLS cover is local. Public DNS, remote certificate issuance, censorship conditions, production concurrency and long-running outages need separate deployment tests. Earlier failing runs remain evidence; only a completed run with no failed checks is a passing gate.
