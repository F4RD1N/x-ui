#!/usr/bin/env python3
"""Check exported ShadowTLS ClientHellos with OpenSSL, without any sockets.

Generate fixtures with the isolated Go test:
  SHADOWTLS_RANDOMIZED_FIXTURE=/tmp/hellos.json go test ./proxy/shadowtls \
    -run '^TestShadowTLSRandomizedOpenSSLFixture$' -count=1
Use a disposable certificate/key for --cert and --key. The test only reads them
into OpenSSL memory; it starts no listeners and prints no private key material.
"""

import argparse
import base64
import json
from pathlib import Path
import ssl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clienthellos", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = json.loads(args.clienthellos.read_text())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.cert, args.key)
    result = []
    for row in rows:
        inbound, outbound = ssl.MemoryBIO(), ssl.MemoryBIO()
        connection = context.wrap_bio(inbound, outbound, server_side=True)
        inbound.write(base64.b64decode(row["record"], validate=True))
        observed = {"fingerprint": row["fingerprint"], "seed": row["seed"]}
        try:
            connection.do_handshake()
            observed.update(accepted=True, detail="handshake-complete")
        except ssl.SSLWantReadError:
            # OpenSSL accepted ClientHello and emitted its server flight. A
            # complete traffic handshake is verified separately by Go tests.
            observed.update(accepted=outbound.pending > 0, detail="clienthello-accepted")
        except ssl.SSLError as error:
            observed.update(accepted=False, detail=str(error))
        result.append(observed)
    args.output.write_text(json.dumps({"openssl": ssl.OPENSSL_VERSION, "results": result}, indent=2) + "\n")
    accepted = sum(row["accepted"] for row in result)
    print(f"OpenSSL accepted {accepted}/{len(result)} ClientHellos; no network sockets used.")
    if len(result) != 128 or accepted != len(result):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
