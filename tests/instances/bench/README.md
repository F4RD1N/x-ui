# One xray core vs several, under many TCP connections

`xload` (in `../xload`) is a load generator for VLESS over TCP (with the TCP
HTTP header): `xload echo` is the echo server the connections end at, and
`xload client` opens N connections through the inbounds, then sends a 64-byte
message per connection at each phase's interval and times the echo.

`bench.py` drives it on a server running this panel:

    go build -o bench/xload ./tests/instances/xload     # copy bench/ to the server
    python3 bench.py setup              # deletes every inbound; creates the bench inbound
                                        # (31000, 1000 clients, 16 fixed cores) and
                                        # 8 Multi Instance copies (31001-31008, 2 cores each)
    python3 bench.py run single 500000 --profile
    python3 bench.py run multi 500000 --profile
    python3 bench.py report

`bench.env` next to the script holds `XUI_USERNAME`/`XUI_PASSWORD` for the
panel (`BENCH_PANEL` sets its URL). Both modes run on the same CPUs; the load
generator and the echo server are pinned to others (`BENCH_CLIENT_CPUS`,
`BENCH_ECHO_CPUS`). Each run records, per phase, the messages answered, the
round-trip percentiles, the cores' CPU (from /proc), the busy share of their
CPUs, memory, GC runs and pauses (from the cores' metrics), and optionally a
CPU profile of one core.
