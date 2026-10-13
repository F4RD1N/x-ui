//go:build linux

// Package diag is "x-ui diag": a report of what the server is (CPUs, NUMA
// nodes, the NICs under the default routes with their queues, RSS and
// interrupts), how the xray instances sit on it, a short live sample of the
// packet path, and plain warnings. It only reads: /proc, /sys, ethtool
// getters and socket counts. It changes nothing.
package diag

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/util/tune"
)

const usage = `Usage: x-ui diag [--json] [--seconds N] [--summary]

Shows the server as x-ui sees it: CPUs, cores and NUMA nodes; each NIC under
the default routes (driver, NUMA node, queues, RSS table and hashing, which
CPU each queue's interrupt runs on and which xray instance owns that CPU,
irqbalance, XPS, RPS); a short live sample (CPU, softirq and steal per CPU,
traffic, drops); each xray instance (CPUs and NUMA nodes, CPU use, threads,
memory, open files, connections, UDP ports, the NIC interrupts on its CPUs);
TCP and conntrack counters against their limits; and warnings with the fix.
It only reads; it changes nothing.

  --json        print the report as JSON
  --seconds N   length of the live sample, 0-30 (default 3; 0: no sample)
  --summary     the installer's short "Detected:/Configured:" block
`

// Main runs "x-ui diag" and returns the exit code.
func Main(args []string, version string) int {
	e := &env{fs: hw.EnvFS(), eth: hw.NoEthtool{}, summary: tune.Summary, now: time.Now, sleep: time.Sleep, root: os.Geteuid() == 0}
	if e.fs.Root == "" {
		e.eth = hw.SystemEthtool()
		e.tcp = sys.CountEstablishedTCP
		e.udp = sys.UDPSockets
	}
	e.exe, _ = os.Executable()
	return run(e, args, version, os.Stdout, os.Stderr)
}

func run(e *env, args []string, version string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("x-ui diag", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	asJSON := fs.Bool("json", false, "")
	seconds := fs.Int("seconds", 3, "")
	summary := fs.Bool("summary", false, "")
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "x-ui diag: unexpected argument %q\n", fs.Arg(0))
		return 1
	}
	if *seconds < 0 || *seconds > 30 {
		fmt.Fprintln(stderr, "x-ui diag: --seconds takes 0 to 30")
		return 1
	}

	if *summary {
		// Quick and never a failure: no sample, no socket scan.
		c := e.gather(version, false)
		for _, l := range c.summaryLines() {
			fmt.Fprintln(stdout, l)
		}
		return 0
	}
	c := e.gather(version, true)
	if *seconds > 0 {
		c.sample(*seconds)
	}
	c.r.Seconds = *seconds
	c.r.Warnings = append(c.r.Warnings, c.warnings()...)
	if *asJSON {
		if err := c.writeJSON(stdout); err != nil {
			fmt.Fprintln(stderr, "x-ui diag:", err)
			return 1
		}
		return 0
	}
	c.render(stdout)
	return 0
}
