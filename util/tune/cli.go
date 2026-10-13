//go:build linux

package tune

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const usage = `Usage: x-ui tune [status|apply|revert|queues] [options]

Tunes this server for x-ui: kernel limits (sysctl), the x-ui service's
open-file limit and Go memory settings, BBR, the uplink NICs (interrupt CPUs,
XPS, UDP hashing, RPS, queue count), time sync, and swap on tiny VMs.
It only ever raises a limit that something else set lower, writes only its own
files, and revert undoes exactly what it did.

  status [--json] [--check]   show the settings, the NICs, the service and health
                              counters (--check: exit 2 when something is not applied)
  apply [--dry-run]           apply everything (also turns automatic tuning on)
        [--take-irqs]         also move NIC interrupts someone else placed
  revert [--purge]            undo it and turn automatic tuning off
  queues [--json]             show the NICs' queue counts and the raises planned
  queues --now                raise them now: the link resets for a few seconds, and
                              the old count comes back if the gateway stops answering
  nic [--boot]                run by x-ui itself: place the NICs' interrupts by the
                              xray instances' CPUs (--boot: raise the queues first)

Time sync, irqbalance's policy and swap are set up by a fresh install and by
'apply', never by an update, and never against an admin's choice (any apply
removes the policy where it would hide an admin's IRQBALANCE_ARGS). A NIC's
queue count is only raised, at boot (x-ui-nic.service) or by 'queues --now';
revert leaves it until the next reboot. Sysctl files whose names sort after
51-x-ui.conf win at boot; after changing one, run 'apply'.

Files: /etc/sysctl.d/51-x-ui.conf, /etc/systemd/system/x-ui.service.d/20-x-ui-tuning.conf,
/etc/modules-load.d/x-ui.conf, /etc/modprobe.d/x-ui.conf, /etc/systemd/system/x-ui-nic.service,
/etc/systemd/system/irqbalance.service.d/90-x-ui.conf, /var/lib/x-ui/tune/ (state.json,
irqbalance-policy, irqbalance.env)
`

// Main runs "x-ui tune" and returns the exit code: 0 ok (skipped keys are
// not errors), 1 error, 2 drift (status --check).
func Main(args []string, version string) int {
	return run(args, version, os.Stdout, os.Stderr)
}

func run(args []string, version string, stdout, stderr io.Writer) int {
	cmd := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("x-ui tune "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	asJSON := fs.Bool("json", false, "")
	check := fs.Bool("check", false, "")
	dry := fs.Bool("dry-run", false, "")
	auto := fs.Bool("auto", false, "")
	boot := fs.Bool("boot", false, "")
	host := fs.Bool("host", false, "") // with --auto: a fresh install's host services
	quiet := fs.Bool("quiet", false, "")
	purge := fs.Bool("purge", false, "")
	takeIRQs := fs.Bool("take-irqs", false, "")
	now := fs.Bool("now", false, "")
	worker := fs.Bool("worker", false, "") // queues --now in its transient unit
	instances := fs.String("instances", "", "")
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp || *boot {
			return 0
		}
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "x-ui tune: unexpected argument %q\n", fs.Arg(0))
		if *boot {
			return 0
		}
		return 1
	}

	e, err := NewEnv()
	if err != nil {
		fmt.Fprintln(stderr, "x-ui tune:", err)
		return 1
	}
	e.Out = stdout
	if e.Root == "" && os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "x-ui tune:", errNotRoot)
		if *boot || cmd == "nic" {
			return 0
		}
		return 1
	}

	switch cmd {
	case "status":
		d, err := e.Status(*asJSON)
		if err != nil {
			fmt.Fprintln(stderr, "x-ui tune:", err)
			return 1
		}
		if *check && len(d) > 0 {
			return 2
		}
		return 0

	case "apply":
		o := ApplyOptions{DryRun: *dry, Auto: *auto, Boot: *boot, Quiet: *quiet || *boot, Host: *host, TakeIRQs: *takeIRQs, Instances: *instances}
		if *boot {
			return bootApply(e, o, version, stdout)
		}
		r, err := e.Apply(o, version)
		if err != nil {
			fmt.Fprintln(stderr, "x-ui tune:", err)
			return 1
		}
		if *dry {
			return 0
		}
		report(e, r, o.Quiet, "apply")
		return 0

	case "revert":
		r, err := e.Revert(*purge, *dry)
		if err != nil {
			fmt.Fprintln(stderr, "x-ui tune:", err)
			return 1
		}
		report(e, r, *quiet, "revert")
		if !*dry {
			fmt.Fprintln(stdout, "Automatic tuning is off; 'x-ui tune apply' turns it back on.")
			fmt.Fprintln(stdout, "The running service keeps its limits until the next x-ui restart.")
		}
		return 0

	case "queues":
		if *now && !*worker && !e.fake() && e.detachable() {
			// A transient unit, so a dropped SSH session cannot stop it
			// halfway.
			args := e.detachArgs()
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
			if err := cmd.Run(); err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return ee.ExitCode()
				}
				fmt.Fprintln(stderr, "x-ui tune:", err)
				return 1
			}
			return 0
		}
		if *now {
			signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
		}
		r, err := e.Queues(QueuesOptions{Now: *now, Worker: *worker, JSON: *asJSON})
		if err != nil {
			fmt.Fprintln(stderr, "x-ui tune:", err)
			return 1
		}
		if r != nil {
			report(e, r, false, "queues")
			for _, p := range r.Problems {
				if strings.Contains(p, "failed too") {
					return 1
				}
			}
		}
		return 0

	case "nic":
		if *boot {
			signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
		}
		r, err := e.RunNIC(NICOptions{Boot: *boot, Instances: *instances})
		if err != nil {
			fmt.Fprintln(stderr, "x-ui tune:", err)
			if *boot {
				return 0
			}
			return 1
		}
		for _, c := range r.Changed {
			e.printf("x-ui tune nic: %s\n", c)
		}
		for _, p := range r.Problems {
			e.printf("x-ui tune nic: skipped: %s\n", p)
		}
		if !*quiet && len(r.Changed) == 0 && len(r.Problems) == 0 {
			e.printf("x-ui tune nic: nothing to change.\n")
		}
		return 0
	}
	fmt.Fprint(stderr, usage)
	return 1
}

// bootApply is the unit's ExecStartPre: quick, quiet, and never a reason for
// the service not to start.
func bootApply(e *Env, o ApplyOptions, version string, out io.Writer) int {
	e.Deadline = time.Now().Add(5 * time.Second)
	done := make(chan *Result, 1)
	go func() {
		r, err := e.Apply(o, version)
		if err != nil {
			fmt.Fprintln(out, "x-ui tune:", err)
		}
		done <- r
	}()
	select {
	case r := <-done:
		if r != nil && len(r.Changed) > 0 {
			fmt.Fprintf(out, "x-ui tune: re-applied %d setting(s): %s\n", len(r.Changed), strings.Join(r.Changed, "; "))
		}
	case <-time.After(5 * time.Second):
		fmt.Fprintln(out, "x-ui tune: gave up after 5 s")
	}
	return 0
}

func report(e *Env, r *Result, quiet bool, what string) {
	if r.Disabled {
		e.printf("Tuning is disabled ('x-ui tune apply' turns it back on); nothing was changed.\n")
		return
	}
	if !quiet || len(r.Changed) > 0 {
		if len(r.Changed) == 0 {
			e.printf("x-ui tune %s: nothing to change.\n", what)
		}
		for _, c := range r.Changed {
			e.printf("  %s\n", c)
		}
	}
	if !quiet {
		for _, p := range r.Problems {
			e.printf("  skipped: %s\n", p)
		}
	}
	if r.Restart && what == "apply" {
		e.printf("The service limits take effect at the next x-ui restart.\n")
	}
}
