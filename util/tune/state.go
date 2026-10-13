//go:build linux

package tune

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/hw"
	"golang.org/x/sys/unix"
)

// KeyState is what x-ui did to one live value.
type KeyState struct {
	Orig    string `json:"orig,omitempty"`    // live value before x-ui first changed it
	Written string `json:"written,omitempty"` // value x-ui last wrote live
	File    string `json:"file,omitempty"`    // value x-ui persisted in its sysctl file
}

// Moved is a file x-ui moved aside, to be put back by revert.
type Moved struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// State is everything revert needs, kept in /var/lib/x-ui/tune/state.json.
type State struct {
	Version  int                  `json:"version"`
	XUI      string               `json:"xui_version,omitempty"`
	Time     string               `json:"time,omitempty"`
	Disabled bool                 `json:"disabled,omitempty"`
	Keys     map[string]*KeyState `json:"keys,omitempty"`
	Hashsize *KeyState            `json:"ct_hashsize,omitempty"`
	Moved    []Moved              `json:"moved,omitempty"`
	// Enabled are units x-ui enabled; Installed are packages it installed.
	Enabled   []string `json:"enabled,omitempty"`
	Installed []string `json:"installed,omitempty"`
	NTP       bool     `json:"ntp_via_timedatectl,omitempty"`
	Swap      string   `json:"swap,omitempty"` // "unit:<name>" or "fstab" when x-ui created the swapfile
	SwapGone  bool     `json:"swap_removed_by_admin,omitempty"`
	// NICs are the uplink NICs an apply found, by PCI address (name when
	// not PCI): what x-ui did to each.
	NICs map[string]*NICState `json:"nics,omitempty"`
	// IRQBalancePolicy: x-ui gave irqbalance its policy script.
	IRQBalancePolicy bool `json:"irqbalance_policy,omitempty"`
}

// NICState is what x-ui did to one NIC.
type NICState struct {
	Name     string               `json:"name"`
	Driver   string               `json:"driver"` // a different driver at the same address is a new NIC
	Channels *ChanState           `json:"channels,omitempty"`
	Hash     map[string]*KeyState `json:"hash,omitempty"` // "udp4", "udp6": letters ("sd")
	IRQ      map[string]*IRQState `json:"irq,omitempty"`  // "q3" (txrx), "q3rx", "q3tx": CPU lists
	XPS      map[string]*KeyState `json:"xps,omitempty"`  // "tx-3": CPU lists
	RPS      map[string]*KeyState `json:"rps,omitempty"`  // "rx-0/rps_cpus" (CPU list), "rx-0/rps_flow_cnt"
	Managed  bool                 `json:"kernel_managed_irqs,omitempty"`
	TakeIRQs bool                 `json:"take_irqs,omitempty"`
}

// ChanState is x-ui's raise of a NIC's queue count.
type ChanState struct {
	Orig    *hw.Channels `json:"orig,omitempty"`    // the counts before x-ui first raised them
	Want    uint32       `json:"want,omitempty"`    // the count x-ui raises to at boot
	RSSCap  int          `json:"rss_cap,omitempty"` // queues RSS can use, learned from a raise
	Failed  string       `json:"failed,omitempty"`  // why a raise failed: not retried automatically
	Attempt *ChanAttempt `json:"attempt,omitempty"` // a raise in progress (fsynced before it starts)
}

// ChanAttempt is a queue change under way.
type ChanAttempt struct {
	At   string `json:"at"`
	From uint32 `json:"from"`
	To   uint32 `json:"to"`
}

// IRQState is what x-ui did to one queue interrupt's CPUs.
type IRQState struct {
	IRQ     int    `json:"irq"`
	Orig    string `json:"orig,omitempty"`
	Written string `json:"written,omitempty"`
}

func newState() *State { return &State{Version: 1, Keys: map[string]*KeyState{}} }

func (e *Env) loadState() (*State, bool, error) {
	data, err := e.read(StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), false, nil
	}
	if err != nil {
		return newState(), false, err
	}
	s := newState()
	if err := json.Unmarshal([]byte(data), s); err != nil {
		return newState(), false, fmt.Errorf("%s: %w", StateFile, err)
	}
	if s.Keys == nil {
		s.Keys = map[string]*KeyState{}
	}
	return s, true, nil
}

// saveState writes the state when anything but its time changed.
func (e *Env) saveState(s *State, old []byte) error {
	t := s.Time
	s.Time = ""
	cur, _ := json.MarshalIndent(s, "", "  ")
	s.Time = t
	if old != nil && bytes.Equal(cur, old) {
		return nil
	}
	s.Time = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.MarshalIndent(s, "", "  ")
	_, err := e.writeFile(StateFile, append(data, '\n'), 0o600)
	return err
}

// stateSnapshot is the state without its time, to tell whether it changed.
func stateSnapshot(s *State) []byte {
	c := *s
	c.Time = ""
	b, _ := json.MarshalIndent(&c, "", "  ")
	return b
}

// lock serialises the installer, the unit's ExecStartPre and the CLI.
func (e *Env) lock(wait time.Duration) (func(), error) {
	p := e.P(StateDir + "/.lock")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("another x-ui tune is running (lock %s)", StateDir+"/.lock")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
