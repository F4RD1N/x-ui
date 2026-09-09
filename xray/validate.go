package xray

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

// TestConfig asks the bundled Xray core whether it would accept this config,
// by running it with -test. This is the only check that means anything: the
// core parses far more than JSON syntax -- protocols, ports, transports,
// certificates -- and anything it rejects here would have stopped it at
// startup instead.
//
// The config is written to a temporary file, never to the live config.json, so
// a candidate can be tested while the core keeps running on the current one.
func TestConfig(configJSON string) error {
	f, err := os.CreateTemp("", "xray-candidate-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(configJSON); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	cmd := exec.Command(GetBinaryPath(), "-test", "-c", f.Name())
	out, err := runWithTimeout(cmd, 30*time.Second)
	if err != nil {
		return &ConfigError{Output: strings.TrimSpace(out), Err: err}
	}
	return nil
}

// ConfigError carries what the core said about a config it refused, so the
// reason reaches the log rather than just "exit status 1".
type ConfigError struct {
	Output string
	Err    error
}

func (e *ConfigError) Error() string {
	if e.Output != "" {
		return "xray rejected the config: " + lastMeaningfulLine(e.Output)
	}
	return "xray rejected the config: " + e.Err.Error()
}

func (e *ConfigError) Unwrap() error { return e.Err }

// lastMeaningfulLine picks the core's actual complaint out of its output; the
// banner it prints first would otherwise be all anyone saw.
func lastMeaningfulLine(out string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" || strings.HasPrefix(l, "Xray ") || strings.HasPrefix(l, "A unified platform") {
			continue
		}
		return l
	}
	return out
}

func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) (string, error) {
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return buf.String(), err
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return buf.String(), os.ErrDeadlineExceeded
	}
}
