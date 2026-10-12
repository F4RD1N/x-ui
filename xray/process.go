package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
)

// GetBinaryName returns the Xray binary filename for the current OS and architecture.
func GetBinaryName() string {
	return fmt.Sprintf("xray-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// sequentialCPUs is the CPU list when the affinity mask cannot be read.
func sequentialCPUs() []int {
	cpus := make([]int, runtime.NumCPU())
	for i := range cpus {
		cpus[i] = i
	}
	return cpus
}

// GetBinaryPath returns the full path to the Xray binary executable.
func GetBinaryPath() string {
	return config.GetBinFolderPath() + "/" + GetBinaryName()
}

// GetConfigPath returns the path to the Xray configuration file in the binary folder.
func GetConfigPath() string {
	return config.GetBinFolderPath() + "/config.json"
}

// GetGeositePath returns the path to the geosite data file used by Xray.
func GetGeositePath() string {
	return config.GetBinFolderPath() + "/geosite.dat"
}

// GetGeoipPath returns the path to the geoip data file used by Xray.
func GetGeoipPath() string {
	return config.GetBinFolderPath() + "/geoip.dat"
}

// GetIPLimitLogPath returns the path to the IP limit log file.
func GetIPLimitLogPath() string {
	return config.GetLogFolder() + "/3xipl.log"
}

// GetIPLimitBannedLogPath returns the path to the banned IP log file.
func GetIPLimitBannedLogPath() string {
	return config.GetLogFolder() + "/3xipl-banned.log"
}

// GetIPLimitBannedPrevLogPath returns the path to the previous banned IP log file.
func GetIPLimitBannedPrevLogPath() string {
	return config.GetLogFolder() + "/3xipl-banned.prev.log"
}

// GetAccessPersistentLogPath returns the path to the persistent access log file.
func GetAccessPersistentLogPath() string {
	return config.GetLogFolder() + "/3xipl-ap.log"
}

// GetAccessPersistentPrevLogPath returns the path to the previous persistent access log file.
func GetAccessPersistentPrevLogPath() string {
	return config.GetLogFolder() + "/3xipl-ap.prev.log"
}

// GetAccessLogPath reads the Xray config and returns the access log file path.
func GetAccessLogPath() (string, error) {
	config, err := os.ReadFile(GetConfigPath())
	if err != nil {
		logger.Warningf("Failed to read configuration file: %s", err)
		return "", err
	}

	jsonConfig := map[string]any{}
	err = json.Unmarshal([]byte(config), &jsonConfig)
	if err != nil {
		logger.Warningf("Failed to parse JSON configuration: %s", err)
		return "", err
	}

	if jsonConfig["log"] != nil {
		jsonLog := jsonConfig["log"].(map[string]any)
		if jsonLog["access"] != nil {
			accessLogPath := jsonLog["access"].(string)
			return accessLogPath, nil
		}
	}
	return "", err
}

// stopProcess calls Stop on the given Process instance.
func stopProcess(p *Process) {
	p.Stop()
}

// Process wraps an Xray process instance and provides management methods.
type Process struct {
	*process
}

// NewProcess creates a new Xray process and sets up cleanup on garbage collection.
func NewProcess(xrayConfig *Config) *Process {
	p := &Process{newProcess(xrayConfig)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

// NewInstanceProcess creates the process of one named core instance. It
// writes its config to configPath and, when cpus is not empty, runs only on
// those CPUs.
func NewInstanceProcess(name string, xrayConfig *Config, configPath string, cpus []int) *Process {
	p := &Process{newProcess(xrayConfig)}
	p.name = name
	p.configPath = configPath
	p.cpus = append([]int(nil), cpus...)
	p.logWriter.prefix = name
	runtime.SetFinalizer(p, stopProcess)
	return p
}

// NewTestProcess creates a new Xray process that uses a specific config file path.
// Used for test runs (e.g. outbound test) so the main config.json is not overwritten.
// The config file at configPath is removed when the process is stopped.
func NewTestProcess(xrayConfig *Config, configPath string) *Process {
	p := &Process{newTestProcess(xrayConfig, configPath)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

type process struct {
	cmd *exec.Cmd

	// done is closed once the child has been reaped, so a caller can wait for
	// the ports it was listening on to be free again. Restarting Xray used to
	// signal the old core and start the new one immediately, which raced the
	// old core's shutdown and failed with "address already in use".
	done chan struct{}

	version string
	apiPort int

	onlineClients []string

	config       *Config
	configPath   string // if set, use this path instead of GetConfigPath()
	removeConfig bool   // remove configPath on Stop (test runs)
	logWriter    *LogWriter
	exitErr      error
	startTime    time.Time

	name  string // instance name; "" for test runs
	cpuMu sync.Mutex
	cpus  []int // CPUs the core is pinned to; empty = not pinned

	memLimit int64     // GOMEMLIMIT for the core in bytes; 0 = inherit the panel's
	exitTime time.Time // when the core exited
	stopped  bool      // Stop was called: the exit was asked for, not a crash
}

// newProcess creates a new internal process struct for Xray.
func newProcess(config *Config) *process {
	return &process{
		version:   "Unknown",
		config:    config,
		logWriter: NewLogWriter(),
		startTime: time.Now(),
		done:      make(chan struct{}),
	}
}

// newTestProcess creates a process that writes and runs with a specific config path.
func newTestProcess(config *Config, configPath string) *process {
	p := newProcess(config)
	p.configPath = configPath
	p.removeConfig = true
	return p
}

// IsRunning returns true if the Xray process is currently running.
func (p *process) IsRunning() bool {
	if p.cmd == nil || p.cmd.Process == nil {
		return false
	}
	// Read the exit through the channel rather than cmd.ProcessState, which is
	// written by the goroutine running cmd.Run() and read here from whichever
	// goroutine asks -- an unsynchronised read that also lagged behind the
	// child's real state, so a just-stopped core still looked like it was up.
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// GetErr returns the error the core exited with, or the error that kept
// it from starting.
func (p *process) GetErr() error {
	if p.cmd != nil && p.cmd.Process != nil {
		select {
		case <-p.done:
		default:
			return nil // still running
		}
	}
	return p.exitErr
}

// GetResult returns the last log line or error from the Xray process.
func (p *process) GetResult() string {
	if len(p.logWriter.lastLine) == 0 && p.exitErr != nil {
		return p.exitErr.Error()
	}
	return p.logWriter.lastLine
}

// GetVersion returns the version string of the Xray process.
func (p *process) GetVersion() string {
	return p.version
}

// GetAPIPort returns the API port used by the Xray process.
func (p *Process) GetAPIPort() int {
	return p.apiPort
}

// GetConfig returns the configuration used by the Xray process.
func (p *Process) GetConfig() *Config {
	return p.config
}

// SetConfig records the configuration the running core now has, after
// changes applied to it through the API.
func (p *process) SetConfig(c *Config) {
	p.config = c
}

// SetMemoryLimit gives the core its own GOMEMLIMIT, in bytes, instead of
// the panel's. It takes effect at Start.
func (p *process) SetMemoryLimit(bytes int64) {
	p.memLimit = bytes
}

// StartTime returns when the core was started.
func (p *process) StartTime() time.Time {
	return p.startTime
}

// Crashed reports whether the core exited without being asked to.
func (p *process) Crashed() bool {
	select {
	case <-p.done:
		return !p.stopped
	default:
		return false
	}
}

// ExitTime returns when the core exited, or the zero time while it runs.
func (p *process) ExitTime() time.Time {
	select {
	case <-p.done:
		return p.exitTime
	default:
		return time.Time{}
	}
}

// Name returns the instance name.
func (p *process) Name() string {
	return p.name
}

// Pid returns the core's process id, or 0 when it never started.
func (p *process) Pid() int {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// CPUs returns the CPUs the core is pinned to (empty when not pinned).
func (p *process) CPUs() []int {
	p.cpuMu.Lock()
	defer p.cpuMu.Unlock()
	return append([]int(nil), p.cpus...)
}

// SetCPUs moves the running core onto cpus. The core keeps running and keeps
// its connections; its Go runtime notices the new mask within about a second
// and resizes GOMAXPROCS to match.
func (p *process) SetCPUs(cpus []int) error {
	p.cpuMu.Lock()
	defer p.cpuMu.Unlock()
	if !p.IsRunning() {
		p.cpus = append([]int(nil), cpus...)
		return nil
	}
	if err := pinProcess(p.Pid(), cpus); err != nil {
		return err
	}
	p.cpus = append([]int(nil), cpus...)
	return nil
}

// GetOnlineClients returns the list of online clients for the Xray process.
func (p *Process) GetOnlineClients() []string {
	return p.onlineClients
}

// SetOnlineClients sets the list of online clients for the Xray process.
func (p *Process) SetOnlineClients(users []string) {
	p.onlineClients = users
}

// GetUptime returns the uptime of the Xray process in seconds.
func (p *Process) GetUptime() uint64 {
	return uint64(time.Since(p.startTime).Seconds())
}

// refreshAPIPort updates the API port from the inbound configs.
func (p *process) refreshAPIPort() {
	for _, inbound := range p.config.InboundConfigs {
		if inbound.Tag == "api" {
			p.apiPort = inbound.Port
			break
		}
	}
}

// refreshVersion updates the version string by running the Xray binary with -version.
func (p *process) refreshVersion() {
	cmd := exec.Command(GetBinaryPath(), "-version")
	data, err := cmd.Output()
	if err != nil {
		p.version = "Unknown"
	} else {
		datas := bytes.Split(data, []byte(" "))
		if len(datas) <= 1 {
			p.version = "Unknown"
		} else {
			p.version = string(datas[1])
		}
	}
}

// Start launches the Xray process with the current configuration.
func (p *process) Start() (err error) {
	if p.IsRunning() {
		return errors.New("xray is already running")
	}

	defer func() {
		if err != nil {
			logger.Error("Failure in running xray-core process: ", err)
			select {
			case <-p.done: // the start goroutine recorded it
			default:
				p.exitErr = err
			}
		}
	}()

	data, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return common.NewErrorf("Failed to generate XRAY configuration files: %v", err)
	}

	err = os.MkdirAll(config.GetLogFolder(), 0o770)
	if err != nil {
		logger.Warningf("Failed to create log folder: %s", err)
	}

	configPath := GetConfigPath()
	if p.configPath != "" {
		configPath = p.configPath
	}
	err = os.WriteFile(configPath, data, fs.ModePerm)
	if err != nil {
		return common.NewErrorf("Failed to write configuration file: %v", err)
	}

	cmd := exec.Command(GetBinaryPath(), "-c", configPath)
	p.cmd = cmd
	if p.memLimit > 0 {
		env := make([]string, 0, len(os.Environ())+1)
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "GOMEMLIMIT=") {
				env = append(env, kv)
			}
		}
		cmd.Env = append(env, fmt.Sprintf("GOMEMLIMIT=%d", p.memLimit))
	}
	p.startTime = time.Now()

	cmd.Stdout = p.logWriter
	cmd.Stderr = p.logWriter

	// Give the core its own process group and have the kernel kill it if this
	// panel dies, so a panel that is SIGKILLed or OOM-killed cannot leave an
	// orphaned core holding the inbound ports.
	setSysProcAttr(cmd)

	cpus := p.CPUs()
	started := make(chan error, 1)
	go func() {
		if len(cpus) > 0 {
			// Fork from a thread pinned to the core's CPUs so the core
			// inherits the mask. The thread stays locked, and alive, until
			// the core exits: the core's Pdeathsig is tied to the thread
			// that forked it, and a locked goroutine that returns takes its
			// thread down with it -- which must only happen after the core
			// is gone.
			runtime.LockOSThread()
			if err := pinCurrentThread(cpus); err != nil {
				logger.Warning("Could not pin xray-core to its CPUs:", err)
			}
		}
		if err := cmd.Start(); err != nil {
			p.exitErr = err
			p.exitTime = time.Now()
			started <- err
			close(p.done)
			return
		}
		started <- nil
		err := cmd.Wait()
		// Everything about the exit is recorded before done is closed:
		// readers check done first, so these writes are then visible.
		if err != nil {
			// On Windows, killing the process results in "exit status 1" which isn't an error for us
			quiet := runtime.GOOS == "windows" && strings.Contains(strings.ToLower(err.Error()), "exit status 1")
			if !quiet {
				logger.Error("Failure in running xray-core:", err)
			}
			p.exitErr = err
		}
		p.exitTime = time.Now()
		close(p.done)
	}()
	if err := <-started; err != nil {
		return common.NewErrorf("Failed to start xray-core: %v", err)
	}

	p.refreshVersion()
	p.refreshAPIPort()

	return nil
}

// Stop terminates the running Xray process.
func (p *process) Stop() error {
	if !p.IsRunning() {
		return errors.New("xray is not running")
	}
	p.stopped = true

	// Remove temporary config file used for test runs so main config is never touched
	if p.configPath != "" && p.removeConfig {
		if p.configPath != GetConfigPath() {
			// Check if file exists before removing
			if _, err := os.Stat(p.configPath); err == nil {
				_ = os.Remove(p.configPath)
			}
		}
	}

	if runtime.GOOS == "windows" {
		if err := p.cmd.Process.Kill(); err != nil {
			return err
		}
	} else if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}

	// Block until the core is gone. Returning here while it is still shutting
	// down is what let a restart bind ports the previous core still held.
	return p.Wait(stopTimeout)
}

// stopTimeout is how long a core gets to shut down on SIGTERM before it is
// killed outright. Xray closes its listeners promptly; this is only a bound on
// a core wedged in a syscall.
const stopTimeout = 10 * time.Second

// Wait blocks until the core has exited and been reaped, or until timeout, in
// which case it is SIGKILLed and waited for unconditionally. Once Wait returns
// nil every socket the core held is closed.
func (p *process) Wait(timeout time.Duration) error {
	select {
	case <-p.done:
		return nil
	case <-time.After(timeout):
	}

	logger.Warning("xray-core did not exit within ", timeout, ", killing it")
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}

	select {
	case <-p.done:
		return nil
	case <-time.After(stopTimeout):
		return errors.New("xray-core did not exit after being killed")
	}
}

// writeCrashReport writes a crash report to the binary folder with a timestamped filename.
func writeCrashReport(m []byte) error {
	crashReportPath := config.GetBinFolderPath() + "/core_crash_" + time.Now().Format("20060102_150405") + ".log"
	return os.WriteFile(crashReportPath, m, os.ModePerm)
}
