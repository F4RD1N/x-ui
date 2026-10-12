package xray

import (
	"regexp"
	"runtime"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/logger"
)

// NewLogWriter returns a new LogWriter for processing Xray log output.
func NewLogWriter() *LogWriter {
	return &LogWriter{}
}

// LogWriter processes and filters log output from the Xray process, handling crash detection and message filtering.
type LogWriter struct {
	lastLine string
	prefix   string // instance name shown in the panel log
}

func (lw *LogWriter) tag() string {
	if lw.prefix == "" {
		return "XRAY: "
	}
	return "XRAY[" + lw.prefix + "]: "
}

// Write processes and filters log output from the Xray process, handling crash detection and message filtering.
func (lw *LogWriter) Write(m []byte) (n int, err error) {
	crashRegex := regexp.MustCompile(`(?i)(panic|exception|stack trace|fatal error)`)

	// Convert the data to a string
	message := strings.TrimSpace(string(m))
	msgLowerAll := strings.ToLower(message)

	// Suppress noisy Windows process-kill signal that surfaces as exit status 1
	if runtime.GOOS == "windows" && strings.Contains(msgLowerAll, "exit status 1") {
		return len(m), nil
	}

	// Check if the message contains a crash
	if crashRegex.MatchString(message) {
		logger.Debug("Core crash detected:\n", message)
		lw.lastLine = message
		err1 := writeCrashReport(m)
		if err1 != nil {
			logger.Error("Unable to write crash report:", err1)
		}
		return len(m), nil
	}

	regex := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{6}) \[([^\]]+)\] (.+)$`)
	messages := strings.SplitSeq(message, "\n")

	for msg := range messages {
		matches := regex.FindStringSubmatch(msg)

		if len(matches) > 3 {
			level := matches[2]
			msgBody := matches[3]
			msgBodyLower := strings.ToLower(msgBody)

			if strings.Contains(msgBodyLower, "tls handshake error") ||
				strings.Contains(msgBodyLower, "connection ends") {
				logger.Debug(lw.tag() + msgBody)
				lw.lastLine = ""
				continue
			}

			if strings.Contains(msgBodyLower, "failed") {
				logger.Error(lw.tag() + msgBody)
			} else {
				switch level {
				case "Debug":
					logger.Debug(lw.tag() + msgBody)
				case "Info":
					logger.Info(lw.tag() + msgBody)
				case "Warning":
					logger.Warning(lw.tag() + msgBody)
				case "Error":
					logger.Error(lw.tag() + msgBody)
				default:
					logger.Debug(lw.tag() + msg)
				}
			}
			lw.lastLine = ""
		} else if msg != "" {
			msgLower := strings.ToLower(msg)

			if strings.Contains(msgLower, "tls handshake error") ||
				strings.Contains(msgLower, "connection ends") {
				logger.Debug(lw.tag() + msg)
				lw.lastLine = msg
				continue
			}

			if strings.Contains(msgLower, "failed") {
				logger.Error(lw.tag() + msg)
			} else {
				logger.Debug(lw.tag() + msg)
			}
			lw.lastLine = msg
		}
	}

	return len(m), nil
}
