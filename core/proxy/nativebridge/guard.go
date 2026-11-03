package nativebridge

import "errors"

// Recover contains a recoverable failure in a new protocol's request handler.
// Panic values are omitted because they might hold credentials. Existing
// protocols and their workers are never wrapped or otherwise changed.
func Recover(err *error, cleanup func()) {
	if recover() != nil {
		*err = errors.New("native outbound internal failure")
		containCleanup(cleanup)
	}
}

func RecoverWorker(cleanup func(error)) {
	if recover() != nil {
		containCleanup(func() { cleanup(errors.New("native protocol worker internal failure")) })
	}
}

func containCleanup(cleanup func()) {
	defer func() { _ = recover() }()
	if cleanup != nil {
		cleanup()
	}
}
