// Package guard contains a failure inside one orbit worker goroutine. It is
// the only change the outbound makes to the copied VPN-Core goroutines: a
// panic closes the session that worker belongs to instead of the process.
// The panic value is not logged, since it might hold credentials.
package guard

import "errors"

// ErrInternal is the error a session ends with after a contained panic.
var ErrInternal = errors.New("orbit: internal failure in a session worker")

// Go runs fn in a new goroutine. If fn panics, the panic stops there and
// onPanic runs (itself guarded).
func Go(fn func(), onPanic func()) {
	go func() {
		defer func() {
			if recover() != nil && onPanic != nil {
				defer func() { _ = recover() }()
				onPanic()
			}
		}()
		fn()
	}()
}
