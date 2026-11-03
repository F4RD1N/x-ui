//go:build race

package client

// raceEnabled: sync.Pool drops items at random under the race detector, so
// allocation counts mean nothing there.
const raceEnabled = true
