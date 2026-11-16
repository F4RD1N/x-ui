//go:build !noclientsample

package clientsample

// enabled is false only in builds tagged noclientsample, which exist to
// measure what recording costs.
const enabled = true
