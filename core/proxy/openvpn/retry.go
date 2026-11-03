package openvpn

import (
	goerrors "errors"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/client"
)

// The back-off between session setups follows OpenVPN 2.6's own client with
// its defaults (auth-retry none, connect-retry 1 300), except that the wait
// stops growing at 30s, not 300s: here the attempts are made by requests, so
// a long wait would keep a phone whose network has come back offline for
// minutes.
//
//   - After AUTH_FAILED or HALT there is no new attempt: the server rejected
//     these credentials (or this client), and asking again with the same
//     ones only gets the account locked or the address banned. A reloaded
//     configuration is a new Handler and starts over.
//   - Except an AUTH_FAILED that ends a session which was up and logging in
//     with a pushed auth-token (client.ErrAuthTokenRejected): the server
//     refused the token, not the credentials, so, as OpenVPN 2.x does, the
//     next request sets up a new session, which logs in with the username
//     and password. If the server refuses those too, that setup's
//     AUTH_FAILED stops the outbound as above, so each refused token costs
//     at most one more login.
//   - After AUTH_FAILED,TEMP the wait is at least what the server asked for
//     ("backoff N").
//   - After any other failure the wait is retryFirst after each of the first
//     retryQuick failures in a row, then twice as long after each one, up to
//     retryMax.
//
// Requests that come during the wait fail at once with the last error. A
// setup that works resets the count; a session that ends after it was up is
// set up again by the next request without waiting, unless the server ended
// it with HALT or with an AUTH_FAILED that was not about an auth-token.
const (
	retryFirst = time.Second
	retryQuick = 5
	retryMax   = 30 * time.Second
	// maxServerBackoff bounds the wait an AUTH_FAILED,TEMP asks for.
	maxServerBackoff = time.Hour
)

// retryDelay is the wait after the n-th failed setup in a row (n >= 1).
func retryDelay(n int) time.Duration {
	if n <= retryQuick {
		return retryFirst
	}
	shift := n - retryQuick
	if shift >= 16 {
		return retryMax
	}
	return min(retryFirst<<shift, retryMax)
}

// rejected reports whether err means that the server rejected this
// configuration for good: AUTH_FAILED (other than a temporary one, or one
// that refused a pushed auth-token) or HALT.
func rejected(err error) bool {
	if goerrors.Is(err, client.ErrServerHalt) {
		return true
	}
	if goerrors.Is(err, client.ErrAuthTokenRejected) {
		return false
	}
	if goerrors.Is(err, client.ErrAuthFailed) {
		temp, _ := tempAuthFailure(err)
		return !temp
	}
	return false
}

// tempAuthFailure reports whether err is a temporary AUTH_FAILED (OpenVPN
// 2.6's "AUTH_FAILED,TEMP[flags]:reason", whose reason the client error
// carries after ErrAuthFailed's text) and the wait its "backoff N" flag asks
// for (0 when none).
func tempAuthFailure(err error) (bool, time.Duration) {
	if !goerrors.Is(err, client.ErrAuthFailed) {
		return false, 0
	}
	marker := client.ErrAuthFailed.Error() + ": TEMP"
	msg := err.Error()
	i := strings.Index(msg, marker)
	if i < 0 {
		return false, 0
	}
	rest := msg[i+len(marker):]
	if rest != "" && rest[0] != '[' && rest[0] != ':' && rest[0] != ' ' {
		return false, 0 // a reason that merely starts with "TEMP"
	}
	var backoff time.Duration
	if flags, ok := strings.CutPrefix(rest, "["); ok {
		if flags, _, ok = strings.Cut(flags, "]"); ok {
			for _, f := range strings.Split(flags, ",") {
				v, ok := strings.CutPrefix(strings.TrimSpace(f), "backoff ")
				if !ok {
					continue
				}
				if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32); err == nil && n > 0 {
					backoff = min(time.Duration(n)*time.Second, maxServerBackoff)
				}
			}
		}
	}
	return true, backoff
}

// setupWorked resets the back-off. h.mu is held.
func (h *Handler) setupWorked() {
	h.failures, h.lastErr, h.retryAt = 0, nil, time.Time{}
}

// setupFailed records a failed setup and returns the line to log about it.
// h.mu is held.
func (h *Handler) setupFailed(err error) string {
	h.failures++
	h.lastErr = err
	if rejected(err) {
		h.stopped = true
		return "the OpenVPN server rejected this configuration; not connecting again until it is reloaded"
	}
	d := retryDelay(h.failures)
	if _, b := tempAuthFailure(err); b > d {
		d = b
	}
	h.retryAt = h.now().Add(d)
	return "setting up the OpenVPN session failed; next attempt in " + d.String()
}

// sessionEnded looks at why the session of t, the current tunnel, which is
// dead, ended. When the server ended it with HALT or AUTH_FAILED (on a
// renegotiation that sent the password: one that sent an auth-token is not
// rejected, see above) it stops the outbound as a rejected setup does and
// reports true, once. h.mu is held.
func (h *Handler) sessionEnded(t *tunnel) bool {
	if h.stopped {
		return false
	}
	err := t.sess.Err()
	if err == nil || !rejected(err) {
		return false
	}
	h.stopped = true
	h.lastErr = errors.New("the OpenVPN server ended the session").Base(err)
	return true
}

// holdOff returns why no setup may start now, or nil. h.mu is held.
func (h *Handler) holdOff() error {
	if h.stopped {
		return errors.New("not connecting to the OpenVPN server again: it rejected this configuration (reload it to try again)").Base(h.lastErr)
	}
	if h.lastErr == nil {
		return nil
	}
	if wait := h.retryAt.Sub(h.now()); wait > 0 {
		wait = (wait + time.Second - 1).Truncate(time.Second)
		return errors.New("not connecting to the OpenVPN server yet after a failed attempt: next attempt in ", wait).Base(h.lastErr)
	}
	return nil
}
