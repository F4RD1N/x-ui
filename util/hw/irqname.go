package hw

import (
	"regexp"
	"strconv"
	"strings"
)

// queueIRQNames are the interrupt names drivers give their queue vectors.
// The first group is the kind when there are two groups, the last is the
// queue number.
var queueIRQNames = []struct {
	re   *regexp.Regexp
	kind string // "" when the first group names it
}{
	{regexp.MustCompile(`-TxRx-(\d+)$`), "txrx"},                  // ixgbe, igb, igc, i40e, ice, bnxt_en
	{regexp.MustCompile(`-Tx-Rx-(\d+)$`), "txrx"},                 // ena
	{regexp.MustCompile(`-rxtx-(\d+)$`), "txrx"},                  // vmxnet3
	{regexp.MustCompile(`-fp-(\d+)$`), "txrx"},                    // qede
	{regexp.MustCompile(`-(rx|tx)-(\d+)$`), ""},                   // separate vectors (igb, enic, ...)
	{regexp.MustCompile(`^mlx5_comp(\d+)$`), "txrx"},              // mlx5_core
	{regexp.MustCompile(`^virtio\d+-(input|output)\.(\d+)$`), ""}, // virtio_net
}

var sharedIRQName = regexp.MustCompile(`^virtio\d+-virtqueues$`)

// sidebandIRQName is the queue vector of a driver's own side VSI on the
// same PCI function, which carries no traffic of the device: i40e's flow
// director ("i40e-0000:01:00.0:fdir-TxRx-0"), ice's control VSI
// ("ice-0000:01:00.0:ctrl-TxRx-0").
var sidebandIRQName = regexp.MustCompile(`:(fdir|ctrl)-TxRx-\d+$`)

// ParseQueueIRQName reads a queue interrupt's name: its queue and whether it
// serves receive ("rx"), transmit ("tx") or both ("txrx"). Anything else (a
// link or misc vector, mlx5_async, virtio's config vector, a side VSI's
// vector) is not a queue interrupt.
func ParseQueueIRQName(name string) (queue int, kind string, ok bool) {
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	if sidebandIRQName.MatchString(name) {
		return 0, "", false
	}
	for _, p := range queueIRQNames {
		m := p.re.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		q, err := strconv.Atoi(m[len(m)-1])
		if err != nil {
			return 0, "", false
		}
		kind = p.kind
		if kind == "" {
			switch m[1] {
			case "rx", "input":
				kind = "rx"
			default:
				kind = "tx"
			}
		}
		return q, kind, true
	}
	return 0, "", false
}

// isSharedIRQName says whether one vector serves all of a device's queues.
func isSharedIRQName(name string) bool {
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	return sharedIRQName.MatchString(name)
}
