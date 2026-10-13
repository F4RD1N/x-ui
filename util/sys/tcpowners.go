package sys

// PortOwner is an inbound listening on a port: the connections to it are
// counted for Name. IP "" (or "0.0.0.0", "::") listens on all addresses.
type PortOwner struct {
	Port int
	IP   string
	Name string
}

// AttributeTCP sums connection counts per owner. A connection to an address
// an owner listens on goes to that owner; the rest on the port go to the
// owner listening on all addresses (the last one listed, when several do).
func AttributeTCP(eps map[LocalEndpoint]int, owners []PortOwner) map[string]int {
	byPort := map[int][]PortOwner{}
	for _, o := range owners {
		if o.IP == "0.0.0.0" || o.IP == "::" || o.IP == "::0" {
			o.IP = ""
		}
		byPort[o.Port] = append(byPort[o.Port], o)
	}
	counts := map[string]int{}
	for ep, n := range eps {
		var wildcard string
		matched := false
		for _, o := range byPort[ep.Port] {
			if o.IP == "" {
				wildcard = o.Name
			} else if o.IP == ep.IP {
				counts[o.Name] += n
				matched = true
				break
			}
		}
		if !matched && wildcard != "" {
			counts[wildcard] += n
		}
	}
	return counts
}
