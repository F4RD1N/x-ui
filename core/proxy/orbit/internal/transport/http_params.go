package transport

import "github.com/xtls/xray-core/proxy/orbit/internal/router"

// ParseHTTPParameters is VPN-Core 0.12's: a provider route's TCP parameters
// for selectors 1-3 are the original HttpCheaterHeader FlatBuffer or a plain
// domain. An empty vector leaves the native authorization fields at zero.
// Orbit links never call it (they always use CheaterID 2 with the inner name).
func ParseHTTPParameters(kind uint16, parameters []byte) (HTTPHeader, error) {
	if kind < 1 || kind > 3 {
		return HTTPHeader{}, ErrHTTPProfile
	}
	if len(parameters) == 0 {
		return HTTPHeader{}, nil
	}
	if h, e := router.ParseHTTPHeader(parameters); e == nil {
		if !safeHTTPText(h.Domain) {
			return HTTPHeader{}, ErrHTTPProfile
		}
		return HTTPHeader{CheaterID: h.CheaterID, CustomID: h.CustomID, Domain: h.Domain, Extra: h.Extra}, nil
	}
	domain := string(parameters)
	if len(domain) > 253 {
		return HTTPHeader{}, ErrHTTPProfile
	}
	for _, c := range domain {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return HTTPHeader{}, ErrHTTPProfile
		}
	}
	id := uint16(1)
	if kind != 1 {
		id = 2
	}
	return HTTPHeader{CheaterID: id, Domain: domain}, nil
}
