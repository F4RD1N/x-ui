package router

// HTTPHeader is the four-slot HttpCheaterHeader table of a route's TCP
// parameters (selectors 1-3). Extra contains ByeDPI helper arguments returned
// verbatim by the native parser, including NUL; the custom outbound refuses a
// route that needs them (it starts no helper process).
type HTTPHeader struct {
	CheaterID, CustomID uint16
	Domain, Extra       string
}

// ParseHTTPHeader decodes the table with the bounds-checked reader. The
// encoder (VPN-Core's MarshalHTTPHeader) is server-side and not needed here.
func ParseHTTPHeader(b []byte) (HTTPHeader, error) {
	r, t := root(b)
	out := HTTPHeader{CheaterID: t.u16(0), CustomID: t.u16(1), Domain: t.text(2), Extra: t.text(3)}
	if r.err != nil {
		return HTTPHeader{}, r.err
	}
	return out, nil
}
