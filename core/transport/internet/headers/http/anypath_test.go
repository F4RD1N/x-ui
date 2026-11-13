package http

import (
	"bytes"
	"testing"
)

func TestHeaderReaderAnyPath(t *testing.T) {
	cases := []struct {
		uri  []string
		path string
		ok   bool
	}{
		{[]string{"*"}, "/api/v4/live/rooms/12345678/events?transport=ws&sid=ab12", true},
		{[]string{"*"}, "/", true},
		{[]string{"/*"}, "/feed/966695/assets/recent/media", true},
		{[]string{"/", "*"}, "/x/y/z", true},
		{[]string{"/a", "/b"}, "/b?q=1", true},
		{[]string{"/a", "/b"}, "/c", false},
		{[]string{"/"}, "/anything", false},
		{[]string{"/*x"}, "/abc", false},
	}
	for _, c := range cases {
		raw := "GET " + c.path + " HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: t\r\n\r\npayload"
		reader := new(HeaderReader).ExpectThisRequest(&RequestConfig{Uri: c.uri})
		b, err := reader.Read(bytes.NewReader([]byte(raw)))
		if c.ok {
			if err != nil {
				t.Errorf("uri %v path %q: want accepted, got %v", c.uri, c.path, err)
				continue
			}
			if b == nil || b.String() != "payload" {
				t.Errorf("uri %v path %q: payload lost: %v", c.uri, c.path, b)
			}
		} else if err != ErrHeaderMisMatch {
			t.Errorf("uri %v path %q: want ErrHeaderMisMatch, got %v", c.uri, c.path, err)
		}
	}
}
