package strictjson

import (
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	for _, tc := range []struct {
		in    string
		valid bool
	}{
		{`{"n":1,"values":[true,null,{"a":"b"}]}`, true},
		{`{"n":1,"n":2}`, false}, {`{"values":[{"a":1,"a":2}]}`, false},
		{`{"unknown":1}`, false}, {`{"n":"one"}`, false},
		{`{} {}`, false}, {`{} garbage`, false}, {``, false},
		{`{"n":1,}`, false}, {`{"n":1`, false}, {string([]byte{0xff}), false},
		{strings.Repeat("[", 66) + strings.Repeat("]", 66), false},
		{strings.Repeat(" ", MaxBytes+1), false},
	} {
		t.Run(tc.in[:min(len(tc.in), 30)], func(t *testing.T) {
			var dst struct {
				N      int   `json:"n"`
				Values []any `json:"values"`
			}
			err := Decode([]byte(tc.in), &dst)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"value":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, b []byte) { var v any; _ = Decode(b, &v) })
}
