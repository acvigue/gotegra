package gotegra

import (
	"reflect"
	"testing"
)

func TestParseProgressLine(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		want string
	}{
		{"gotegra-progress 1", false, ""},
		{"", false, ""},
		{"idle", true, "device: working"},
		{"qspi-erase", true, "device: erasing the QSPI boot flash"},
		{"qspi 19 115 BCT+18", true, "device: programming QSPI 19/115 (16%) BCT+18"},
		{"qspi 115 115 secondary_gpt", true, "device: programming QSPI 115/115 (100%) secondary_gpt"},
		{"qspi 120 115 x", true, "device: programming QSPI 115/115 (100%) x"},
		{"qspi 3 0 x", false, ""},
		{"qspi three 115", false, ""},
		{"qspi-done SUCCESS", true, "device: QSPI programming finished: SUCCESS"},
		{"something-newer 1 2", false, ""},
	}
	for _, c := range cases {
		st, ok := parseProgressLine(c.line)
		if ok != c.ok || (ok && st.String() != c.want) {
			t.Errorf("%q: ok=%v %q, want ok=%v %q", c.line, ok, st.String(), c.ok, c.want)
		}
	}
}

func TestLineSplitter(t *testing.T) {
	var l lineSplitter
	if got := l.feed([]byte("idle\r\nqspi 1 1")); !reflect.DeepEqual(got, []string{"idle"}) {
		t.Errorf("first feed: %q", got)
	}
	if got := l.feed([]byte("15 A_mb2\nqspi-e")); !reflect.DeepEqual(got, []string{"qspi 1 115 A_mb2"}) {
		t.Errorf("second feed: %q", got)
	}
	l.feed(make([]byte, 5000)) // garbage without a newline must not accumulate
	if len(l.buf) != 0 {
		t.Errorf("buffer not reset: %d bytes", len(l.buf))
	}
}
