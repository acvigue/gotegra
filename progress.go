package gotegra

import (
	"fmt"
	"strconv"
	"strings"
)

// The device-side agent can report what it is doing while no LUN is exported —
// most usefully during QSPI programming, when it otherwise has no USB presence
// at all. A flashing image that supports this (luka-firmware's flash-progress)
// binds a CDC-ACM serial gadget in those gaps and writes one state line a
// second:
//
//	gotegra-progress 1              once, after the port opens
//	idle                            no step has produced anything yet
//	qspi-erase                      the boot flash is being erased
//	qspi <done> <total> <part>      writes finished / planned / current partition
//	qspi-done <SUCCESS|FAILED>      boot flash programming has ended
//
// An image without it simply never shows the port, and the host falls back to
// its periodic "still waiting" line.

// ProgressProduct is the USB product string of the agent's progress gadget.
const ProgressProduct = "L4T flash progress"

// progressState is the agent's most recent report.
type progressState struct {
	phase       string // "idle", "qspi-erase", "qspi", "qspi-done"
	done, total int    // qspi
	part        string // qspi: partition being written
	result      string // qspi-done
}

// parseProgressLine decodes one line from the progress port. ok is false for
// the greeting, blank lines and anything not understood (a newer agent may say
// more than this host knows).
func parseProgressLine(line string) (st progressState, ok bool) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return st, false
	}
	switch f[0] {
	case "idle", "qspi-erase":
		return progressState{phase: f[0]}, true
	case "qspi":
		if len(f) < 3 {
			return st, false
		}
		done, e1 := strconv.Atoi(f[1])
		total, e2 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil || done < 0 || total <= 0 {
			return st, false
		}
		st = progressState{phase: "qspi", done: done, total: total}
		if len(f) > 3 {
			st.part = f[3]
		}
		return st, true
	case "qspi-done":
		st = progressState{phase: "qspi-done"}
		if len(f) > 1 {
			st.result = f[1]
		}
		return st, true
	}
	return st, false
}

// String is the one-line rendering shown while waiting.
func (s progressState) String() string {
	switch s.phase {
	case "idle":
		return "device: working"
	case "qspi-erase":
		return "device: erasing the QSPI boot flash"
	case "qspi":
		done := s.done
		if done > s.total {
			done = s.total
		}
		return fmt.Sprintf("device: programming QSPI %d/%d (%d%%) %s", done, s.total, done*100/s.total, s.part)
	case "qspi-done":
		return "device: QSPI programming finished: " + s.result
	}
	return ""
}

// lineSplitter turns a byte stream into complete lines, keeping a partial last
// line for the next call.
type lineSplitter struct{ buf []byte }

func (l *lineSplitter) feed(p []byte) []string {
	l.buf = append(l.buf, p...)
	var lines []string
	for {
		i := strings.IndexAny(string(l.buf), "\r\n")
		if i < 0 {
			break
		}
		if i > 0 {
			lines = append(lines, string(l.buf[:i]))
		}
		l.buf = l.buf[i+1:]
	}
	if len(l.buf) > 4096 { // not our protocol: do not grow without bound
		l.buf = l.buf[:0]
	}
	return lines
}
