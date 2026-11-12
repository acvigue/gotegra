//go:build darwin

package gotegra

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// progressPortFromIoreg returns the callout device (/dev/cu.usbmodem…) of the
// agent's progress gadget from `ioreg -r -c IOUSBHostDevice -l` output, or "".
// Each matched USB device is a top-level "+-o" entry whose subtree carries the
// serial client's IOCalloutDevice.
func progressPortFromIoreg(out string) string {
	for _, block := range strings.Split("\n"+out, "\n+-o ") {
		if !strings.Contains(block, `"USB Product Name" = "`+ProgressProduct+`"`) {
			continue
		}
		for _, line := range strings.Split(block, "\n") {
			if dev := ioregStr(line, `"IOCalloutDevice" = `); dev != "" {
				return dev
			}
		}
	}
	return ""
}

func findProgressPort() string {
	out, err := exec.Command("ioreg", "-r", "-c", "IOUSBHostDevice", "-l", "-w0").Output()
	if err != nil {
		return ""
	}
	return progressPortFromIoreg(string(out))
}

// progressWatcher follows the agent's progress port across its appearances (it
// exists only between LUNs) and prints each change of state.
type progressWatcher struct {
	fd      int
	open    bool
	split   lineSplitter
	last    string // last line printed
	inPlace bool   // the cursor sits at the end of an in-place progress line
}

// poll is called about once a second from the LUN wait loop. It reports
// whether the device is currently talking, so the caller can hold back its own
// "still waiting" line.
func (w *progressWatcher) poll() bool {
	if !w.open {
		dev := findProgressPort()
		if dev == "" {
			return false
		}
		// O_NONBLOCK: never wait for carrier on open or for data on read.
		fd, err := syscall.Open(dev, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
		if err != nil {
			return false
		}
		rawTTY(fd)
		w.fd, w.open, w.split = fd, true, lineSplitter{}
	}
	buf := make([]byte, 4096)
	for {
		n, err := syscall.Read(w.fd, buf)
		if n > 0 {
			for _, line := range w.split.feed(buf[:n]) {
				if st, ok := parseProgressLine(line); ok {
					w.show(st)
				}
			}
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EINTR {
			return true // port is there, nothing new
		}
		// EOF or an error: the agent unbound the gadget for its next LUN.
		w.close()
		return false
	}
}

func (w *progressWatcher) show(st progressState) {
	s := st.String()
	if s == "" || s == w.last {
		return
	}
	w.last = s
	if st.phase == "qspi" {
		fmt.Printf("\r  %-76s", s) // counts up in place
		w.inPlace = true
		return
	}
	w.endLine()
	fmt.Printf("  %s\n", s)
}

// endLine finishes an in-place progress line before anything else is printed.
func (w *progressWatcher) endLine() {
	if w.inPlace {
		fmt.Println()
		w.inPlace = false
	}
}

func (w *progressWatcher) close() {
	w.endLine()
	if w.open {
		syscall.Close(w.fd)
		w.open = false
	}
}

// rawTTY puts the serial port in raw mode with echo off. A cooked tty would
// echo the device's own lines back at it.
func rawTTY(fd int) {
	var t syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGETA, uintptr(unsafe.Pointer(&t))); e != 0 {
		return
	}
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8 | syscall.CLOCAL | syscall.CREAD
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCSETA, uintptr(unsafe.Pointer(&t)))
}
