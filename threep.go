package gotegra

import (
	"encoding/binary"
	"fmt"
)

// The "3p" protocol is how tegrarcm_v2 talks to mb2_applet / mb2 once it is
// running (NvTegra3pSend / NvTegra3pReceive). Each packet is:
//
//	header[16] = [magic=3][type][seq_lo][seq_hi]   (u32 LE each)
//	if data packet: [len u32][payload...]
//	trailer[4]  = two's-complement of the byte-sum of header+payload
//
// Types: 1 = command (carries payload, awaits ACK), 3 = ACK, 4 = NACK. The
// receiver ACKs every data packet. Sequence numbers (seq_lo/seq_hi) increment
// per command; ACK/NACK echo the last received packet's sequence.
type threeP struct {
	d    *Device
	seq  uint64 // our outgoing command sequence
	rseq uint64 // last received packet's sequence (echoed in our ACK/NACK)
}

const tpTimeout = 1000000 // 1000 s, as tegrarcm uses

func newThreeP(d *Device) *threeP { return &threeP{d: d} }

func sumBytes(b []byte) uint32 {
	var s uint32
	for _, x := range b {
		s += uint32(x)
	}
	return s
}

// bulkInFull reads exactly n bytes from EP 0x81 (3p fields are discrete bulk
// transfers, so a single read usually suffices, but loop to be safe).
func (d *Device) bulkInFull(n int) ([]byte, error) {
	out := make([]byte, 0, n)
	for len(out) < n {
		b, err := d.BulkIn(n-len(out), tpTimeout)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("short bulk-IN: %d/%d", len(out), n)
		}
		out = append(out, b...)
	}
	return out, nil
}

// send writes one 3p packet. Data packets (type 1) carry a length + payload and
// wait for an ACK; ACK/NACK (3/4) are header+trailer only.
func (t *threeP) send(ptype uint32, payload []byte) error {
	seq := t.seq
	if ptype == 3 || ptype == 4 {
		seq = t.rseq
	}
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:], 3)
	binary.LittleEndian.PutUint32(hdr[4:], ptype)
	binary.LittleEndian.PutUint32(hdr[8:], uint32(seq))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(seq>>32))
	if err := t.d.BulkOut(hdr, tpTimeout); err != nil {
		return err
	}
	cksum := sumBytes(hdr)
	isData := ptype != 3 && ptype != 4
	if isData {
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(payload)))
		if err := t.d.BulkOut(l[:], tpTimeout); err != nil {
			return err
		}
	}
	if len(payload) > 0 {
		if err := t.d.BulkOut(payload, tpTimeout); err != nil {
			return err
		}
		cksum += sumBytes(payload)
	}
	var tr [4]byte
	binary.LittleEndian.PutUint32(tr[:], -cksum)
	if err := t.d.BulkOut(tr[:], tpTimeout); err != nil {
		return err
	}
	if isData {
		t.seq++
		return t.waitAck()
	}
	return nil
}

// recv reads one 3p packet. For a data packet it verifies the checksum and ACKs
// the sender, returning the payload.
func (t *threeP) recv() (ptype uint32, payload []byte, err error) {
	hdr, err := t.d.bulkInFull(16)
	if err != nil {
		return 0, nil, err
	}
	if binary.LittleEndian.Uint32(hdr[0:]) != 3 {
		return 0, nil, fmt.Errorf("3p: bad magic 0x%x", binary.LittleEndian.Uint32(hdr[0:]))
	}
	ptype = binary.LittleEndian.Uint32(hdr[4:])
	t.rseq = uint64(binary.LittleEndian.Uint32(hdr[8:])) | uint64(binary.LittleEndian.Uint32(hdr[12:]))<<32
	switch ptype {
	case 4:
		return ptype, nil, fmt.Errorf("3p: NACK")
	case 3:
		if _, err := t.d.bulkInFull(4); err != nil { // trailer checksum
			return ptype, nil, err
		}
		return ptype, nil, nil
	}
	lenB, err := t.d.bulkInFull(4)
	if err != nil {
		return ptype, nil, err
	}
	plen := int(binary.LittleEndian.Uint32(lenB))
	if plen > 0 {
		payload, err = t.d.bulkInFull(plen)
		if err != nil {
			return ptype, nil, err
		}
	}
	trB, err := t.d.bulkInFull(4)
	if err != nil {
		return ptype, payload, err
	}
	if sumBytes(hdr)+sumBytes(payload)+binary.LittleEndian.Uint32(trB) != 0 {
		return ptype, payload, fmt.Errorf("3p: checksum mismatch")
	}
	if err := t.send(3, nil); err != nil { // ACK the data packet
		return ptype, payload, err
	}
	return ptype, payload, nil
}

func (t *threeP) waitAck() error {
	ptype, _, err := t.recv()
	if err != nil {
		return err
	}
	if ptype != 3 {
		return fmt.Errorf("3p: expected ACK, got type %d", ptype)
	}
	return nil
}

// Mb2Probe queries the running mb2/mb2_applet for its version over the 3p
// protocol, printing what it finds. Used to confirm the applet is up.
func (d *Device) Mb2Probe() error { return newThreeP(d).ProbeVersion() }

// ProbeVersion issues the mb2 "get version" command (command 1) and reports the
// packets the device returns. A leading dword of 1 = mb2_applet, 3 = mb2
// (NvTegraRcmIsMb2Applet / NvTegraRcmIsMb2).
func (t *threeP) ProbeVersion() error {
	if err := t.send(1, []byte{1, 0, 0, 0}); err != nil {
		return fmt.Errorf("send get-version: %w", err)
	}
	for i := 0; i < 3; i++ {
		ptype, data, err := t.recv()
		if err != nil {
			return fmt.Errorf("recv[%d]: %w", i, err)
		}
		n := len(data)
		if n > 16 {
			n = 16
		}
		fmt.Printf("  3p recv[%d]: type=%d len=%d data=%x\n", i, ptype, len(data), data[:n])
		if len(data) >= 16 {
			kind := binary.LittleEndian.Uint32(data[0:])
			if kind == 1 || kind == 3 {
				name := "MB2"
				if kind == 1 {
					name = "MB2 Applet"
				}
				fmt.Printf("  => %s version %02d.%02d.%04d\n", name,
					binary.LittleEndian.Uint32(data[4:]),
					binary.LittleEndian.Uint32(data[8:]),
					binary.LittleEndian.Uint32(data[12:]))
				return nil
			}
		}
	}
	return nil
}

// RebootTo reboots a running mb2/mb2_applet via the 3p "reboot" command (7):
// recovery (mode 0) drops the device back into bootrom RCM, coldboot (mode 1)
// boots the installed OS (NvTegraRcmReboot).
func (d *Device) RebootTo(recovery bool) error {
	t := newThreeP(d)
	mode := uint32(1) // coldboot
	if recovery {
		mode = 0
	}
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint32(payload[0:], 7) // command 7 = reboot
	binary.LittleEndian.PutUint32(payload[4:], mode)
	return t.send(1, payload)
}
