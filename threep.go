package gotegra

import (
	"bytes"
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
// usbEndpoint is the subset of *Device the 3p layer needs: raw bulk transfers on
// EP 0x01 (OUT) and EP 0x81 (IN). *Device satisfies it; unit tests supply a fake
// so the packet framing can be checked without hardware.
type usbEndpoint interface {
	BulkOut(data []byte, timeoutMS uint32) error
	BulkIn(n int, timeoutMS uint32) ([]byte, error)
}

type threeP struct {
	d    usbEndpoint
	seq  uint64 // our outgoing command sequence
	rseq uint64 // last received packet's sequence (echoed in our ACK/NACK)
}

const tpTimeout = 1000000 // 1000 s, as tegrarcm uses

func newThreeP(d usbEndpoint) *threeP { return &threeP{d: d} }

func sumBytes(b []byte) uint32 {
	var s uint32
	for _, x := range b {
		s += uint32(x)
	}
	return s
}

// bulkInFull reads exactly n bytes from EP 0x81 (3p fields are discrete bulk
// transfers, so a single read usually suffices, but loop to be safe).
func (t *threeP) bulkInFull(n int) ([]byte, error) {
	out := make([]byte, 0, n)
	for len(out) < n {
		b, err := t.d.BulkIn(n-len(out), tpTimeout)
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
	hdr, err := t.bulkInFull(16)
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
		if _, err := t.bulkInFull(4); err != nil { // trailer checksum
			return ptype, nil, err
		}
		return ptype, nil, nil
	}
	lenB, err := t.bulkInFull(4)
	if err != nil {
		return ptype, nil, err
	}
	plen := int(binary.LittleEndian.Uint32(lenB))
	if plen > 0 {
		payload, err = t.bulkInFull(plen)
		if err != nil {
			return ptype, nil, err
		}
	}
	trB, err := t.bulkInFull(4)
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

// RCM command opcodes. Each is the first u32 of the payload of a 3p type-1
// "command" packet; the command-specific struct follows it. From tegrarcm_v2:
// NvTegraRcmAppletDownload sends opcode 2, NvTegraRunOemCmd sends opcode 6 for
// every OEM command, NvTegra3pCommandComplete sends opcode 9, and
// NvTegraRcmAppletBoot sends opcode 10 (all via NvTegra3pCommandSend, which
// wraps them in a type-1 packet — see the first u32 passed to NvTegra3pSend).
const (
	rcmOpcodeDownload = 2
	rcmOpcodeOEM      = 6
	rcmOpcodeComplete = 9
	rcmOpcodeBoot     = 10
)

// OEM sub-commands: the first u32 of the 16-byte OEM command struct that follows
// an rcmOpcodeOEM opcode (tegrarcm_v2 NvTegraGetOemCmd). The device reports the
// result in a status packet whose own opcode is oemStatusOpcode.
const (
	oemCmdBurnFuses = 6
	oemCmdReadFuses = 8
	oemStatusOpcode = 8
	oemCmdStructLen = 16 // NvTegraRunOemCmd's command buffer is 0x10 bytes
)

// buildOemCommand assembles the payload of the 3p type-1 command packet for an
// OEM command: the rcmOpcodeOEM opcode u32, followed by the 16-byte OEM command
// struct [oemCmd, args...]. Mirrors NvTegra3pCommandSend(dev, 6, buf, 0x10) in
// tegrarcm_v2, where buf[0] is the OEM sub-command. Pure, so it is unit-tested.
func buildOemCommand(oemCmd uint32, args ...uint32) []byte {
	buf := make([]byte, 4+oemCmdStructLen)
	binary.LittleEndian.PutUint32(buf[0:], rcmOpcodeOEM)
	binary.LittleEndian.PutUint32(buf[4:], oemCmd)
	for i, a := range args {
		off := 8 + i*4
		if off+4 > len(buf) {
			break
		}
		binary.LittleEndian.PutUint32(buf[off:], a)
	}
	return buf
}

// OemBurnFuses sends the generic tegrarcm_v2 `--oem burnfuses <blob>` sequence
// over the 3p protocol to a RUNNING mb2_applet: a type-1 command packet
// (opcode 6 = OEM, OEM cmd 6 = burnfuses), then the already-signed fuse blob as
// a single type-2 data packet, then it reads the burn status. Mirrors
// NvTegraRunOemCmd(burnfuses) in tegrarcm_v2.
//
// This is the generic applet path. It is NOT what T234 tegraflash does for
// `burnfuses`: that bakes the fuse blob into a signed FSKP MB2 image and
// RCM-boots it (see fuse.go — BurnFusesFSKP, the production path). gotegra never
// builds or signs the blob; the caller passes the artifact produced offline by
// tegraparser/tegrasign_v3. The OUTGOING framing here is reversed from
// tegrarcm_v2; the device-side responses are reconstructed and NOT verified
// against hardware. Burning fuses is IRREVERSIBLE — callers must gate this.
func (t *threeP) OemBurnFuses(fuseBlob []byte) error {
	if len(fuseBlob) == 0 {
		return fmt.Errorf("empty fuse blob")
	}
	if err := t.send(1, buildOemCommand(oemCmdBurnFuses)); err != nil {
		return fmt.Errorf("send burnfuses command: %w", err)
	}
	// tegrarcm reads the device's command response (NvTegra3pCommandReceive)
	// before streaming the data; drain it.
	if _, _, err := t.recv(); err != nil {
		return fmt.Errorf("burnfuses command response: %w", err)
	}
	if err := t.send(2, fuseBlob); err != nil {
		return fmt.Errorf("send fuse blob (%d bytes): %w", len(fuseBlob), err)
	}
	// Status packet payload: [opcode=8][status u64][message...] (0 == success),
	// matching NvTegra3pGetCommandStatus + NvTegraHandleStatus.
	_, status, err := t.recv()
	if err != nil {
		return fmt.Errorf("read burn status: %w", err)
	}
	if err := checkOemStatus(status); err != nil {
		return err
	}
	// Acknowledge the status (NvTegraHandleStatus → NvTegra3pCommandComplete,
	// opcode 9). Best-effort: the burn result is already known.
	_ = t.send(1, buildCompleteCommand())
	return nil
}

// buildCompleteCommand builds the "command complete" payload: opcode 9 + an
// 8-byte zero struct (NvTegra3pCommandComplete(dev, 0, 0)).
func buildCompleteCommand() []byte {
	buf := make([]byte, 4+8)
	binary.LittleEndian.PutUint32(buf[0:], rcmOpcodeComplete)
	return buf
}

// checkOemStatus interprets an OEM status packet payload. Pure, so it is
// unit-tested.
func checkOemStatus(status []byte) error {
	if len(status) < 4 {
		return nil // no status body; the ACK/NACK already decided success
	}
	if op := binary.LittleEndian.Uint32(status[0:]); op != oemStatusOpcode {
		return fmt.Errorf("unexpected status opcode %d (want %d)", op, oemStatusOpcode)
	}
	if len(status) >= 12 {
		if code := binary.LittleEndian.Uint64(status[4:]); code != 0 {
			msg := string(bytes.TrimRight(status[12:], "\x00"))
			if msg != "" {
				return fmt.Errorf("fuse burn failed: 0x%016x: %s", code, msg)
			}
			return fmt.Errorf("fuse burn failed: device status 0x%016x", code)
		}
	}
	return nil
}

// BurnFusesApplet runs the OEM burnfuses 3p sequence against a running applet on
// this device. See threeP.OemBurnFuses for the important caveats.
func (d *Device) BurnFusesApplet(fuseBlob []byte) error {
	return newThreeP(d).OemBurnFuses(fuseBlob)
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
