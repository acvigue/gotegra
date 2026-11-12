package gotegra

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

var le = binary.LittleEndian

// fakeEndpoint is a usbEndpoint that records everything written and serves a
// scripted stream of bytes for reads, so the 3p wire framing can be checked
// without hardware.
type fakeEndpoint struct {
	out bytes.Buffer
	in  []byte
	pos int
}

func (f *fakeEndpoint) BulkOut(data []byte, _ uint32) error {
	f.out.Write(data)
	return nil
}

func (f *fakeEndpoint) BulkIn(n int, _ uint32) ([]byte, error) {
	if f.pos >= len(f.in) {
		return nil, io.ErrUnexpectedEOF
	}
	end := f.pos + n
	if end > len(f.in) {
		end = len(f.in)
	}
	b := f.in[f.pos:end]
	f.pos = end
	return b, nil
}

func sum(b []byte) uint32 {
	var s uint32
	for _, x := range b {
		s += uint32(x)
	}
	return s
}

// dataPacket builds a 3p data/command packet exactly as a device would send it:
// 16-byte header, 4-byte length, payload, 4-byte two's-complement checksum of
// header+payload (the length word is not part of the checksum, matching recv).
func dataPacket(ptype uint32, seq uint64, payload []byte) []byte {
	hdr := make([]byte, 16)
	le.PutUint32(hdr[0:], 3)
	le.PutUint32(hdr[4:], ptype)
	le.PutUint32(hdr[8:], uint32(seq))
	le.PutUint32(hdr[12:], uint32(seq>>32))
	lenB := make([]byte, 4)
	le.PutUint32(lenB, uint32(len(payload)))
	tr := make([]byte, 4)
	le.PutUint32(tr, -(sum(hdr) + sum(payload)))
	out := append([]byte{}, hdr...)
	out = append(out, lenB...)
	out = append(out, payload...)
	return append(out, tr...)
}

// ackPacket builds a 3p ACK (type 3): header + a 4-byte trailer (recv does not
// verify the ACK trailer).
func ackPacket(seq uint64) []byte {
	hdr := make([]byte, 16)
	le.PutUint32(hdr[0:], 3)
	le.PutUint32(hdr[4:], 3)
	le.PutUint32(hdr[8:], uint32(seq))
	le.PutUint32(hdr[12:], uint32(seq>>32))
	return append(hdr, 0, 0, 0, 0)
}

// parsedPacket is one packet read back off the OUT stream.
type parsedPacket struct {
	ptype   uint32
	seq     uint64
	payload []byte
}

// parseOut decodes the recorded OUT byte stream into packets the same way the
// device would, verifying each data packet's checksum.
func parseOut(t *testing.T, b []byte) []parsedPacket {
	t.Helper()
	var pkts []parsedPacket
	for len(b) > 0 {
		if len(b) < 16 {
			t.Fatalf("truncated header: %d bytes left", len(b))
		}
		hdr := b[:16]
		if le.Uint32(hdr[0:]) != 3 {
			t.Fatalf("bad magic 0x%x", le.Uint32(hdr[0:]))
		}
		ptype := le.Uint32(hdr[4:])
		seq := uint64(le.Uint32(hdr[8:])) | uint64(le.Uint32(hdr[12:]))<<32
		b = b[16:]
		if ptype == 3 || ptype == 4 {
			if len(b) < 4 {
				t.Fatalf("truncated ack trailer")
			}
			b = b[4:]
			pkts = append(pkts, parsedPacket{ptype: ptype, seq: seq})
			continue
		}
		if len(b) < 4 {
			t.Fatalf("truncated length")
		}
		plen := int(le.Uint32(b[:4]))
		b = b[4:]
		if len(b) < plen+4 {
			t.Fatalf("truncated payload/trailer: want %d, have %d", plen+4, len(b))
		}
		payload := b[:plen]
		tr := le.Uint32(b[plen : plen+4])
		if sum(hdr)+sum(payload)+tr != 0 {
			t.Fatalf("checksum mismatch on type %d packet", ptype)
		}
		b = b[plen+4:]
		pkts = append(pkts, parsedPacket{ptype: ptype, seq: seq, payload: payload})
	}
	return pkts
}

func TestBuildOemCommand(t *testing.T) {
	got := buildOemCommand(oemCmdBurnFuses)
	if len(got) != 4+oemCmdStructLen {
		t.Fatalf("len = %d, want %d", len(got), 4+oemCmdStructLen)
	}
	if op := le.Uint32(got[0:]); op != rcmOpcodeOEM {
		t.Errorf("opcode = %d, want %d (OEM)", op, rcmOpcodeOEM)
	}
	if c := le.Uint32(got[4:]); c != oemCmdBurnFuses {
		t.Errorf("oem cmd = %d, want %d (burnfuses)", c, oemCmdBurnFuses)
	}
	// Remaining struct words default to zero (file-based burnfuses carries no sub).
	for i := 8; i < len(got); i++ {
		if got[i] != 0 {
			t.Errorf("byte %d = 0x%x, want 0", i, got[i])
		}
	}
	// readfuses uses the same framing with a different sub-command.
	if c := le.Uint32(buildOemCommand(oemCmdReadFuses)[4:]); c != oemCmdReadFuses {
		t.Errorf("readfuses cmd = %d, want %d", c, oemCmdReadFuses)
	}
	// Extra args land after the sub-command.
	if a := le.Uint32(buildOemCommand(oemCmdBurnFuses, 0x1234)[8:]); a != 0x1234 {
		t.Errorf("arg0 = 0x%x, want 0x1234", a)
	}
}

func TestCheckOemStatus(t *testing.T) {
	ok := make([]byte, 12)
	le.PutUint32(ok[0:], oemStatusOpcode) // opcode 8, status u64 = 0
	if err := checkOemStatus(ok); err != nil {
		t.Errorf("success status returned error: %v", err)
	}

	fail := make([]byte, 12)
	le.PutUint32(fail[0:], oemStatusOpcode)
	le.PutUint32(fail[4:], 0x5) // non-zero status
	if err := checkOemStatus(fail); err == nil {
		t.Error("non-zero status did not error")
	}

	badOp := make([]byte, 12)
	le.PutUint32(badOp[0:], 7) // not 8
	if err := checkOemStatus(badOp); err == nil {
		t.Error("wrong opcode did not error")
	}

	// A short/absent status body is tolerated (the ACK already decided success).
	if err := checkOemStatus(nil); err != nil {
		t.Errorf("nil status errored: %v", err)
	}
}

// TestOemBurnFusesFraming drives the full OEM burnfuses 3p exchange against a
// scripted device and asserts the exact outgoing wire framing.
func TestOemBurnFusesFraming(t *testing.T) {
	fuseBlob := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	// Device IN stream, in the order OemBurnFuses reads it:
	//   ack(command)  → cmd response (empty data) → ack(data blob)
	//   → status (opcode 8, success) → ack(complete)
	status := make([]byte, 12)
	le.PutUint32(status[0:], oemStatusOpcode)
	var in []byte
	in = append(in, ackPacket(0)...)          // ack our command (seq 0)
	in = append(in, dataPacket(1, 0, nil)...) // command response, empty
	in = append(in, ackPacket(1)...)          // ack our data packet (seq 1)
	in = append(in, dataPacket(1, 1, status)...)
	in = append(in, ackPacket(2)...) // ack our complete packet (seq 2)

	f := &fakeEndpoint{in: in}
	tp := newThreeP(f)
	if err := tp.OemBurnFuses(fuseBlob); err != nil {
		t.Fatalf("OemBurnFuses: %v", err)
	}

	pkts := parseOut(t, f.out.Bytes())
	// Expected OUT: command(type1), ack(for cmd response), data(type2),
	// ack(for status), complete(type1).
	var cmd, data, complete *parsedPacket
	acks := 0
	for i := range pkts {
		switch pkts[i].ptype {
		case 1:
			if cmd == nil {
				cmd = &pkts[i]
			} else {
				complete = &pkts[i]
			}
		case 2:
			data = &pkts[i]
		case 3:
			acks++
		default:
			t.Errorf("unexpected OUT packet type %d", pkts[i].ptype)
		}
	}
	if cmd == nil {
		t.Fatal("no command packet sent")
	}
	if want := buildOemCommand(oemCmdBurnFuses); !bytes.Equal(cmd.payload, want) {
		t.Errorf("command payload = %x, want %x", cmd.payload, want)
	}
	if data == nil {
		t.Fatal("no data packet sent")
	}
	if !bytes.Equal(data.payload, fuseBlob) {
		t.Errorf("data payload = %x, want %x (the fuse blob verbatim)", data.payload, fuseBlob)
	}
	if data.seq != 1 {
		t.Errorf("data packet seq = %d, want 1 (command was seq 0)", data.seq)
	}
	if complete == nil {
		t.Error("no command-complete packet sent")
	} else if op := le.Uint32(complete.payload[0:]); op != rcmOpcodeComplete {
		t.Errorf("complete opcode = %d, want %d", op, rcmOpcodeComplete)
	}
	if acks != 2 {
		t.Errorf("sent %d ACKs, want 2 (one per received data packet)", acks)
	}
}

// TestOemBurnFusesEmpty rejects an empty blob before touching USB.
func TestOemBurnFusesEmpty(t *testing.T) {
	f := &fakeEndpoint{}
	if err := newThreeP(f).OemBurnFuses(nil); err == nil {
		t.Error("empty blob did not error")
	}
	if f.out.Len() != 0 {
		t.Error("wrote to USB for an empty blob")
	}
}

// TestOemBurnFusesDeviceFailure surfaces a non-zero device status as an error.
func TestOemBurnFusesDeviceFailure(t *testing.T) {
	status := make([]byte, 12)
	le.PutUint32(status[0:], oemStatusOpcode)
	le.PutUint32(status[4:], 0x9) // failure code
	var in []byte
	in = append(in, ackPacket(0)...)
	in = append(in, dataPacket(1, 0, nil)...)
	in = append(in, ackPacket(1)...)
	in = append(in, dataPacket(1, 1, status)...)
	f := &fakeEndpoint{in: in}
	if err := newThreeP(f).OemBurnFuses([]byte{1, 2, 3, 4}); err == nil {
		t.Error("device failure status was not surfaced as an error")
	}
}
