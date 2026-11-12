package gotegra

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
)

// ext4 on-disk facts needed to find the metadata that mke2fs writes as explicit
// zeros. The flashing path writes partition images sparsely (all-zero 1 MiB
// chunks are skipped), which is only correct for bytes the filesystem never
// relies on being zero. Free data blocks qualify, and so do zero blocks inside
// files (mke2fs -d records those as holes), but inode tables (every group is
// INODE_ZEROED), bitmaps and the reserved GDT area are zero-filled by mke2fs and
// assumed zero afterwards; after a `tar --sparse` round trip they are holes and
// would otherwise be skipped, leaving stale bytes from whatever was on the
// drive before. These ranges are therefore written even when zero, which is
// what lets the flash do without a whole-drive discard (NVIDIA's own flow never
// erases either: bmaptool writes every mapped block).

type byteRange struct{ off, end int64 } // [off, end)

const (
	ext4SuperMagic = 0xEF53

	ext4FeatureIncompat64bit  = 0x0080
	ext4FeatureIncompatMetaBG = 0x0010
	ext4FeatureROSparseSuper  = 0x0001
	ext4FeatureROSparseSuper2 = 0x0200
)

// Ext4MetadataRanges returns the byte ranges (relative to the image) that hold
// ext4 group metadata: each group's block bitmap, inode bitmap and inode table,
// plus the superblock + GDT + reserved-GDT copy of every group that carries
// one. Ranges are sorted and merged. It returns nil, nil for an image that is
// not ext4.
func Ext4MetadataRanges(path string) ([]byteRange, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sb := make([]byte, 1024)
	if _, err := f.ReadAt(sb, 1024); err != nil {
		return nil, nil // too small to be a filesystem
	}
	le := binary.LittleEndian
	if le.Uint16(sb[0x38:]) != ext4SuperMagic {
		return nil, nil
	}
	logBS := le.Uint32(sb[0x18:])
	if logBS > 6 {
		return nil, fmt.Errorf("ext4: implausible block size shift %d", logBS)
	}
	bs := int64(1024) << logBS
	firstData := int64(le.Uint32(sb[0x14:]))
	blocksPerGroup := int64(le.Uint32(sb[0x20:]))
	inodesPerGroup := int64(le.Uint32(sb[0x28:]))
	inodeSize := int64(le.Uint16(sb[0x58:]))
	if inodeSize == 0 {
		inodeSize = 128
	}
	incompat := le.Uint32(sb[0x60:])
	roCompat := le.Uint32(sb[0x64:])
	reservedGDT := int64(le.Uint16(sb[0xCE:]))
	blocks := int64(le.Uint32(sb[0x4:]))
	descSize := int64(32)
	if incompat&ext4FeatureIncompat64bit != 0 {
		blocks |= int64(le.Uint32(sb[0x150:])) << 32
		if d := int64(le.Uint16(sb[0xFE:])); d >= 32 {
			descSize = d
		}
	}
	if blocksPerGroup == 0 || inodesPerGroup == 0 {
		return nil, fmt.Errorf("ext4: zero blocks/inodes per group")
	}
	ngroups := (blocks - firstData + blocksPerGroup - 1) / blocksPerGroup
	if ngroups <= 0 || ngroups > 1<<20 {
		return nil, fmt.Errorf("ext4: implausible group count %d", ngroups)
	}
	gdtBlocks := (ngroups*descSize + bs - 1) / bs

	gdt := make([]byte, ngroups*descSize)
	if _, err := f.ReadAt(gdt, (firstData+1)*bs); err != nil {
		return nil, fmt.Errorf("ext4: read group descriptors: %w", err)
	}
	backup := [2]int64{int64(le.Uint32(sb[0x17C:])), int64(le.Uint32(sb[0x180:]))}
	hasSB := func(g int64) bool {
		switch {
		case roCompat&ext4FeatureROSparseSuper2 != 0:
			return g == 0 || g == backup[0] || g == backup[1]
		case roCompat&ext4FeatureROSparseSuper != 0:
			return g <= 1 || isPowerOf(g, 3) || isPowerOf(g, 5) || isPowerOf(g, 7)
		}
		return true
	}

	var rs []byteRange
	add := func(blk, nblocks int64) {
		if nblocks <= 0 || blk < 0 || blk >= blocks {
			return
		}
		rs = append(rs, byteRange{off: blk * bs, end: (blk + nblocks) * bs})
	}
	for g := int64(0); g < ngroups; g++ {
		d := gdt[g*descSize:]
		bb := int64(le.Uint32(d[0:]))
		ib := int64(le.Uint32(d[4:]))
		it := int64(le.Uint32(d[8:]))
		if descSize >= 64 {
			bb |= int64(le.Uint32(d[0x20:])) << 32
			ib |= int64(le.Uint32(d[0x24:])) << 32
			it |= int64(le.Uint32(d[0x28:])) << 32
		}
		add(bb, 1)
		add(ib, 1)
		add(it, (inodesPerGroup*inodeSize+bs-1)/bs)
		if hasSB(g) {
			start := firstData + g*blocksPerGroup
			n := int64(1) // the superblock copy itself
			if incompat&ext4FeatureIncompatMetaBG == 0 {
				n += gdtBlocks + reservedGDT
			}
			add(start, n)
		}
	}
	return mergeRanges(rs), nil
}

func isPowerOf(n, base int64) bool {
	if n < 1 {
		return false
	}
	for n%base == 0 {
		n /= base
	}
	return n == 1
}

// mergeRanges sorts ranges and merges the ones that touch or overlap.
func mergeRanges(rs []byteRange) []byteRange {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].off < rs[j].off })
	out := []byteRange{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.off <= last.end {
			if r.end > last.end {
				last.end = r.end
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// rangeSet answers "does [off, end) touch any range" for ascending queries,
// which is how the write loop asks.
type rangeSet struct {
	rs []byteRange
	i  int
}

func (s *rangeSet) overlaps(off, end int64) bool {
	for s.i < len(s.rs) && s.rs[s.i].end <= off {
		s.i++
	}
	return s.i < len(s.rs) && s.rs[s.i].off < end
}

func (s *rangeSet) total() int64 {
	var n int64
	for _, r := range s.rs {
		n += r.end - r.off
	}
	return n
}
