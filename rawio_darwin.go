//go:build darwin

package gotegra

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// rawBlockSize is the logical block size of the exported LUNs. macOS rejects
// writes to /dev/rdiskN whose length is not a multiple of this (EINVAL,
// "invalid argument"). The nvme LUN enumerates with 512-byte logical blocks
// (confirmed: a write at offset 512 succeeds), so partition images whose size
// is not a multiple of 512 (e.g. a kernel dtb) must have their final short
// chunk padded up to the block boundary.
const rawBlockSize = 512

// writeRawImage streams an image onto the raw block device at a byte offset
// (/dev/rdiskN, unbuffered). Needs root.
//
// sparse=true skips all-zero 1 MiB chunks (seeks over them), so stale bytes
// stay on the drive wherever the image is zero. That is correct for free
// filesystem blocks and for holes inside files, and wrong for metadata the
// filesystem assumes zero — hence forced (below). The flashpkg LUN is never
// written sparsely: the device backs it with its own freshly mke2fs'd ext4, so
// gaps would leave that filesystem's bytes behind and produce an unmountable
// franken-ext4.
//
// forced lists image byte ranges that are written even when zero (ext4
// metadata that mke2fs zero-fills; see Ext4MetadataRanges). With sparse=false
// it is ignored.
func writeRawImage(imgPath, dev string, byteOffset int64, sparse bool, forced []byteRange) error {
	raw := strings.Replace(dev, "/dev/disk", "/dev/rdisk", 1)
	src, err := os.Open(imgPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(raw, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s (needs root — run with sudo): %w", raw, err)
	}
	defer dst.Close()
	if byteOffset > 0 {
		if _, err := dst.Seek(byteOffset, io.SeekStart); err != nil {
			return fmt.Errorf("seek to %d: %w", byteOffset, err)
		}
	}
	buf := make([]byte, 1<<20)
	var written, skipped, forcedBytes int64
	var pos int64
	fs := &rangeSet{rs: forced}
	last := time.Now()
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			b := buf[:n]
			zero := sparse && isZeroBlock(b)
			if zero && fs.overlaps(pos, pos+int64(n)) {
				zero = false // metadata the filesystem assumes zeroed: write it
				forcedBytes += int64(n)
			}
			pos += int64(n)
			if zero {
				// Nothing the filesystem relies on lives here: seek over it
				// instead of writing (only real data moves).
				if _, err := dst.Seek(int64(n), io.SeekCurrent); err != nil {
					return fmt.Errorf("seek: %w", err)
				}
				skipped += int64(n)
			} else {
				wb := b
				if n%rawBlockSize != 0 {
					// Final short chunk: pad up to the block boundary with zeros
					// so the raw write is block-aligned (the partition is
					// erase-nvme'd to zero and sized >= its image, so the pad is
					// harmless). Without this macOS returns EINVAL.
					padded := (n + rawBlockSize - 1) / rawBlockSize * rawBlockSize
					tmp := make([]byte, padded)
					copy(tmp, b)
					wb = tmp
				}
				if _, werr := dst.Write(wb); werr != nil {
					return werr
				}
				written += int64(n)
			}
			if time.Since(last) > 2*time.Second {
				fmt.Printf("\r  wrote %d MiB, skipped %d MiB zeros", written>>20, skipped>>20)
				last = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	fmt.Printf("\r  wrote %d MiB, skipped %d MiB zeros (done", written>>20, skipped>>20)
	if forcedBytes > 0 {
		fmt.Printf("; %d MiB of zeroed fs metadata written", forcedBytes>>20)
	}
	fmt.Println(")")
	return nil
}

func isZeroBlock(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// readRawImage copies the first size bytes of the raw block device to outPath.
// Needs root.
func readRawImage(dev, outPath string, size int64) error {
	raw := strings.Replace(dev, "/dev/disk", "/dev/rdisk", 1)
	src, err := os.Open(raw)
	if err != nil {
		return fmt.Errorf("open %s (needs root): %w", raw, err)
	}
	defer src.Close()
	dst, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := io.CopyN(dst, src, size); err != nil && err != io.EOF {
		return err
	}
	return nil
}
