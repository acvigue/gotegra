package gotegra

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Flash packages are 128 MiB ext4 images the device-side agent mounts
// (`mount -t ext4`), holding flashpkg/conf/command_sequence and
// flashpkg/bootloader/*. They are built here the way luka's ci/flashpack.sh
// builds them: a staging tree + `mke2fs -d` (no loop mount, no root). Reading
// one back uses 7z, which understands ext4 (p7zip on macOS).

// FlashpkgSize is the agent's fixed flash-package LUN size.
const FlashpkgSize = 128 << 20

func mke2fsPath() (string, error) {
	if p, err := exec.LookPath("mke2fs"); err == nil {
		return p, nil
	}
	for _, p := range []string{
		"/opt/homebrew/opt/e2fsprogs/sbin/mke2fs",
		"/usr/local/opt/e2fsprogs/sbin/mke2fs",
		"/opt/homebrew/bin/mke2fs",
		"/sbin/mke2fs",
		"/usr/sbin/mke2fs",
	} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("mke2fs not found (brew install e2fsprogs)")
}

// buildFlashpkgFromTree makes the ext4 image img (FlashpkgSize bytes) with the
// contents of tree.
func buildFlashpkgFromTree(tree, img string) error {
	mke2fs, err := mke2fsPath()
	if err != nil {
		return err
	}
	f, err := os.Create(img)
	if err != nil {
		return err
	}
	if err := f.Truncate(FlashpkgSize); err != nil {
		f.Close()
		return err
	}
	f.Close()
	// Mirror what ci/flashpack.sh's (Ubuntu) mke2fs produces so the package the
	// agent mounts is the same shape whichever host built it: 4 KiB blocks and
	// none of the newer defaults (orphan_file, metadata_csum_seed) that a
	// 1.47 mke2fs would otherwise add.
	cmd := exec.Command(mke2fs, "-q", "-F", "-t", "ext4", "-b", "4096", "-m", "0",
		"-O", "^orphan_file,^metadata_csum_seed", "-d", tree, img)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mke2fs: %v\n%s", err, out)
	}
	return nil
}

// buildFlashpkg makes a flash package at img holding only a command sequence
// (one verb per line) — enough for probes and QSPI-less test runs.
func buildFlashpkg(img, commandSequence string) error {
	tree, err := os.MkdirTemp("", "gotegra-flashpkg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tree)
	if err := os.MkdirAll(filepath.Join(tree, "flashpkg", "conf"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tree, "flashpkg", "conf", "command_sequence"), []byte(commandSequence), 0o644); err != nil {
		return err
	}
	if err := ensureAgentDirs(tree); err != nil {
		return err
	}
	return buildFlashpkgFromTree(tree, img)
}

// ReadFlashpkgSequence returns flashpkg/conf/command_sequence from a flash
// package image (needs 7z).
func ReadFlashpkgSequence(img string) (string, error) {
	sevenZ, err := exec.LookPath("7z")
	if err != nil {
		return "", fmt.Errorf("7z not found (brew install p7zip)")
	}
	dir, err := os.MkdirTemp("", "gotegra-seq-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	cmd := exec.Command(sevenZ, "x", "-y", "-o"+dir, img, "flashpkg/conf/command_sequence")
	if o, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("7z x %s: %v\n%s", img, err, o)
	}
	data, err := os.ReadFile(filepath.Join(dir, "flashpkg", "conf", "command_sequence"))
	if err != nil {
		return "", fmt.Errorf("%s has no flashpkg/conf/command_sequence: %w", img, err)
	}
	return string(data), nil
}

// SequenceInfo is what a command sequence implies for the host side.
type SequenceInfo struct {
	ExportsNvme    bool // export-devices present: an nvme LUN will be offered
	ErasesNvme     bool // erase-nvme present: a whole-drive discard runs before the export
	Bootloader     bool // bootloader present: QSPI is programmed (in the background)
	ForcedRecovery bool // "reboot forced-recovery": the box returns to RCM afterwards
	Reboots        bool // a reboot verb is present (status LUN comes before it)
}

// ParseSequence inspects a command sequence (one verb per line).
func ParseSequence(seq string) SequenceInfo {
	var si SequenceInfo
	for _, line := range strings.Split(seq, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "export-devices":
			si.ExportsNvme = true
		case "erase-nvme":
			si.ErasesNvme = true
		case "bootloader":
			si.Bootloader = true
		case "reboot":
			si.Reboots = true
			if len(f) > 1 && f[1] == "forced-recovery" {
				si.ForcedRecovery = true
			}
		}
	}
	return si
}

// RewriteFlashpkgSequence copies the flash package in to out with
// flashpkg/conf/command_sequence replaced by seq (one verb per line; ';' is
// accepted as a line separator). The bootloader/ payload is carried over
// unchanged. Needs 7z and mke2fs.
func RewriteFlashpkgSequence(in, out, seq string) (string, error) {
	seq = strings.ReplaceAll(seq, ";", "\n")
	var lines []string
	for _, l := range strings.Split(seq, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("empty command sequence")
	}
	return rewriteFlashpkg(in, out, func(string) string { return strings.Join(lines, "\n") + "\n" })
}

// RewriteFlashpkg copies the flash package in to out with every command whose
// verb is in dropVerbs removed from flashpkg/conf/command_sequence (the
// bootloader/ payload is carried over unchanged). It returns the resulting
// command sequence. Needs 7z and mke2fs.
func RewriteFlashpkg(in, out string, dropVerbs ...string) (string, error) {
	drop := map[string]bool{}
	for _, v := range dropVerbs {
		drop[v] = true
	}
	return rewriteFlashpkg(in, out, func(old string) string {
		var kept []string
		for _, line := range strings.Split(strings.TrimRight(old, "\n"), "\n") {
			if f := strings.Fields(line); len(f) > 0 && drop[f[0]] {
				continue
			}
			kept = append(kept, line)
		}
		return strings.Join(kept, "\n") + "\n"
	})
}

func rewriteFlashpkg(in, out string, edit func(old string) string) (string, error) {
	sevenZ, err := exec.LookPath("7z")
	if err != nil {
		return "", fmt.Errorf("7z not found (brew install p7zip)")
	}
	tree, err := os.MkdirTemp("", "gotegra-flashpkg-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tree)
	cmd := exec.Command(sevenZ, "x", "-y", "-o"+tree, in, "-x!lost+found", "-x![SYS]")
	if o, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("7z x %s: %v\n%s", in, err, o)
	}
	seqPath := filepath.Join(tree, "flashpkg", "conf", "command_sequence")
	data, err := os.ReadFile(seqPath)
	if err != nil {
		return "", fmt.Errorf("%s has no flashpkg/conf/command_sequence: %w", in, err)
	}
	seq := edit(string(data))
	if err := os.WriteFile(seqPath, []byte(seq), 0o644); err != nil {
		return "", err
	}
	// 7z extracts with the current umask; the agent only reads, but keep the
	// tree world-readable like ci/flashpack.sh's staging does.
	filepath.Walk(tree, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			if info.IsDir() {
				os.Chmod(p, 0o755)
			} else {
				os.Chmod(p, 0o644)
			}
		}
		return nil
	})
	if err := ensureAgentDirs(tree); err != nil {
		return "", err
	}
	if err := buildFlashpkgFromTree(tree, out); err != nil {
		return "", err
	}
	return seq, nil
}

// ensureAgentDirs adds what the device-side agent assumes is already in the
// package because NVIDIA's host adds its files to the device's own tree
// (get_flash_package: mkdir -p flashpkg/logs; a PENDING status). Every verb
// redirects its output to flashpkg/logs/<verb>.log; without that directory the
// redirect fails, so export-devices fails at once and a backgrounded
// `bootloader` never writes /run/bootloader-status and the agent waits for it
// forever — no LUN, no status, nothing on USB (diagnosed 2026-11-09 after four
// silent runs).
func ensureAgentDirs(tree string) error {
	if err := os.MkdirAll(filepath.Join(tree, "flashpkg", "logs"), 0o777); err != nil {
		return err
	}
	st := filepath.Join(tree, "flashpkg", "status")
	if _, err := os.Stat(st); err != nil {
		if err := os.WriteFile(st, []byte("PENDING: expecting command sequence from host\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LintFlashpkg checks a flash package for what the agent needs and returns the
// problems found (nil = fine). Needs 7z.
func LintFlashpkg(img string) ([]string, error) {
	sevenZ, err := exec.LookPath("7z")
	if err != nil {
		return nil, fmt.Errorf("7z not found (brew install p7zip)")
	}
	out, err := exec.Command(sevenZ, "l", "-slt", img).Output()
	if err != nil {
		return nil, fmt.Errorf("7z l %s: %w", img, err)
	}
	have := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Path = ") {
			have[strings.TrimPrefix(line, "Path = ")] = true
		}
	}
	var problems []string
	if !have["flashpkg/conf/command_sequence"] {
		problems = append(problems, "missing flashpkg/conf/command_sequence (the agent does nothing and reports FAILED)")
	}
	if !have["flashpkg/logs"] {
		problems = append(problems, "missing flashpkg/logs/ directory: every agent step redirects into it; export-devices fails at once and a leading `bootloader` hangs the agent forever")
	}
	seq, err := ReadFlashpkgSequence(img)
	if err == nil && ParseSequence(seq).Bootloader {
		missing := false
		for _, f := range []string{"flashpkg/bootloader/boot_device_type", "flashpkg/bootloader/partitions.conf"} {
			if !have[f] {
				missing = true
				problems = append(problems, "sequence has `bootloader` but "+f+" is missing (program-boot-device fails safe, QSPI untouched)")
			}
		}
		if !missing {
			p, err := lintBootChain(sevenZ, img)
			if err != nil {
				return nil, err
			}
			problems = append(problems, p...)
		}
	}
	return problems, nil
}

// lintBootChain checks the QSPI payload for the defect that makes a box leave
// RCM and die before UEFI: an MB1 cold-boot BCT with no firmware locations.
func lintBootChain(sevenZ, img string) ([]string, error) {
	dir, err := os.MkdirTemp("", "gotegra-lint-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	extract := func(name string) ([]byte, error) {
		cmd := exec.Command(sevenZ, "x", "-y", "-o"+dir, img, "flashpkg/bootloader/"+name)
		if o, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("7z x %s: %v\n%s", img, err, o)
		}
		return os.ReadFile(filepath.Join(dir, "flashpkg", "bootloader", name))
	}
	conf, err := extract("partitions.conf")
	if err != nil {
		return nil, err
	}
	return checkMB1BCT(string(conf), extract), nil
}

// checkMB1BCT verifies that the MB1 cold-boot BCT named by partitions.conf
// (lines of name:start:size:file) carries the QSPI location of the slot-A
// MEM_BCT and MB2 partitions. tegrabct_v2 stores each as a little-endian
// {u32 start sector, u32 byte size}; MB1 loads the next stages from them. A BCT
// generated against a layout without the boot partitions — the top-level one
// NVIDIA's external-device sign pass leaves behind — has none, and a QSPI
// programmed with it never reaches UEFI. Layouts without an A_MB1_BCT partition
// are not checked.
func checkMB1BCT(partitionsConf string, read func(name string) ([]byte, error)) []string {
	type part struct {
		start, size int64
		file        string
	}
	parts := map[string]part{}
	for _, line := range strings.Split(partitionsConf, "\n") {
		f := strings.SplitN(strings.TrimSpace(line), ":", 4)
		if len(f) < 4 {
			continue
		}
		start, e1 := strconv.ParseInt(f[1], 10, 64)
		size, e2 := strconv.ParseInt(f[2], 10, 64)
		if e1 == nil && e2 == nil {
			parts[f[0]] = part{start, size, f[3]}
		}
	}
	bctPart, ok := parts["A_MB1_BCT"]
	if !ok || bctPart.file == "" {
		return nil
	}
	bct, err := read(bctPart.file)
	if err != nil {
		return []string{"partitions.conf names " + bctPart.file + " for A_MB1_BCT but it cannot be read: " + err.Error()}
	}
	var absent []string
	for _, name := range []string{"A_MEM_BCT", "A_mb2"} {
		p, ok := parts[name]
		if !ok {
			continue
		}
		var entry [8]byte
		binary.LittleEndian.PutUint32(entry[:4], uint32(p.start/512))
		binary.LittleEndian.PutUint32(entry[4:], uint32(p.size))
		if !bytes.Contains(bct, entry[:]) {
			absent = append(absent, name)
		}
	}
	if len(absent) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("the MB1 cold-boot BCT (%s) has no location for %s: MB1 could not load the next boot stage and the box would never reach UEFI (BCT built against a layout without the QSPI boot partitions)",
		bctPart.file, strings.Join(absent, ", "))}
}
