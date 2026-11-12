// Command gotegra drives an NVIDIA Tegra SoC in RCM (recovery) mode over native
// USB (libusb via purego, no cgo) — the USB side of NVIDIA's tegrarcm_v2 for the
// T234 (Orin) path, reimplemented so it runs anywhere libusb does, with no VM.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/levitree/gotegra"
)

// command is one gotegra subcommand.
type command struct {
	name  string
	args  string // argument synopsis for the usage line
	short string // one-line description
	long  string // extra help text (optional)
	root  bool   // reads or writes the raw LUNs: needs root on macOS
	run   func(args []string) error
}

// errUsage makes main print the command's usage and exit 2.
var errUsage = errors.New("usage")

// groups is the command table, in help order.
var groups = []struct {
	title    string
	commands []command
}{
	{"Flash a device in recovery mode (run with sudo)", []command{
		{name: "flashall", args: "[-no-erase] [-rootfs name] <flashpack-dir> | <rcmboot-dir> <flashpkg.img> <parts-dir>",
			short: "the whole flash: RCM boot, QSPI, every NVMe partition, final status",
			long: `A flashpack directory holds rcmboot/, flashpkg.img and flashparts/ (flash.idx,
partition images, and the rootfs extracted from its .tar.zst). The three-path
form mixes pieces, e.g. known-good RCM blobs with a new package.
-no-erase drops a package's erase-nvme step (a whole-drive discard); the rootfs
write does not need a zeroed drive.`,
			root: true, run: cmdFlashAll},
		{name: "flashqspi", args: "<flashpack-dir> | <rcmboot-dir> <flashpkg.img>",
			short: "program only the QSPI boot flash; the NVMe is not touched",
			long:  "Any flash package works: its NVMe export/erase steps are dropped for this run.",
			root:  true, run: cmdFlashQspi},
		{name: "probe-nvme", args: "<flashpack-dir> | <rcmboot-dir> [flashpkg.img]",
			short: "non-destructive: boot the agent and check that it exports the NVMe",
			long:  "With a package given the probe is derived from it, so mounting it is tested too.",
			root:  true, run: cmdProbeNvme},
	}},
	{"Pick up or inspect a run in progress (run with sudo)", []command{
		{name: "resume", args: "[-rootfs name] <parts-dir>",
			short: "continue from the nvme stage after a run stopped while the device was busy",
			root:  true, run: cmdResume},
		{name: "status", short: "release a still-exported nvme LUN, then print the device's status and logs",
			root: true, run: func(args []string) error {
				if len(args) != 0 {
					return errUsage
				}
				return gotegra.CaptureStatus()
			}},
		{name: "flashparts", args: "[-no-erase] [-rootfs name] <flashpkg.img> <parts-dir>",
			short: "flashall without the RCM boot (agent already started with flashboot)",
			root:  true, run: cmdFlashParts},
		{name: "run-pkg", args: "[-parts dir] [-rootfs name] <rcmboot-dir> <flashpkg.img>",
			short: "run a package exactly as written, waiting for the RCM device first",
			long: `Follows the package's own sequence: the nvme LUN is written from -parts or
released unwritten, the status is checked, and after "reboot forced-recovery"
it waits for the box to return to RCM.`,
			root: true, run: cmdRunPkg},
	}},
	{"Flash packages (no device needed)", []command{
		{name: "pkg-show", args: "<flashpkg.img>",
			short: "print a package's command sequence and check it would work on the device",
			run:   cmdPkgShow},
		{name: "pkg-seq", args: "<flashpkg.img> <out.img> '<verb>;<verb>...'",
			short: "copy a package with a new command sequence",
			long:  "e.g. gotegra pkg-seq in.img out.img 'export-devices nvme0n1;bootloader;reboot'",
			run:   cmdPkgSeq},
		{name: "pkg-drop", args: "<flashpkg.img> <out.img> <verb>...",
			short: "copy a package with the given verbs removed", run: cmdPkgDrop},
	}},
	{"RCM primitives (device in recovery mode, 0955:7323)", []command{
		{name: "uid", short: "read BR_CID and decode the fuse / secure-boot state", run: cmdUID},
		{name: "flashboot", args: "<rcmboot-dir>", short: "RCM-boot the flashing kernel (blob.bin) and stop", run: cmdFlashBoot},
		{name: "applet-boot", args: "<blob-dir>", short: "RCM-boot to the mb2 applet in one session", run: cmdAppletBoot},
		{name: "rcmboot", args: "<blob>...", short: "send the given signed blobs to the bootrom, in order", run: cmdRcmBoot},
		{name: "applet", args: "<applet-blob>", short: "poll the bootloader, then download the applet", run: cmdApplet},
		{name: "mb2probe", short: "query a running mb2 applet over the 3p protocol", run: cmdMb2Probe},
		{name: "reboot", args: "[recovery|coldboot]", short: "ask a running mb2 applet to reboot (default recovery)", run: cmdReboot},
	}},
	{"Burn fuses — IRREVERSIBLE (device in recovery mode)", []command{
		{name: "burnfuses", args: "[-burn] [-yes] <fuse-blob-dir>   |   -via-applet [-burn] <fuse-blob.bin>",
			short: "FSKP fuse burn (T234/Orin); dry run unless -burn",
			long: `gotegra only transports the already-signed fuse blob built offline by
odmfuse/tegraparser/tegrasign_v3; it never signs. Dry run by default (no device
needed); -burn performs the IRREVERSIBLE burn after a typed confirmation (-yes
skips it). -via-applet sends "--oem burnfuses <blob>" to a running mb2_applet
over the 3p protocol instead of the FSKP RCM session.`,
			run: cmdBurnFuses},
	}},
}

func lookup(name string) *command {
	for _, g := range groups {
		for i := range g.commands {
			if g.commands[i].name == name {
				return &g.commands[i]
			}
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name, args := os.Args[1], os.Args[2:]
	if name == "fuse" {
		name = "burnfuses"
	}
	switch name {
	case "-h", "--help", "help":
		if len(args) > 0 {
			if c := lookup(args[0]); c != nil {
				c.usage()
				return
			}
		}
		usage()
		return
	}
	c := lookup(name)
	if c == nil {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", name)
		usage()
		os.Exit(2)
	}
	for _, a := range args {
		if a == "-h" || a == "--help" {
			c.usage()
			return
		}
	}
	// Fail before touching the device: /dev/rdiskN is root-only on macOS, and
	// discovering that after the RCM boot would leave the box sitting in the agent.
	if c.root && runtime.GOOS == "darwin" && os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "error: %s needs root for raw disk access — run it with sudo\n", c.name)
		os.Exit(1)
	}
	err := c.run(args)
	if errors.Is(err, errUsage) {
		c.usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func (c *command) usage() {
	fmt.Fprintf(os.Stderr, "usage: gotegra %s", c.name)
	if c.args != "" {
		fmt.Fprintf(os.Stderr, " %s", c.args)
	}
	fmt.Fprintf(os.Stderr, "\n\n%s\n", c.short)
	if c.long != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", c.long)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, "gotegra - native NVIDIA Tegra RCM + flash over libusb (T234/Orin)\n")
	for _, g := range groups {
		fmt.Fprintf(os.Stderr, "\n%s:\n", g.title)
		for _, c := range g.commands {
			fmt.Fprintf(os.Stderr, "  %-12s %s\n", c.name, c.short)
		}
	}
	fmt.Fprint(os.Stderr, `
"gotegra help <command>" shows a command's arguments. Flashing is macOS-only.
GOTEGRA_ANY_LUN=1 accepts any external USB disk of the right size as the
flashing LUN (normally LUNs are matched by their "flashpkg"/"nvme0n1" name).
`)
}

// flashFlags parses the options shared by the flashing commands and returns the
// positional arguments. A nil pointer leaves that flag undefined.
func flashFlags(args []string, noErase *bool, rootfs, parts *string) ([]string, error) {
	fs := flag.NewFlagSet("gotegra", flag.ContinueOnError)
	fs.Usage = func() {}
	if noErase != nil {
		fs.BoolVar(noErase, "no-erase", false, "")
	}
	if rootfs != nil {
		fs.StringVar(rootfs, "rootfs", "", "")
	}
	if parts != nil {
		fs.StringVar(parts, "parts", "", "")
	}
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return nil, errUsage
	}
	return fs.Args(), nil
}

// flashpack is the directory layout luka-firmware's ci/flashpack.sh produces.
type flashpack struct{ rcmboot, pkg, parts string }

// openFlashpack accepts a flashpack directory, or the directory above it (a CI
// artifact unpacks as <dir>/flashpack + manifest.json).
func openFlashpack(dir string) (flashpack, error) {
	for _, d := range []string{dir, filepath.Join(dir, "flashpack")} {
		fp := flashpack{filepath.Join(d, "rcmboot"), filepath.Join(d, "flashpkg.img"), filepath.Join(d, "flashparts")}
		if _, err := os.Stat(fp.pkg); err == nil {
			if st, err := os.Stat(fp.rcmboot); err != nil || !st.IsDir() {
				return fp, fmt.Errorf("%s has flashpkg.img but no rcmboot/ directory", d)
			}
			return fp, nil
		}
	}
	return flashpack{}, fmt.Errorf("%s is not a flashpack directory (no flashpkg.img)", dir)
}

func cmdFlashAll(args []string) error {
	var o gotegra.FlashOptions
	var rootfs string
	args, err := flashFlags(args, &o.NoErase, &rootfs, nil)
	if err != nil {
		return err
	}
	switch len(args) {
	case 1:
		fp, err := openFlashpack(args[0])
		if err != nil {
			return err
		}
		return gotegra.FlashAllWith(fp.rcmboot, fp.pkg, fp.parts, rootfs, o)
	case 3:
		return gotegra.FlashAllWith(args[0], args[1], args[2], rootfs, o)
	}
	return errUsage
}

func cmdFlashQspi(args []string) error {
	switch len(args) {
	case 1:
		fp, err := openFlashpack(args[0])
		if err != nil {
			return err
		}
		return gotegra.FlashQspi(fp.rcmboot, fp.pkg)
	case 2:
		return gotegra.FlashQspi(args[0], args[1])
	}
	return errUsage
}

func cmdProbeNvme(args []string) error {
	switch len(args) {
	case 1:
		// A flashpack directory, or a bare rcmboot directory (minimal probe package).
		if fp, err := openFlashpack(args[0]); err == nil {
			return gotegra.ProbeNvme(fp.rcmboot, fp.pkg)
		}
		return gotegra.ProbeNvme(args[0], "")
	case 2:
		return gotegra.ProbeNvme(args[0], args[1])
	}
	return errUsage
}

func cmdResume(args []string) error {
	var rootfs string
	args, err := flashFlags(args, nil, &rootfs, nil)
	if err != nil {
		return err
	}
	if len(args) != 1 {
		return errUsage
	}
	return gotegra.FlashResumeParts(args[0], rootfs)
}

func cmdFlashParts(args []string) error {
	var o gotegra.FlashOptions
	var rootfs string
	args, err := flashFlags(args, &o.NoErase, &rootfs, nil)
	if err != nil {
		return err
	}
	if len(args) != 2 {
		return errUsage
	}
	return gotegra.FlashWritePartsWith(args[0], args[1], rootfs, o)
}

func cmdRunPkg(args []string) error {
	var o gotegra.RunPkgOptions
	args, err := flashFlags(args, nil, &o.RootfsName, &o.PartsDir)
	if err != nil {
		return err
	}
	if len(args) != 2 {
		return errUsage
	}
	return gotegra.RunPkg(args[0], args[1], o)
}

func cmdPkgShow(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	seq, err := gotegra.ReadFlashpkgSequence(args[0])
	if err != nil {
		return err
	}
	si := gotegra.ParseSequence(seq)
	fmt.Printf("%s command sequence:\n%s", args[0], seq)
	fmt.Printf("programs QSPI: %v, exports nvme: %v, erases nvme: %v, forced-recovery: %v\n",
		si.Bootloader, si.ExportsNvme, si.ErasesNvme, si.ForcedRecovery)
	problems, err := gotegra.LintFlashpkg(args[0])
	if err != nil {
		return err
	}
	if len(problems) == 0 {
		fmt.Println("lint: OK")
		return nil
	}
	for _, p := range problems {
		fmt.Println("lint: PROBLEM:", p)
	}
	return fmt.Errorf("package would not work on the device")
}

func cmdPkgSeq(args []string) error {
	if len(args) < 3 {
		return errUsage
	}
	seq, err := gotegra.RewriteFlashpkgSequence(args[0], args[1], strings.Join(args[2:], ";"))
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s; command sequence:\n%s", args[1], seq)
	return nil
}

func cmdPkgDrop(args []string) error {
	if len(args) < 3 {
		return errUsage
	}
	seq, err := gotegra.RewriteFlashpkg(args[0], args[1], args[2:]...)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s; command sequence:\n%s", args[1], seq)
	return nil
}

// withDevice opens the RCM device for one command.
func withDevice(fn func(d *gotegra.Device) error) error {
	d, err := gotegra.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	return fn(d)
}

func cmdUID(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	return withDevice(func(d *gotegra.Device) error {
		cid, raw, err := d.ReadBRCID()
		if err != nil {
			return err
		}
		fmt.Printf("BR_CID: %s\n", cid)
		fmt.Printf("raw descriptor: %x\n", raw)
		if auth, ok := gotegra.DecodeFuseState(cid); ok {
			fmt.Printf("fuse/secure-boot: %s\n", auth)
		}
		return nil
	})
}

func cmdFlashBoot(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	bootBlobs, postBlobs, err := gotegra.ResolveFlashBootBlobs(args[0])
	if err != nil {
		return err
	}
	return withDevice(func(d *gotegra.Device) error { return d.FlashBoot(bootBlobs, postBlobs) })
}

func cmdAppletBoot(args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	bootBlobs, applet, err := gotegra.ResolveRcmBlobs(args[0])
	if err != nil {
		return err
	}
	return withDevice(func(d *gotegra.Device) error { return d.FullRcmBoot(bootBlobs, applet) })
}

func cmdRcmBoot(files []string) error {
	if len(files) == 0 {
		return errUsage
	}
	return withDevice(func(d *gotegra.Device) error {
		if cid, _, err := d.ReadBRCID(); err == nil {
			fmt.Printf("BR_CID: %s\n", cid)
		}
		return d.RcmBoot(files)
	})
}

func cmdApplet(files []string) error {
	if len(files) != 1 {
		return errUsage
	}
	return withDevice(func(d *gotegra.Device) error {
		ver, lastErr, err := d.PollBootloader()
		if err != nil {
			return fmt.Errorf("pollbl: %w", err)
		}
		fmt.Printf("BL: version %q last_boot_error=%d\n", ver, lastErr)
		return d.RcmBoot(files)
	})
}

func cmdMb2Probe(args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	return withDevice(func(d *gotegra.Device) error { return d.Mb2Probe() })
}

// cmdBurnFuses implements `gotegra burnfuses` (alias `fuse`): the FSKP fuse-burn
// RCM session for T234/Orin, or the generic `--oem burnfuses` applet path with
// -via-applet. Dry run by default; -burn performs the IRREVERSIBLE burn.
func cmdBurnFuses(args []string) error {
	fs := flag.NewFlagSet("burnfuses", flag.ContinueOnError)
	burn := fs.Bool("burn", false, "actually burn the fuses (IRREVERSIBLE); omit for a dry run")
	yes := fs.Bool("yes", false, "skip the interactive confirmation (only with -burn)")
	viaApplet := fs.Bool("via-applet", false, "send `--oem burnfuses <fuse-blob>` to a running mb2_applet over 3p (arg is a fuse-blob file) instead of the FSKP RCM session (arg is a blob dir)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "usage: gotegra burnfuses [-burn] [-yes] <fuse-blob-dir>\n"+
			"       gotegra burnfuses -via-applet [-burn] [-yes] <fuse-blob.bin>\n\n"+
			"Burns T234/Orin fuses via FSKP. gotegra only transports the already-signed\n"+
			"blob produced offline by odmfuse/tegraparser/tegrasign_v3; it never signs.\n"+
			"Fuse burning is IRREVERSIBLE: dry run is the default, -burn performs the burn.\n")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one path argument")
	}
	if *viaApplet {
		return burnFusesApplet(rest[0], *burn, *yes)
	}
	return burnFusesFSKP(rest[0], *burn, *yes)
}

func burnFusesFSKP(dir string, burn, yes bool) error {
	bootBlobs, postBlobs, err := gotegra.ResolveFuseBlobs(dir)
	if err != nil {
		return err
	}
	plan, err := gotegra.BuildFSKPBurnPlan(bootBlobs, postBlobs)
	if err != nil {
		return err
	}
	fmt.Print(plan.String())
	if !burn {
		fmt.Println("\nDRY RUN — no USB I/O performed. Re-run with -burn to burn (IRREVERSIBLE).")
		return nil
	}
	d, err := openAndConfirm("FSKP fuse burn", yes)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.BurnFusesFSKP(plan)
}

func burnFusesApplet(blobPath string, burn, yes bool) error {
	data, err := os.ReadFile(blobPath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("fuse blob %s is empty", blobPath)
	}
	fmt.Printf("Applet --oem burnfuses (3p) for %s (%d bytes):\n", filepath.Base(blobPath), len(data))
	fmt.Println("  1. type-1 command packet: payload [opcode 6 = OEM][oem cmd 6 = burnfuses]")
	fmt.Println("  2. type-2 data packet:    the signed fuse blob")
	fmt.Println("  3. read the device status packet (opcode 8; 0 = success)")
	if !burn {
		fmt.Println("\nDRY RUN — no USB I/O performed. Re-run with -burn to burn (IRREVERSIBLE).")
		return nil
	}
	d, err := openAndConfirm("applet --oem burnfuses", yes)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.BurnFusesApplet(data)
}

// openAndConfirm opens the device, prints its BR_CID and current fuse /
// secure-boot state so the operator can see exactly which chip (by CID/ECID) and
// what it is today, then asks for an irreversible-burn confirmation. It returns
// the open device only on an explicit "BURN" (or -yes), and closes it otherwise.
func openAndConfirm(what string, yes bool) (*gotegra.Device, error) {
	d, err := gotegra.Open()
	if err != nil {
		return nil, err
	}
	cid, _, err := d.ReadBRCID()
	if err != nil {
		d.Close()
		return nil, fmt.Errorf("read BR_CID: %w", err)
	}
	fmt.Printf("device BR_CID: %s\n", cid)
	if st, ok := gotegra.DecodeFuseState(cid); ok {
		fmt.Printf("current fuse/secure-boot state: %s\n", st)
	}
	if !yes && !confirmBurn(what) {
		d.Close()
		return nil, fmt.Errorf("aborted")
	}
	return d, nil
}

// confirmBurn asks the operator to type BURN on stdin before an irreversible burn.
func confirmBurn(what string) bool {
	fmt.Fprintf(os.Stderr, "\n*** WARNING: %s is IRREVERSIBLE and can permanently brick the device. ***\n", what)
	fmt.Fprint(os.Stderr, "Type BURN to proceed: ")
	var in string
	fmt.Scanln(&in)
	return in == "BURN"
}

func cmdReboot(args []string) error {
	mode := "recovery"
	if len(args) == 1 {
		mode = args[0]
	}
	if len(args) > 1 || (mode != "recovery" && mode != "coldboot") {
		return errUsage
	}
	return withDevice(func(d *gotegra.Device) error { return d.RebootTo(mode == "recovery") })
}
