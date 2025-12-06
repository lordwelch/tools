package packer

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gokrazy/internal/config"
	"github.com/gokrazy/internal/deviceconfig"
	"github.com/gokrazy/internal/tlsflag"
	"github.com/gokrazy/tools/internal/version"
	"github.com/gokrazy/tools/packer"
)

func (pack *Pack) logicPrepare(ctx context.Context) error {
	log := pack.Env.Logger()
	cfg := pack.Cfg
	tlsflag.SetInsecure(cfg.InternalCompatibilityFlags.Insecure)
	tlsflag.SetUseTLS(cfg.Update.UseTLS)

	if cfg.InternalCompatibilityFlags.Update != "" &&
		cfg.InternalCompatibilityFlags.Overwrite != "" {
		return fmt.Errorf("both -update and -overwrite are specified; use either one, not both")
	}

	// Check early on if the destination is a device that is mounted
	// so that the user does not get the impression that everything
	// is fine and about to complete after a lengthy build phase.
	// See also https://github.com/gokrazy/gokrazy/discussions/308
	switch {
	case cfg.InternalCompatibilityFlags.Overwrite != "" ||
		(pack.Output != nil && pack.Output.Type == OutputTypeFull && pack.Output.Path != ""):

		target := cfg.InternalCompatibilityFlags.Overwrite
		st, err := os.Stat(target)
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		if err == nil && st.Mode()&os.ModeDevice == os.ModeDevice {
			if err := verifyNotMounted(target); err != nil {
				return fmt.Errorf("cannot overwrite %s: %v (perhaps automatically?)\n  please unmount all partitions and retry", target, err)
			}
		}
	}

	var mbrOnlyWithoutGpt bool
	pack.firstPartitionOffsetSectors = deviceconfig.DefaultBootPartitionStartLBA
	if cfg.DeviceType != "" {
		if devcfg, ok := deviceconfig.GetDeviceConfigBySlug(cfg.DeviceType); ok {
			pack.rootDeviceFiles = devcfg.RootDeviceFiles
			mbrOnlyWithoutGpt = devcfg.MBROnlyWithoutGPT
			if devcfg.BootPartitionStartLBA != 0 {
				pack.firstPartitionOffsetSectors = devcfg.BootPartitionStartLBA
			}
		} else {
			return fmt.Errorf("unknown device slug %q", cfg.DeviceType)
		}
	}

	pack.Pack = packer.NewPackForHost(pack.firstPartitionOffsetSectors, cfg.Hostname)

	newInstallation := cfg.InternalCompatibilityFlags.Update == ""
	useGPT := newInstallation && !mbrOnlyWithoutGpt

	pack.Pack.UsePartuuid = newInstallation
	pack.Pack.UseGPTPartuuid = useGPT
	pack.Pack.UseGPT = useGPT

	if os.Getenv("GOKR_PACKER_FD") != "" { // partitioning child process
		if _, err := pack.SudoPartition(cfg.InternalCompatibilityFlags.Overwrite); err != nil {
			log.Printf("%s", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	log.Printf("%s %s on GOARCH=%s GOOS=%s",
		programName,
		version.ReadBrief(),
		runtime.GOARCH,
		runtime.GOOS)
	log.Printf("")

	if cfg.InternalCompatibilityFlags.Update != "" {
		// TODO: fix update URL:
		log.Printf("Updating gokrazy installation on http://%s", cfg.Hostname)
		log.Printf("")
	}

	log.Printf("Build target: %s", strings.Join(filterGoEnv(packer.Env()), " "))

	pack.buildTimestamp = time.Now().Format(time.RFC3339)
	if ts, ok := ctx.Value(BuildTimestampOverride).(string); ok {
		pack.buildTimestamp = ts
	}
	log.Printf("Build timestamp: %s", pack.buildTimestamp)

	systemCertsPEM, err := pack.findSystemCertsPEM()
	if err != nil {
		return err
	}
	pack.systemCertsPEM = systemCertsPEM

	packageBuildFlags, err := pack.findBuildFlagsFiles(cfg)
	if err != nil {
		return err
	}
	pack.packageBuildFlags = packageBuildFlags

	packageBuildTags, err := pack.findBuildTagsFiles(cfg)
	if err != nil {
		return err
	}
	pack.packageBuildTags = packageBuildTags

	packageBuildEnv, err := findBuildEnv(cfg)
	if err != nil {
		return err
	}
	pack.packageBuildEnv = packageBuildEnv

	flagFileContents, err := pack.findFlagFiles(cfg)
	if err != nil {
		return err
	}
	pack.flagFileContents = flagFileContents

	envFileContents, err := pack.findEnvFiles(cfg)
	if err != nil {
		return err
	}
	pack.envFileContents = envFileContents

	dontStart, err := pack.findDontStart(cfg)
	if err != nil {
		return err
	}
	pack.dontStart = dontStart

	waitForClock, err := pack.findWaitForClock(cfg)
	if err != nil {
		return err
	}
	pack.waitForClock = waitForClock

	basenames, err := findBasenames(cfg)
	if err != nil {
		return err
	}
	pack.basenames = basenames

	return nil
}

func (pack *Pack) findDontStart(cfg *config.Struct) (map[string]bool, error) {
	log := pack.Env.Logger()

	if len(cfg.PackageConfig) > 0 {
		contents := make(map[string]bool)
		for pkg, packageConfig := range cfg.PackageConfig {
			if !packageConfig.DontStart {
				continue
			}
			contents[pkg] = packageConfig.DontStart
			packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
				kind:         "not be started at boot",
				path:         cfg.Meta.Path,
				lastModified: cfg.Meta.LastModified,
			})
		}
		return contents, nil
	}

	dontStartPaths, err := findPackageFiles("dontstart")
	if err != nil {
		return nil, err
	}

	if len(dontStartPaths) == 0 {
		return nil, nil // no dontstart.txt files found
	}

	buildPackages := buildPackageMapFromFlags(cfg)

	contents := make(map[string]bool)
	for _, p := range dontStartPaths {
		pkg := strings.TrimSuffix(strings.TrimPrefix(p.path, "dontstart/"), "/dontstart.txt")
		if !buildPackages[pkg] {
			log.Printf("WARNING: dontstart.txt file %s does not match any specified package (%s)", pkg, cfg.Packages)
			continue
		}
		packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
			kind:         "not be started at boot",
			path:         p.path,
			lastModified: p.modTime,
		})

		contents[pkg] = true
	}

	return contents, nil
}

func (pack *Pack) findWaitForClock(cfg *config.Struct) (map[string]bool, error) {
	log := pack.Env.Logger()

	if len(cfg.PackageConfig) > 0 {
		contents := make(map[string]bool)
		for pkg, packageConfig := range cfg.PackageConfig {
			if !packageConfig.WaitForClock {
				continue
			}
			contents[pkg] = packageConfig.WaitForClock
			packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
				kind:         "wait for clock synchronization before start",
				path:         cfg.Meta.Path,
				lastModified: cfg.Meta.LastModified,
			})
		}
		return contents, nil
	}

	waitForClockPaths, err := findPackageFiles("waitforclock")
	if err != nil {
		return nil, err
	}

	if len(waitForClockPaths) == 0 {
		return nil, nil // no waitforclock.txt files found
	}

	buildPackages := buildPackageMapFromFlags(cfg)

	contents := make(map[string]bool)
	for _, p := range waitForClockPaths {
		pkg := strings.TrimSuffix(strings.TrimPrefix(p.path, "waitforclock/"), "/waitforclock.txt")
		if !buildPackages[pkg] {
			log.Printf("WARNING: waitforclock.txt file %s does not match any specified package (%s)", pkg, cfg.Packages)
			continue
		}
		packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
			kind:         "wait for clock synchronization before start",
			path:         p.path,
			lastModified: p.modTime,
		})

		contents[pkg] = true
	}

	return contents, nil
}

func findBasenames(cfg *config.Struct) (map[string]string, error) {
	contents := make(map[string]string)
	for pkg, packageConfig := range cfg.PackageConfig {
		if packageConfig.Basename == "" {
			continue
		}
		contents[pkg] = packageConfig.Basename
		packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
			kind: "be installed with the basename set to " + packageConfig.Basename,
		})
	}
	return contents, nil
}
