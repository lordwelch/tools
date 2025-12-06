// Package packer builds and deploys a gokrazy image. Called from the old
// gokr-packer binary and the new gok binary.
package packer

import (
	"archive/tar"
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gokrazy/internal/config"
	"github.com/gokrazy/internal/deviceconfig"
	"github.com/gokrazy/internal/updateflag"
	"github.com/gokrazy/tools/internal/log"
	"github.com/gokrazy/tools/packer"
)

type contextKey int

var BuildTimestampOverride contextKey

const MB = 1024 * 1024

type filePathAndModTime struct {
	path    string
	modTime time.Time
}

func findPackageFiles(fileType string) ([]filePathAndModTime, error) {
	var packageFilePaths []filePathAndModTime
	err := filepath.Walk(fileType, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info != nil && !info.Mode().IsRegular() {
			return nil
		}
		if strings.HasSuffix(path, fmt.Sprintf("/%s.txt", fileType)) {
			packageFilePaths = append(packageFilePaths, filePathAndModTime{
				path:    path,
				modTime: info.ModTime(),
			})
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no fileType directory found
		}
	}

	return packageFilePaths, nil
}

type packageConfigFile struct {
	kind         string
	path         string
	lastModified time.Time
}

// packageConfigFiles is a map from package path to packageConfigFile, for constructing output that is keyed per package
var packageConfigFiles = make(map[string][]packageConfigFile)

func buildPackageMapFromFlags(cfg *config.Struct) map[string]bool {
	buildPackages := make(map[string]bool)
	for _, pkg := range cfg.Packages {
		buildPackages[pkg] = true
	}
	for _, pkg := range cfg.GokrazyPackagesOrDefault() {
		if strings.TrimSpace(pkg) == "" {
			continue
		}
		buildPackages[pkg] = true
	}
	return buildPackages
}

func buildPackagesFromFlags(cfg *config.Struct) []string {
	var buildPackages []string
	buildPackages = append(buildPackages, cfg.Packages...)
	buildPackages = append(buildPackages, getGokrazySystemPackages(cfg)...)
	return buildPackages
}

func (pack *Pack) findFlagFiles(cfg *config.Struct) (map[string][]string, error) {
	log := pack.Env.Logger()

	if len(cfg.PackageConfig) > 0 {
		contents := make(map[string][]string)
		for pkg, packageConfig := range cfg.PackageConfig {
			if len(packageConfig.CommandLineFlags) == 0 {
				continue
			}
			contents[pkg] = packageConfig.CommandLineFlags
			packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
				kind:         "be started with command-line flags",
				path:         cfg.Meta.Path,
				lastModified: cfg.Meta.LastModified,
			})
		}
		return contents, nil
	}

	flagFilePaths, err := findPackageFiles("flags")
	if err != nil {
		return nil, err
	}

	if len(flagFilePaths) == 0 {
		return nil, nil // no flags.txt files found
	}

	buildPackages := buildPackageMapFromFlags(cfg)

	contents := make(map[string][]string)
	for _, p := range flagFilePaths {
		pkg := strings.TrimSuffix(strings.TrimPrefix(p.path, "flags/"), "/flags.txt")
		if !buildPackages[pkg] {
			log.Printf("WARNING: flag file %s does not match any specified package (%s)", pkg, cfg.Packages)
			continue
		}
		packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
			kind:         "be started with command-line flags",
			path:         p.path,
			lastModified: p.modTime,
		})

		b, err := os.ReadFile(p.path)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		contents[pkg] = lines
	}

	return contents, nil
}

func (pack *Pack) findBuildFlagsFiles(cfg *config.Struct) (map[string][]string, error) {
	log := pack.Env.Logger()

	if len(cfg.PackageConfig) > 0 {
		contents := make(map[string][]string)
		for pkg, packageConfig := range cfg.PackageConfig {
			if len(packageConfig.GoBuildFlags) == 0 {
				continue
			}
			contents[pkg] = packageConfig.GoBuildFlags
			packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
				kind:         "be compiled with build flags",
				path:         cfg.Meta.Path,
				lastModified: cfg.Meta.LastModified,
			})
		}
		return contents, nil
	}

	buildFlagsFilePaths, err := findPackageFiles("buildflags")
	if err != nil {
		return nil, err
	}

	if len(buildFlagsFilePaths) == 0 {
		return nil, nil // no flags.txt files found
	}

	buildPackages := buildPackageMapFromFlags(cfg)

	contents := make(map[string][]string)
	for _, p := range buildFlagsFilePaths {
		pkg := strings.TrimSuffix(strings.TrimPrefix(p.path, "buildflags/"), "/buildflags.txt")
		if !buildPackages[pkg] {
			log.Printf("WARNING: buildflags file %s does not match any specified package (%s)", pkg, cfg.Packages)
			continue
		}
		packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
			kind:         "be compiled with build flags",
			path:         p.path,
			lastModified: p.modTime,
		})

		b, err := os.ReadFile(p.path)
		if err != nil {
			return nil, err
		}

		var buildFlags []string
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			if flag := sc.Text(); flag != "" {
				buildFlags = append(buildFlags, flag)
			}
		}

		if err := sc.Err(); err != nil {
			return nil, err
		}

		// use full package path opposed to flags
		contents[pkg] = buildFlags
	}

	return contents, nil
}

func findBuildEnv(cfg *config.Struct) (map[string][]string, error) {
	contents := make(map[string][]string)
	for pkg, packageConfig := range cfg.PackageConfig {
		if len(packageConfig.GoBuildEnvironment) == 0 {
			continue
		}
		contents[pkg] = packageConfig.GoBuildEnvironment
		packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
			kind:         "be compiled with build environment variables",
			path:         cfg.Meta.Path,
			lastModified: cfg.Meta.LastModified,
		})
	}
	return contents, nil
}

func (pack *Pack) findBuildTagsFiles(cfg *config.Struct) (map[string][]string, error) {
	log := pack.Env.Logger()

	if len(cfg.PackageConfig) > 0 {
		contents := make(map[string][]string)
		for pkg, packageConfig := range cfg.PackageConfig {
			if len(packageConfig.GoBuildTags) == 0 {
				continue
			}
			contents[pkg] = packageConfig.GoBuildTags
			packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
				kind:         "be compiled with build tags",
				path:         cfg.Meta.Path,
				lastModified: cfg.Meta.LastModified,
			})
		}
		return contents, nil
	}

	buildTagsFiles, err := findPackageFiles("buildtags")
	if err != nil {
		return nil, err
	}

	if len(buildTagsFiles) == 0 {
		return nil, nil // no flags.txt files found
	}

	buildPackages := buildPackageMapFromFlags(cfg)

	contents := make(map[string][]string)
	for _, p := range buildTagsFiles {
		pkg := strings.TrimSuffix(strings.TrimPrefix(p.path, "buildtags/"), "/buildtags.txt")
		if !buildPackages[pkg] {
			log.Printf("WARNING: buildtags file %s does not match any specified package (%s)", pkg, cfg.Packages)
			continue
		}
		packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
			kind:         "be compiled with build tags",
			path:         p.path,
			lastModified: p.modTime,
		})

		b, err := os.ReadFile(p.path)
		if err != nil {
			return nil, err
		}

		var buildTags []string
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			if flag := sc.Text(); flag != "" {
				buildTags = append(buildTags, flag)
			}
		}

		if err := sc.Err(); err != nil {
			return nil, err
		}

		// use full package path opposed to flags
		contents[pkg] = buildTags
	}

	return contents, nil
}

func (pack *Pack) findEnvFiles(cfg *config.Struct) (map[string][]string, error) {
	log := pack.Env.Logger()

	if len(cfg.PackageConfig) > 0 {
		contents := make(map[string][]string)
		for pkg, packageConfig := range cfg.PackageConfig {
			if len(packageConfig.Environment) == 0 {
				continue
			}
			contents[pkg] = packageConfig.Environment
			packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
				kind:         "be started with environment variables",
				path:         cfg.Meta.Path,
				lastModified: cfg.Meta.LastModified,
			})
		}
		return contents, nil
	}

	buildFlagsFilePaths, err := findPackageFiles("env")
	if err != nil {
		return nil, err
	}

	if len(buildFlagsFilePaths) == 0 {
		return nil, nil // no flags.txt files found
	}

	buildPackages := buildPackageMapFromFlags(cfg)

	contents := make(map[string][]string)
	for _, p := range buildFlagsFilePaths {
		pkg := strings.TrimSuffix(strings.TrimPrefix(p.path, "env/"), "/env.txt")
		if !buildPackages[pkg] {
			log.Printf("WARNING: environment variable file %s does not match any specified package (%s)", pkg, cfg.Packages)
			continue
		}
		packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
			kind:         "be started with environment variables",
			path:         p.path,
			lastModified: p.modTime,
		})

		b, err := os.ReadFile(p.path)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		contents[pkg] = lines
	}

	return contents, nil
}

func addToFileInfo(parent *FileInfo, path string) (time.Time, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}

	var latestTime time.Time
	for _, entry := range entries {
		filename := entry.Name()
		// get existing file info
		var fi *FileInfo
		for _, ent := range parent.Dirents {
			if ent.Filename == filename {
				fi = ent
				break
			}
		}

		info, err := entry.Info()
		if err != nil {
			return time.Time{}, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			info, err = os.Stat(filepath.Join(path, filename))
			if err != nil {
				return time.Time{}, err
			}
		}

		if latestTime.Before(info.ModTime()) {
			latestTime = info.ModTime()
		}

		// or create if not exist
		if fi == nil {
			fi = &FileInfo{
				Filename: filename,
				Mode:     info.Mode(),
			}
			parent.Dirents = append(parent.Dirents, fi)
		} else {
			// file overwrite is not supported -> return error
			if !info.IsDir() || fi.FromHost != "" || fi.FromLiteral != "" {
				return time.Time{}, fmt.Errorf("file already exists in filesystem: %s", filepath.Join(path, filename))
			}
		}

		// add content
		if info.IsDir() {
			modTime, err := addToFileInfo(fi, filepath.Join(path, filename))
			if err != nil {
				return time.Time{}, err
			}
			if latestTime.Before(modTime) {
				latestTime = modTime
			}
		} else {
			fi.FromHost = filepath.Join(path, filename)
		}
	}

	return latestTime, nil
}

type archiveExtraction struct {
	dirs map[string]*FileInfo
}

func (ae *archiveExtraction) mkdirp(dir string) {
	if dir == "/" {
		// Special case to avoid strings.Split() returning a slice with the
		// empty string as only element, which would result in creating a
		// subdirectory of the root directory without a name.
		return
	}
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	parent := ae.dirs["."]
	for idx, part := range parts {
		path := strings.Join(parts[:1+idx], "/")
		if dir, ok := ae.dirs[path]; ok {
			parent = dir
			continue
		}
		subdir := &FileInfo{
			Filename: part,
		}
		parent.Dirents = append(parent.Dirents, subdir)
		ae.dirs[path] = subdir
		parent = subdir
	}
}

func (ae *archiveExtraction) extractArchive(path string) (time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	defer f.Close()
	rd := tar.NewReader(f)

	var latestTime time.Time
	for {
		header, err := rd.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return time.Time{}, err
		}

		// header.Name is e.g. usr/lib/aarch64-linux-gnu/xtables/libebt_mark.so
		// for files, but e.g. usr/lib/ (note the trailing /) for directories.
		filename := strings.TrimSuffix(header.Name, "/")

		fi := &FileInfo{
			Filename: filepath.Base(filename),
			Mode:     os.FileMode(header.Mode),
		}

		if latestTime.Before(header.ModTime) {
			latestTime = header.ModTime
		}

		dir := filepath.Dir(filename)
		// Create all directory elements. Archives can contain directory entries
		// without having entries for their parent, e.g. web/assets/fonts/ might
		// be the first entry in an archive.
		ae.mkdirp(dir)
		parent := ae.dirs[dir]
		parent.Dirents = append(parent.Dirents, fi)

		switch header.Typeflag {
		case tar.TypeSymlink:
			fi.SymlinkDest = header.Linkname

		case tar.TypeDir:
			ae.dirs[filename] = fi

		default:
			// TODO(optimization): do not hold file data in memory, instead
			// stream the archive contents lazily to conserve RAM
			b, err := io.ReadAll(rd)
			if err != nil {
				return time.Time{}, err
			}
			fi.FromLiteral = string(b)
		}
	}

	return latestTime, nil
}

// findExtraFilesInDir probes for extrafiles .tar files (possibly with an
// architecture suffix like _amd64), or whether dir itself exists.
func findExtraFilesInDir(dir string) (string, error) {
	targetArch := packer.TargetArch()

	var err error
	for _, p := range []string{
		dir + "_" + targetArch + ".tar",
		dir + ".tar",
		dir,
	} {
		_, err = os.Stat(p)
		if err == nil {
			return p, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
	return "", err // return last error
}

// TODO(cleanup): It would be nice to de-duplicate the path resolution logic
// between findExtraFilesInDir and addExtraFilesFromDir. Maybe
// findExtraFilesInDir could os.Open the file and pass the file handle to the
// caller. That would prevent any TOCTOU problems.
func addExtraFilesFromDir(pkg, dir string, fi *FileInfo) error {
	ae := archiveExtraction{
		dirs: make(map[string]*FileInfo),
	}
	ae.dirs["."] = fi // root

	targetArch := packer.TargetArch()

	effectivePath := dir + "_" + targetArch + ".tar"
	latestModTime, err := ae.extractArchive(effectivePath)
	if err != nil {
		return err
	}
	if len(fi.Dirents) == 0 {
		effectivePath = dir + ".tar"
		latestModTime, err = ae.extractArchive(effectivePath)
		if err != nil {
			return err
		}
	}
	if len(fi.Dirents) == 0 {
		effectivePath = dir
		latestModTime, err = addToFileInfo(fi, effectivePath)
		if err != nil {
			return err
		}
		if len(fi.Dirents) == 0 {
			return nil
		}
	}

	packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
		kind:         "include extra files in the root file system",
		path:         effectivePath,
		lastModified: latestModTime,
	})

	return nil
}

func mkdirp(root *FileInfo, dir string) *FileInfo {
	if dir == "/" {
		// Special case to avoid strings.Split() returning a slice with the
		// empty string as only element, which would result in creating a
		// subdirectory of the root directory without a name.
		return root
	}
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	parent := root
	for _, part := range parts {
		subdir := &FileInfo{
			Filename: part,
		}
		parent.Dirents = append(parent.Dirents, subdir)
		parent = subdir
	}
	return parent
}

func FindExtraFiles(cfg *config.Struct) (map[string][]*FileInfo, error) {
	extraFiles := make(map[string][]*FileInfo)
	if len(cfg.PackageConfig) > 0 {
		for pkg, packageConfig := range cfg.PackageConfig {
			var fileInfos []*FileInfo

			for dest, path := range packageConfig.ExtraFilePaths {
				root := &FileInfo{}
				if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
					var err error
					path, err = filepath.Abs(path)
					if err != nil {
						return nil, err
					}
					// Copy a file from the host
					dir := mkdirp(root, filepath.Dir(dest))
					dir.Dirents = append(dir.Dirents, &FileInfo{
						Filename: filepath.Base(dest),
						FromHost: path,
					})
					packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
						kind:         "include extra files in the root file system",
						path:         path,
						lastModified: st.ModTime(),
					})
				} else {
					// Check if the ExtraFilePaths entry refers to an extrafiles
					// .tar archive or an existing directory. If nothing can be
					// found, report the error so the user can fix their config.
					_, err := findExtraFilesInDir(path)
					if err != nil {
						return nil, fmt.Errorf("ExtraFilePaths of %s: %v", pkg, err)
					}
					// Copy a tarball or directory from the host
					dir := mkdirp(root, dest)
					if err := addExtraFilesFromDir(pkg, path, dir); err != nil {
						return nil, err
					}
				}

				fileInfos = append(fileInfos, root)
			}

			for dest, contents := range packageConfig.ExtraFileContents {
				root := &FileInfo{}
				dir := mkdirp(root, filepath.Dir(dest))
				dir.Dirents = append(dir.Dirents, &FileInfo{
					Filename:    filepath.Base(dest),
					FromLiteral: contents,
				})
				packageConfigFiles[pkg] = append(packageConfigFiles[pkg], packageConfigFile{
					kind: "include extra files in the root file system",
				})
				fileInfos = append(fileInfos, root)
			}

			extraFiles[pkg] = fileInfos
		}
		// fall through to look for extra files in <pkg>/_gokrazy/extrafiles
	}

	buildPackages := buildPackagesFromFlags(cfg)
	packageDirs, err := packer.PackageDirs(buildPackages)
	if err != nil {
		return nil, err
	}
	for idx, pkg := range buildPackages {
		if len(cfg.PackageConfig) == 0 {
			// Look for extra files in $PWD/extrafiles/<pkg>/
			dir := filepath.Join("extrafiles", pkg)
			root := &FileInfo{}
			if err := addExtraFilesFromDir(pkg, dir, root); err != nil {
				return nil, err
			}
			extraFiles[pkg] = append(extraFiles[pkg], root)
		}
		{
			// Look for extra files in <pkg>/_gokrazy/extrafiles/
			dir := packageDirs[idx]
			subdir := filepath.Join(dir, "_gokrazy", "extrafiles")
			root := &FileInfo{}
			if err := addExtraFilesFromDir(pkg, subdir, root); err != nil {
				return nil, err
			}
			extraFiles[pkg] = append(extraFiles[pkg], root)
		}
	}

	return extraFiles, nil
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

type countingWriter int64

func (cw *countingWriter) Write(p []byte) (n int, err error) {
	*cw += countingWriter(len(p))
	return len(p), nil
}

func partitionPath(base, num string) string {
	if strings.HasPrefix(base, "/dev/mmcblk") ||
		strings.HasPrefix(base, "/dev/loop") {
		return base + "p" + num
	} else if strings.HasPrefix(base, "/dev/disk") ||
		strings.HasPrefix(base, "/dev/rdisk") {
		return base + "s" + num
	}
	return base + num
}

func verifyNotMounted(dev string) error {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		if os.IsNotExist(err) {
			return nil // platform does not have /proc/self/mountinfo, fall back to not verifying
		}
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.Split(line, " ")
		if len(parts) < 9 {
			continue
		}
		if strings.HasPrefix(parts[9], dev) {
			return fmt.Errorf("partition %s is mounted on %s", parts[9], parts[4])
		}
	}
	return nil
}

func (p *Pack) overwriteDevice(dev string, root *FileInfo, rootDeviceFiles []deviceconfig.RootFile) error {
	log := p.Env.Logger()

	if err := verifyNotMounted(dev); err != nil {
		return err
	}
	parttable := "GPT + Hybrid MBR"
	if !p.UseGPT {
		parttable = "no GPT, only MBR"
	}
	log.Printf("partitioning %s (%s)", dev, parttable)

	f, err := p.partition(p.Cfg.InternalCompatibilityFlags.Overwrite)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(p.FirstPartitionOffsetSectors*512, io.SeekStart); err != nil {
		return err
	}

	if err := p.writeBoot(f, ""); err != nil {
		return err
	}

	if err := p.writeMBR(p.FirstPartitionOffsetSectors, &offsetReadSeeker{f, p.FirstPartitionOffsetSectors * 512}, f, p.Partuuid); err != nil {
		return err
	}

	if _, err := f.Seek((p.FirstPartitionOffsetSectors+(100*MB/512))*512, io.SeekStart); err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "gokr-packer")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if err := p.writeRoot(tmp, root); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if _, err := io.Copy(f, tmp); err != nil {
		return err
	}

	if err := p.writeRootDeviceFiles(f, rootDeviceFiles); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	log.Printf("If your applications need to store persistent data, unplug and re-plug the SD card, then create a file system using e.g.:")
	log.Printf("")
	partition := partitionPath(dev, "4")
	if p.ModifyCmdlineRoot() {
		partition = fmt.Sprintf("/dev/disk/by-partuuid/%s", p.PermUUID())
	} else {
		if target, err := filepath.EvalSymlinks(dev); err == nil {
			partition = partitionPath(target, "4")
		}
	}
	log.Printf("\tmkfs.ext4 %s", partition)
	log.Printf("")

	return nil
}

type offsetReadSeeker struct {
	io.ReadSeeker
	offset int64
}

func (ors *offsetReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekStart {
		// github.com/gokrazy/internal/fat.Reader only uses io.SeekStart
		return ors.ReadSeeker.Seek(offset+ors.offset, io.SeekStart)
	}
	return ors.ReadSeeker.Seek(offset, whence)
}

func (p *Pack) overwriteFile(root *FileInfo, rootDeviceFiles []deviceconfig.RootFile, firstPartitionOffsetSectors int64) (bootSize int64, rootSize int64, err error) {
	log := p.Env.Logger()

	f, err := os.Create(p.Cfg.InternalCompatibilityFlags.Overwrite)
	if err != nil {
		return 0, 0, err
	}

	if err := f.Truncate(int64(p.Cfg.InternalCompatibilityFlags.TargetStorageBytes)); err != nil {
		return 0, 0, err
	}

	if err := p.Partition(f, uint64(p.Cfg.InternalCompatibilityFlags.TargetStorageBytes)); err != nil {
		return 0, 0, err
	}

	if _, err := f.Seek(p.FirstPartitionOffsetSectors*512, io.SeekStart); err != nil {
		return 0, 0, err
	}
	var bs countingWriter
	if err := p.writeBoot(io.MultiWriter(f, &bs), ""); err != nil {
		return 0, 0, err
	}

	if err := p.writeMBR(p.FirstPartitionOffsetSectors, &offsetReadSeeker{f, p.FirstPartitionOffsetSectors * 512}, f, p.Partuuid); err != nil {
		return 0, 0, err
	}

	if _, err := f.Seek(p.FirstPartitionOffsetSectors*512+100*MB, io.SeekStart); err != nil {
		return 0, 0, err
	}

	tmp, err := os.CreateTemp("", "gokr-packer")
	if err != nil {
		return 0, 0, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if err := p.writeRoot(tmp, root); err != nil {
		return 0, 0, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}

	var rs countingWriter
	if _, err := io.Copy(io.MultiWriter(f, &rs), tmp); err != nil {
		return 0, 0, err
	}

	if err := p.writeRootDeviceFiles(f, rootDeviceFiles); err != nil {
		return 0, 0, err
	}

	log.Printf("If your applications need to store persistent data, create a file system using e.g.:")
	log.Printf("\t/sbin/mkfs.ext4 -F -E offset=%v %s %v", p.FirstPartitionOffsetSectors*512+1100*MB, p.Cfg.InternalCompatibilityFlags.Overwrite, packer.PermSizeInKB(firstPartitionOffsetSectors, uint64(p.Cfg.InternalCompatibilityFlags.TargetStorageBytes)))
	log.Printf("")

	return int64(bs), int64(rs), f.Close()
}

type OutputType string

const (
	OutputTypeGaf  OutputType = "gaf"
	OutputTypeFull OutputType = "full"
)

type OutputStruct struct {
	Path string     `json:",omitempty"`
	Type OutputType `json:",omitempty"`
}

type Osenv struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	logger log.Logger
}

func (s *Osenv) initLogger() {
	if s.logger == nil {
		s.logger = log.New(s.Stderr)
	}
}

func (s *Osenv) Logger() log.Logger {
	s.initLogger()
	return s.logger
}

func (s *Osenv) Logf(format string, v ...any) {
	s.initLogger()
	s.logger.Printf(format, v...)
}

type Pack struct {
	packer.Pack

	// Everything Operating System environment related
	// like input/output channels to use (for logging).
	Env Osenv

	// FileCfg holds an untouched copy
	// of the config file, as it was read from disk.
	FileCfg *config.Struct
	Cfg     *config.Struct
	Output  *OutputStruct

	// state
	buildTimestamp              string
	rootDeviceFiles             []deviceconfig.RootFile
	firstPartitionOffsetSectors int64
	systemCertsPEM              string
	packageBuildFlags           map[string][]string
	packageBuildTags            map[string][]string
	packageBuildEnv             map[string][]string
	flagFileContents            map[string][]string
	envFileContents             map[string][]string
	dontStart                   map[string]bool
	waitForClock                map[string]bool
	basenames                   map[string]string
	schema                      string
	update                      *config.UpdateStruct
	root                        *FileInfo
	sbom                        []byte
	initTmp                     string
	kernelDir                   string
}

func filterGoEnv(env []string) []string {
	relevant := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "GOARCH=") ||
			strings.HasPrefix(kv, "GOOS=") ||
			strings.HasPrefix(kv, "CGO_ENABLED=") {
			relevant = append(relevant, kv)
		}
	}
	sort.Strings(relevant)
	return relevant
}

const programName = "gokrazy gok"

func (pack *Pack) logic(ctx context.Context, sbomHook func(marshaled []byte, withHash SBOMWithHash)) error {
	dnsCheck := make(chan error)
	go func() {
		defer close(dnsCheck)
		host, err := os.Hostname()
		if err != nil {
			dnsCheck <- fmt.Errorf("finding hostname: %v", err)
			return
		}
		if _, err := net.LookupHost(host); err != nil {
			dnsCheck <- err
			return
		}
		dnsCheck <- nil
	}()

	if err := pack.logicPrepare(ctx); err != nil {
		return err
	}

	bindir, err := os.MkdirTemp("", "gokrazy-bins-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(bindir)

	if err := pack.logicBuild(sbomHook, bindir); err != nil {
		return err
	}
	defer os.RemoveAll(pack.initTmp)

	if err := pack.logicWrite(dnsCheck); err != nil {
		return err
	}

	return nil
}

func (pack *Pack) printHowToInteract(cfg *config.Struct) error {
	log := pack.Env.Logger()
	update := pack.update // for convenience

	updateFlag := pack.Cfg.InternalCompatibilityFlags.Update
	if updateFlag == "" {
		updateFlag = "yes"
	}
	updateBaseUrl, err := updateflag.Value{
		Update: updateFlag,
	}.BaseURL(update.HTTPPort, update.HTTPSPort, pack.schema, update.Hostname, update.HTTPPassword)
	if err != nil {
		return err
	}

	log.Printf("")
	log.Printf("To interact with the device, gokrazy provides a web interface reachable at:")
	log.Printf("")
	log.Printf("\t%s", updateBaseUrl.String())
	log.Printf("")
	log.Printf("In addition, the following Linux consoles are set up:")
	log.Printf("")
	if cfg.SerialConsoleOrDefault() != "disabled" {
		log.Printf("\t1. foreground Linux console on the serial port (115200n8, pin 6, 8, 10 for GND, TX, RX), accepting input")
		log.Printf("\t2. secondary Linux framebuffer console on HDMI; shows Linux kernel message but no init system messages")
	} else {
		log.Printf("\t1. foreground Linux framebuffer console on HDMI")
	}

	if cfg.SerialConsoleOrDefault() != "disabled" {
		log.Printf("")
		log.Printf("Use -serial_console=disabled to make gokrazy not touch the serial port, and instead make the framebuffer console on HDMI the foreground console")
	}
	log.Printf("")
	if pack.schema == "https" {
		certObj, err := getCertificateFromString(update.CertPEM)
		if err != nil {
			return fmt.Errorf("error loading certificate: %v", err)
		} else {
			log.Printf("")
			log.Printf("The TLS Certificate of the gokrazy web interface is located under")
			log.Printf("\t%s", cfg.Meta.Path)
			log.Printf("The fingerprint of the Certificate is")
			log.Printf("\t%x", getCertificateFingerprintSHA1(certObj))
			log.Printf("The certificate is valid until")
			log.Printf("\t%s", certObj.NotAfter.String())
			log.Printf("Please verify the certificate, before adding an exception to your browser!")
		}
	}
	return nil
}

func (pack *Pack) Main(ctx context.Context) {
	if err := pack.logic(ctx, nil); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR:\n  %s\n", err)
		os.Exit(1)
	}
}

func (pack *Pack) GenerateSBOM(ctx context.Context) ([]byte, SBOMWithHash, error) {
	var sbom []byte
	var sbomWithHash SBOMWithHash
	if err := pack.logic(ctx, func(b []byte, wh SBOMWithHash) {
		sbom = b
		sbomWithHash = wh
	}); err != nil {
		return nil, SBOMWithHash{}, err
	}
	return sbom, sbomWithHash, nil
}
