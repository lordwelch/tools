package packer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/trace"

	"github.com/gokrazy/internal/config"
	"github.com/gokrazy/internal/deviceconfig"
	"github.com/gokrazy/internal/httpclient"
	"github.com/gokrazy/internal/tlsflag"
	"github.com/gokrazy/internal/updateflag"
	"github.com/gokrazy/tools/internal/measure"
	"github.com/gokrazy/tools/packer"
	"github.com/gokrazy/updater"
)

func (pack *Pack) logicWrite(dnsCheck chan error) error {
	ctx := context.Background()
	log := pack.Env.Logger()

	var (
		updateHttpClient         *http.Client
		foundMatchingCertificate bool
		updateBaseUrl            *url.URL
		target                   *updater.Target
	)

	newInstallation := pack.Cfg.InternalCompatibilityFlags.Update == ""
	if !newInstallation {
		update := pack.update // for convenience
		var err error
		updateBaseUrl, err = updateflag.Value{
			Update: pack.Cfg.InternalCompatibilityFlags.Update,
		}.BaseURL(update.HTTPPort, update.HTTPSPort, pack.schema, update.Hostname, update.HTTPPassword)
		if err != nil {
			return err
		}

		updateHttpClient, foundMatchingCertificate, err = httpclient.GetTLSHttpClientByTLSFlag(tlsflag.GetUseTLS(), tlsflag.GetInsecure(), updateBaseUrl)
		if err != nil {
			return fmt.Errorf("getting http client by tls flag: %v", err)
		}
		done := measure.Interactively("probing https")
		remoteScheme, err := httpclient.GetRemoteScheme(updateBaseUrl)
		done("")
		if remoteScheme == "https" {
			updateBaseUrl, err = updateflag.Value{
				Update: pack.Cfg.InternalCompatibilityFlags.Update,
			}.BaseURL(update.HTTPPort, update.HTTPSPort, "https", update.Hostname, update.HTTPPassword)
			if err != nil {
				return err
			}
			pack.Cfg.InternalCompatibilityFlags.Update = updateBaseUrl.String()
		}

		if updateBaseUrl.Scheme != "https" && foundMatchingCertificate {
			log.Printf("")
			log.Printf("!!!WARNING!!! Possible SSL-Stripping detected!")
			log.Printf("Found certificate for hostname in your client configuration but the host does not offer https!")
			log.Printf("")
			if !tlsflag.Insecure() {
				log.Printf("update canceled: TLS certificate found, but negotiating a TLS connection with the target failed")
				os.Exit(1)
			}
			log.Printf("Proceeding anyway as requested (--insecure).")
		}

		// Opt out of PARTUUID= for updating until we can check the remote
		// userland version is new enough to understand how to set the active
		// root partition when PARTUUID= is in use.
		if err != nil {
			return err
		}
		updateBaseUrl.Path = "/"

		target, err = updater.NewTarget(ctx, updateBaseUrl.String(), updateHttpClient)
		if err != nil {
			return fmt.Errorf("checking target partuuid support: %v", err)
		}
		pack.UsePartuuid = target.Supports("partuuid")
		pack.UseGPTPartuuid = target.Supports("gpt")
		pack.UseGPT = target.Supports("gpt")
		pack.ExistingEEPROM = target.InstalledEEPROM()
	}
	log.Printf("")
	log.Printf("Feature summary:")
	log.Printf("  use GPT: %v", pack.UseGPT)
	log.Printf("  use PARTUUID: %v", pack.UsePartuuid)
	log.Printf("  use GPT PARTUUID: %v", pack.UseGPTPartuuid)

	cfg := pack.Cfg   // for convenience
	root := pack.root // for convenience
	// Determine where to write the boot and root images to.
	var (
		isDev                    bool
		tmpBoot, tmpRoot, tmpMBR *os.File
		bootSize, rootSize       int64
	)
	switch {
	case cfg.InternalCompatibilityFlags.Overwrite != "" ||
		(pack.Output != nil && pack.Output.Type == OutputTypeFull && pack.Output.Path != ""):

		st, err := os.Stat(cfg.InternalCompatibilityFlags.Overwrite)
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		isDev = err == nil && st.Mode()&os.ModeDevice == os.ModeDevice

		if isDev {
			if err := pack.overwriteDevice(cfg.InternalCompatibilityFlags.Overwrite, root, pack.rootDeviceFiles); err != nil {
				return err
			}
			log.Printf("To boot gokrazy, plug the SD card into a supported device (see https://gokrazy.org/platforms/)")
			log.Printf("")
		} else {
			lower := 1200*MB + int(pack.firstPartitionOffsetSectors)

			if cfg.InternalCompatibilityFlags.TargetStorageBytes == 0 {
				return fmt.Errorf("--target_storage_bytes is required (e.g. --target_storage_bytes=%d) when using overwrite with a file", lower)
			}
			if cfg.InternalCompatibilityFlags.TargetStorageBytes%512 != 0 {
				return fmt.Errorf("--target_storage_bytes must be a multiple of 512 (sector size), use e.g. %d", lower)
			}
			if cfg.InternalCompatibilityFlags.TargetStorageBytes < lower {
				return fmt.Errorf("--target_storage_bytes must be at least %d (for boot + 2 root file systems + 100 MB /perm)", lower)
			}

			bootSize, rootSize, err = pack.overwriteFile(root, pack.rootDeviceFiles, pack.firstPartitionOffsetSectors)
			if err != nil {
				return err
			}

			log.Printf("To boot gokrazy, copy %s to an SD card and plug it into a supported device (see https://gokrazy.org/platforms/)", cfg.InternalCompatibilityFlags.Overwrite)
			log.Printf("")
		}

	case pack.Output != nil && pack.Output.Type == OutputTypeGaf && pack.Output.Path != "":
		if err := pack.overwriteGaf(root, pack.sbom); err != nil {
			return err
		}

	default:
		if cfg.InternalCompatibilityFlags.OverwriteBoot != "" {
			mbrfn := cfg.InternalCompatibilityFlags.OverwriteMBR
			if cfg.InternalCompatibilityFlags.OverwriteMBR == "" {
				var err error
				tmpMBR, err = os.CreateTemp("", "gokrazy")
				if err != nil {
					return err
				}
				defer os.Remove(tmpMBR.Name())
				mbrfn = tmpMBR.Name()
			}
			if err := pack.writeBootFile(cfg.InternalCompatibilityFlags.OverwriteBoot, mbrfn); err != nil {
				return err
			}
		}

		if cfg.InternalCompatibilityFlags.OverwriteRoot != "" {
			var rootErr error
			trace.WithRegion(context.Background(), "writeroot", func() {
				rootErr = pack.writeRootFile(cfg.InternalCompatibilityFlags.OverwriteRoot, root)
			})
			if rootErr != nil {
				return rootErr
			}
		}

		if cfg.InternalCompatibilityFlags.OverwriteBoot == "" && cfg.InternalCompatibilityFlags.OverwriteRoot == "" {
			var err error
			tmpMBR, err = os.CreateTemp("", "gokrazy")
			if err != nil {
				return err
			}
			defer os.Remove(tmpMBR.Name())

			tmpBoot, err = os.CreateTemp("", "gokrazy")
			if err != nil {
				return err
			}
			defer os.Remove(tmpBoot.Name())

			if err := pack.writeBoot(tmpBoot, tmpMBR.Name()); err != nil {
				return err
			}

			tmpRoot, err = os.CreateTemp("", "gokrazy")
			if err != nil {
				return err
			}
			defer os.Remove(tmpRoot.Name())

			if err := pack.writeRoot(tmpRoot, root); err != nil {
				return err
			}
		}
	}

	log.Printf("")
	log.Printf("Build complete!")

	if err := pack.printHowToInteract(cfg); err != nil {
		return err
	}

	if err := <-dnsCheck; err != nil {
		log.Printf("WARNING: if the above URL does not work, perhaps name resolution (DNS) is broken")
		log.Printf("in your local network? Resolving your hostname failed: %v", err)
		log.Printf("Did you maybe configure a DNS server other than your router?")
		log.Printf("")
	}

	if newInstallation {
		return nil
	}

	return pack.logicUpdate(ctx, isDev, bootSize, rootSize, tmpMBR, tmpBoot, tmpRoot, updateBaseUrl, target, updateHttpClient)
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
