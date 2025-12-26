package main

/*
   A generic builder program to help build go packages
   Includes:
     - Version detection via "VERSION" file or --version <version>
     - Build for windows/mac/linux on amd64/arm64
     - Creates .tar.gz for mac/linux with files set to executable permissions and a .zip for Windows
*/

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var BINARY_NAME string

var (
	MAIN_PKG     = "./cmd"
	DIST_DIR     = "dist"
	VERSION_FILE = "./VERSION"
	VERSION      = "dev"
)

const DEFAULT_VERSION = ""

type BuildTarget struct {
	OS   string
	Arch string
}

// default supported build buildTargets
var buildTargetsDefault = []BuildTarget{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

// usage prints the usage information for the build script
func usage() {
	basename := filepath.Base(os.Args[0])
	log.Printf("Usage:\n\n%s -name \"<binary name>\" [-all/-targets \"<targets>\">] [-release] [-v <version>]\n", basename)

	log.Printf("\nOptions:\n")
	log.Printf("  -name <string>               Name of the binary to build (required)\n")
	log.Printf("  -out <string>                Output directory for built binaries (default: \"dist\")\n")
	log.Printf("  -all                         Build for all default OS/ARCH targets (default: current OS/ARCH only)\n")
	log.Printf("  -targets <string>            Build for specific OS/ARCH target(s) (format: os/arch, comma-separated for multiple)\n")
	log.Printf("  -release                     Build for release (stripped binaries)\n")
	log.Printf("  -version <string>            Version to embed in the binary (overrides VERSION file)\n\n")
	log.Printf("  -version-location <string>   Location of the version variable (default: main.Version)\n\n")

	log.Printf("Default build targets (-all):\n")

	var targetNames []string
	for _, target := range buildTargetsDefault {
		targetNames = append(targetNames, fmt.Sprintf("%s/%s", target.OS, target.Arch))
	}

	fmt.Println("  " + strings.Join(targetNames, ", "))
}

func main() {
	log.SetFlags(0)

	// Parse flags
	name := flag.String("name", "", "name of the binary project")
	out := flag.String("out", DIST_DIR, "output directory for built binaries")
	all := flag.Bool("all", false, "build for all supported OS/ARCH targets")
	targets := flag.String("targets", "", "specific OS/ARCH target to build (format: os/arch)")
	release := flag.Bool("release", false, "build for release (stripped binaries)")
	version := flag.String("version", "", "version to embed in the binary (overrides VERSION file)")
	versionLocation := flag.String("version-location", "main.Version", "location of the version file (overrides VERSION_FILE)")

	flag.Parse()

	if *targets != "" && *all {
		log.Printf("Error: cannot specify both -targets and -all flags\n")
		usage()
		os.Exit(1)
	}

	var buildTargets []BuildTarget

	// If a specific target is provided, override the targets list
	if *targets != "" {
		targetsList := strings.Split(*targets, ",")
		buildTargets = []BuildTarget{}

		for _, target := range targetsList {
			parts := strings.Split(target, "/")
			if len(parts) != 2 {
				log.Printf("Error: invalid target format '%s'. Expected os/arch\n", target)
				usage()
				os.Exit(1)
			}
			buildTargets = append(buildTargets, BuildTarget{
				OS: parts[0], Arch: parts[1],
			})
		}
	} else if !*all {
		// If not building for all targets, limit to current OS/ARCH
		buildTargets = []BuildTarget{
			{OS: runtime.GOOS, Arch: runtime.GOARCH},
		}
	} else {
		buildTargets = buildTargetsDefault
	}

	// Set output directory if provided, use "dist" as default
	if out != nil && *out != "" {
		DIST_DIR = *out
	}

	// Validate binary name, exit if not provided
	if name == nil || *name == "" {
		usage()
		os.Exit(1)
	}
	BINARY_NAME = *name

	// Read version from VERSION file, use default if not found
	v, err := readVersion()
	if err != nil {
		fmt.Printf("Warn: reading version: %v", err)
	}

	if version != nil && *version != "" {
		v = *version
	}

	msgBuilding := fmt.Sprintf("Building %s", BINARY_NAME)
	if v != "" {
		msgBuilding += fmt.Sprintf(" version %s", v)
	}
	fmt.Printf("%s\n", msgBuilding)

	var wg sync.WaitGroup

	for _, target := range buildTargets {
		wg.Add(1)
		go func() {
			prefix := fmt.Sprintf(
				"%-20s",
				fmt.Sprintf("[%s/%s] ", target.OS, target.Arch),
			)
			defer wg.Done()
			buildAndPackage(prefix, target, *versionLocation, v, *release)
		}()
	}

	wg.Wait()
}

// readversion attempts to read the VERSION file, defaults to the VERSION constant if not found
func readVersion() (string, error) {
	data, err := os.ReadFile(VERSION_FILE)
	if err != nil {
		return VERSION, fmt.Errorf("failed to read VERSION file: %w", err)
	}

	v := strings.TrimSpace(string(data))
	if v == "" {
		return VERSION, fmt.Errorf("VERSION file is empty")
	}

	return v, nil
}

func buildAndPackage(prefix string, target BuildTarget, versionLocation, version string, release bool) error {
	// Create output directory
	outDirName := fmt.Sprintf("%s-%s-%s", BINARY_NAME, target.OS, target.Arch)
	outDir := filepath.Join(DIST_DIR, version, outDirName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create dist dir: %w", err)
	}

	// Build the binary name and path
	binName := BINARY_NAME
	if target.OS == "windows" {
		binName += ".exe"
	}

	binPath := filepath.Join(outDir, binName)

	// Set the ldflags
	ldflags := ""
	if version != "" {
		ldflags += fmt.Sprintf("-X %s=%s", versionLocation, version)
	}
	if release {
		ldflags += " -w -s"
	}
	fmt.Printf("%s -> go build %s/%s\n", prefix, target.OS, target.Arch)

	args := []string{
		"build",
		"-o", binPath,
	}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, MAIN_PKG)

	cmd := exec.Command("go", args...)

	cmd.Env = append(os.Environ(), "GOOS="+target.OS, "GOARCH="+target.Arch)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build failed for %s/%s: %w", target.OS, target.Arch, err)
	}

	if err := packageDir(prefix, target, outDirName, version); err != nil {
		return err
	}

	if err := os.RemoveAll(outDir); err != nil {
		return fmt.Errorf("failed to clean up build dir: %w", err)
	}

	return nil
}

func packageDir(prefix string, target BuildTarget, dir, version string) error {
	switch target.OS {
	case "windows":
		return createZip(prefix, dir, version)
	default:
		return createTarGz(prefix, dir, version)
	}
}

func createZip(prefix string, dir, version string) error {
	archivePath := filepath.Join(DIST_DIR, version, dir+".zip")
	fmt.Printf("%s -> creating zip archive: %s\n", prefix, archivePath)

	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	srcDir := filepath.Join(DIST_DIR, version, dir)

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, errWalk error) error {
		if errWalk != nil {
			return fmt.Errorf("error walking path %s: %w", path, errWalk)
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		zipPath := filepath.ToSlash(relPath)
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("failed to get file info header: %w", err)
		}

		header.Name = zipPath
		header.Method = zip.Deflate

		w, err := zw.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("failed to create header: %w", err)
		}

		in, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file for zipping: %w", err)
		}
		defer in.Close()

		_, err = io.Copy(w, in)
		if err != nil {
			return fmt.Errorf("failed to copy file data to zip: %w", err)
		}

		return nil
	})
}

func createTarGz(prefix string, dir, version string) error {
	archivePath := filepath.Join(DIST_DIR, version, dir+".tar.gz")
	fmt.Printf("%s -> creating tar.gz archive: %s\n", prefix, archivePath)

	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	srcDir := filepath.Join(DIST_DIR, version, dir)

	defer func() {
		fmt.Printf("%s -> build complete\n", prefix)
	}()
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, errWalk error) error {
		if errWalk != nil {
			return fmt.Errorf("error walking path %s: %w", path, errWalk)
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		tarPath := filepath.ToSlash(relPath)

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to get tar file info header: %w", err)
		}

		header.Name = tarPath

		if filepath.Base(tarPath) == BINARY_NAME {
			header.Mode = 0o755
		}

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		in, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file for tarring: %w", err)
		}
		defer in.Close()

		_, err = io.Copy(tw, in)
		if err != nil {
			return fmt.Errorf("failed to copy file data to tar: %w", err)
		}

		return nil
	})
}
