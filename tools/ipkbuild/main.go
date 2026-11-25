// ipkbuild packs a directory into an opkg .ipk without the OpenWrt SDK: a
// gzipped tar holding debian-binary, control.tar.gz and data.tar.gz, every
// entry owned by root. File modes are set explicitly so packages built on
// Windows keep executables executable.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// executable reports whether a packaged path must be 0755.
func executable(name string) bool {
	return strings.HasPrefix(name, "usr/bin/") ||
		strings.HasPrefix(name, "usr/sbin/") ||
		strings.HasPrefix(name, "etc/init.d/") ||
		strings.HasPrefix(name, "etc/uci-defaults/") ||
		name == "postinst" || name == "prerm" || name == "postrm" || name == "preinst"
}

type entry struct {
	name string
	dir  bool
	data []byte
	mode int64
}

func collect(root string) ([]entry, int64, error) {
	var entries []entry
	var size int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if name == "." {
			return nil
		}
		if d.IsDir() {
			entries = append(entries, entry{name: name + "/", dir: true, mode: 0o755})
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		mode := int64(0o644)
		if executable(name) {
			mode = 0o755
		}
		size += int64(len(data))
		entries = append(entries, entry{name: name, data: data, mode: mode})
		return nil
	})
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries, size, err
}

func tarGz(entries []entry, modTime time.Time, rootEntry bool) ([]byte, error) {
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	write := func(header *tar.Header, data []byte) error {
		header.Uid, header.Gid = 0, 0
		header.Uname, header.Gname = "root", "root"
		header.ModTime = modTime
		header.Format = tar.FormatGNU
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		_, err := archive.Write(data)
		return err
	}
	if rootEntry {
		if err := write(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}, nil); err != nil {
			return nil, err
		}
	}
	for _, e := range entries {
		header := &tar.Header{Name: "./" + e.name, Mode: e.mode}
		if e.dir {
			header.Typeflag = tar.TypeDir
		} else {
			header.Typeflag = tar.TypeReg
			header.Size = int64(len(e.data))
		}
		if err := write(header, e.data); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	if err := compressed.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func main() {
	dataDir := flag.String("data", "", "directory with the package's files (becomes /)")
	controlDir := flag.String("control", "", "directory with control scripts and conffiles")
	pkg := flag.String("package", "", "package name")
	version := flag.String("version", "", "package version")
	arch := flag.String("arch", "all", "opkg architecture")
	depends := flag.String("depends", "", "comma-separated dependencies")
	description := flag.String("description", "", "one-line description")
	out := flag.String("out", "", "output .ipk path")
	license := flag.String("license", "", "license identifier (omitted when empty)")
	flag.Parse()
	if *dataDir == "" || *pkg == "" || *version == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	modTime := time.Now().UTC().Truncate(time.Second)

	dataEntries, installedSize, err := collect(*dataDir)
	if err != nil {
		fail(err)
	}
	data, err := tarGz(dataEntries, modTime, true)
	if err != nil {
		fail(err)
	}

	var controlEntries []entry
	if *controlDir != "" {
		controlEntries, _, err = collect(*controlDir)
		if err != nil {
			fail(err)
		}
	}
	var control strings.Builder
	fmt.Fprintf(&control, "Package: %s\nVersion: %s\n", *pkg, *version)
	if *depends != "" {
		fmt.Fprintf(&control, "Depends: %s\n", *depends)
	}
	fmt.Fprintf(&control, "Source: https://github.com/Slam00/FlowCloud-OpenWRT\nSection: net\nArchitecture: %s\nInstalled-Size: %d\nMaintainer: FlowCloud\n",
		*arch, installedSize)
	if *license != "" {
		fmt.Fprintf(&control, "License: %s\n", *license)
	}
	fmt.Fprintf(&control, "Description: %s\n", *description)
	controlEntries = append(controlEntries, entry{name: "control", data: []byte(control.String()), mode: 0o644})
	sort.Slice(controlEntries, func(i, j int) bool { return controlEntries[i].name < controlEntries[j].name })
	controlArchive, err := tarGz(controlEntries, modTime, true)
	if err != nil {
		fail(err)
	}

	outer, err := tarGz([]entry{
		{name: "debian-binary", data: []byte("2.0\n"), mode: 0o644},
		{name: "data.tar.gz", data: data, mode: 0o644},
		{name: "control.tar.gz", data: controlArchive, mode: 0o644},
	}, modTime, false)
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(path.Dir(filepath.ToSlash(*out)), 0o755); err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, outer, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("%s (%d bytes)\n", *out, len(outer))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ipkbuild:", err)
	os.Exit(1)
}
