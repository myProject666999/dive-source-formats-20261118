package archive

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	// maxMetaFileSize bounds a single metadata document (manifest, index, config); anything larger
	// is not a metadata document
	maxMetaFileSize = 8 << 20
	// maxMetaTotalSize bounds all buffered metadata of one archive, so a hostile archive cannot
	// grow memory without bound
	maxMetaTotalSize = 64 << 20
)

// tarContents is the result of the first pass over an archive: small files buffered, large ones
// (the layer payloads) recorded by name and size for the spool pass or on-demand reads.
type tarContents struct {
	meta map[string][]byte
	big  map[string]int64
}

func (c *tarContents) has(name string) bool {
	_, ok := c.meta[name]
	if ok {
		return true
	}
	_, ok = c.big[name]
	return ok
}

// cleanEntryName validates a tar entry name. Entries are never extracted under their archive name,
// but a name that is absolute or walks up out of the root marks a hostile or broken archive and is
// rejected outright.
func cleanEntryName(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty name")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute path %q", name)
	}
	for _, elem := range strings.Split(name, "/") {
		if elem == ".." {
			return "", fmt.Errorf("path %q escapes the archive root", name)
		}
	}
	return path.Clean(name), nil
}

// scanTar reads every entry of the (already decompressed) tar stream r, buffering files small enough
// to be metadata and only recording the rest.
func scanTar(r io.Reader) (*tarContents, error) {
	c := &tarContents{meta: map[string][]byte{}, big: map[string]int64{}}
	tr := tar.NewReader(r)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return c, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entries: %w", err)
		}
		name, err := cleanEntryName(hdr.Name)
		if err != nil {
			return nil, fmt.Errorf("unsafe tar entry: %w", err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			// directories carry no content
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size < 0 {
				return nil, fmt.Errorf("tar entry %q has a negative size", name)
			}
			if hdr.Size <= maxMetaFileSize && total+hdr.Size <= maxMetaTotalSize {
				data, err := io.ReadAll(tr)
				if err != nil {
					return nil, fmt.Errorf("reading tar entry %q: %w", name, err)
				}
				c.meta[name] = data
				total += hdr.Size
			} else {
				c.big[name] = hdr.Size
			}
		default:
			return nil, fmt.Errorf("tar entry %q has unsupported type flag %d", name, hdr.Typeflag)
		}
	}
}

// spooled is a layer payload copied out of the archive.
type spooled struct {
	path   string
	digest string
	size   int64
}

// spoolEntries streams the named entries of the archive at path into dir in a single pass, hashing
// each as it goes. It returns an error naming every wanted entry the archive does not have.
func spoolEntries(path string, names []string, dir string) (map[string]spooled, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() // nolint:errcheck
	r, _, err := decompress(f)
	if err != nil {
		return nil, err
	}
	defer r.Close() // nolint:errcheck

	want := make(map[string]bool, len(names))
	for _, name := range names {
		want[name] = true
	}
	out := make(map[string]spooled, len(names))

	tr := tar.NewReader(r)
	for len(want) > 0 {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entries: %w", err)
		}
		name, err := cleanEntryName(hdr.Name)
		if err != nil {
			return nil, fmt.Errorf("unsafe tar entry: %w", err)
		}
		if !want[name] {
			continue
		}
		tmp, err := os.CreateTemp(dir, "layer-*")
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		size, copyErr := io.Copy(io.MultiWriter(tmp, h), tr)
		closeErr := tmp.Close()
		if copyErr != nil || closeErr != nil {
			os.Remove(tmp.Name()) // nolint:errcheck
			return nil, fmt.Errorf("spooling tar entry %q: %w", name, errors.Join(copyErr, closeErr))
		}
		out[name] = spooled{path: tmp.Name(), digest: "sha256:" + hex.EncodeToString(h.Sum(nil)), size: size}
		delete(want, name)
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for name := range want {
			missing = append(missing, name)
		}
		return nil, fmt.Errorf("archive is missing entries: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// entryCloser couples an entry reader to the archive file and decompressor backing it.
type entryCloser struct {
	io.Reader
	file   io.Closer
	stream io.Closer
}

func (c *entryCloser) Close() error {
	return errors.Join(c.stream.Close(), c.file.Close())
}

// openTarEntry re-opens the archive at path and scans to the named entry, for on-demand layer reads.
// The returned reader yields the entry's stored bytes; closing it closes the archive.
func openTarEntry(path, name string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, _, err := decompress(f)
	if err != nil {
		f.Close() // nolint:errcheck
		return nil, err
	}
	closer := &entryCloser{file: f, stream: r}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			closer.Close() // nolint:errcheck
			return nil, fmt.Errorf("reading tar entries: %w", err)
		}
		entryName, err := cleanEntryName(hdr.Name)
		if err != nil {
			closer.Close() // nolint:errcheck
			return nil, fmt.Errorf("unsafe tar entry: %w", err)
		}
		if entryName == name {
			closer.Reader = tr
			return closer, nil
		}
	}
	closer.Close() // nolint:errcheck
	return nil, fmt.Errorf("entry %q not found in the archive", name)
}
