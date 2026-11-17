package archive

import (
	"fmt"
	"os"
)

// parseContext carries what a format parser needs to resolve layer payloads.
type parseContext struct {
	opts Options
	src  Source
	// archivePath is the tarball to spool from or re-scan on demand; "" for an OCI layout directory
	archivePath string
	// cleanup removes the spool dir Parse created (nil when the caller provided Options.TempDir or
	// nothing was spooled); the parsed Image adopts it
	cleanup func() error
}

// spoolDir returns where layer payloads are spooled, creating (and adopting) a temp dir when the
// caller did not provide one.
func (c *parseContext) spoolDir() (string, func() error, error) {
	if c.opts.TempDir != "" {
		if err := os.MkdirAll(c.opts.TempDir, 0o700); err != nil {
			return "", nil, err
		}
		return c.opts.TempDir, func() error { return nil }, nil
	}
	dir, err := os.MkdirTemp("", "dive-archive-*")
	if err != nil {
		return "", nil, err
	}
	c.cleanup = func() error { return os.RemoveAll(dir) }
	return dir, c.cleanup, nil
}

// parseTar reads an image archive file. The layout is detected from the content: a manifest.json
// makes it a docker save, an index.json an OCI layout. Options.Format pins the layout instead.
func parseTar(path string, opts Options) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open image archive: %w", err)
	}
	defer f.Close() // nolint:errcheck
	r, _, err := decompress(f)
	if err != nil {
		return nil, fmt.Errorf("unable to decompress archive %q: %w", path, err)
	}
	defer r.Close() // nolint:errcheck
	contents, err := scanTar(r)
	if err != nil {
		return nil, fmt.Errorf("unable to read archive %q: %w", path, err)
	}

	switch {
	case contents.has("manifest.json"):
		if opts.Format == FormatOCI {
			return nil, fmt.Errorf("%q is a docker save archive (it has a manifest.json), not an OCI image archive", path)
		}
		return parseDockerSave(path, contents, opts)
	case contents.has("index.json"):
		if opts.Format == FormatDockerSave {
			return nil, fmt.Errorf("%q is an OCI image archive (it has an index.json), not a docker save archive", path)
		}
		return parseOCI(path, &tarBlobs{contents: contents}, opts)
	default:
		return nil, fmt.Errorf("%q is not a recognized image archive: it has neither a manifest.json (docker save) nor an index.json (OCI layout)", path)
	}
}

// parseOCIDir reads an OCI image layout directory.
func parseOCIDir(dir string, opts Options) (*Image, error) {
	if _, err := os.Stat(dir + string(os.PathSeparator) + "index.json"); err != nil {
		return nil, fmt.Errorf("%q is not an OCI image layout directory: no index.json", dir)
	}
	return parseOCI(dir, &dirBlobs{root: dir}, opts)
}
