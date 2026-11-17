// Package archive reads container image archives into one internal representation, whatever produced
// them: `docker save` tarballs (legacy and docker 25+ OCI layout), `podman save` tarballs, OCI image
// archives and OCI image layout directories. The parsed Image keeps where it came from, so errors can
// name the document (manifest.json, index.json, a config or layer blob) that is at fault.
//
// Layer order always comes from the manifest (manifest.json for docker saves, the selected OCI manifest
// otherwise); the config's rootfs.diff_ids only cross-checks that order. A disagreement is reported as
// an inconsistent archive, never resolved by silently picking one side. History entries with empty_layer
// set own no layer and are skipped when pairing commands with layers.
package archive

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// Format is the archive layout an Image was read from.
type Format string

const (
	// FormatDockerSave is the manifest.json layout of `docker save` and `podman save`, including the
	// docker 25+ variant that stores layers as OCI blobs next to manifest.json.
	FormatDockerSave Format = "docker-save"
	// FormatOCI is the OCI image layout: index.json, oci-layout and content addressed blobs.
	FormatOCI Format = "oci"
)

// Platform identifies an os/architecture(/variant) triple.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

func (p Platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// matches reports whether the platform descriptor p selects the wanted platform. A descriptor without
// a platform cannot be disproved and matches anything.
func (p *Platform) matches(want Platform) bool {
	if p == nil {
		return true
	}
	return p.OS == want.OS && p.Architecture == want.Architecture && (want.Variant == "" || p.Variant == want.Variant)
}

// Source describes where an Image was read from.
type Source struct {
	// Path is the archive file or layout directory as handed to Parse
	Path   string
	Format Format
	// ManifestDigest is the digest of the OCI manifest the image was selected from (FormatOCI only)
	ManifestDigest string
	// Platform is the platform of the selected manifest (FormatOCI only)
	Platform Platform
}

// String labels the source for error messages, e.g. `docker-save archive "img.tar"`.
func (s Source) String() string {
	return fmt.Sprintf("%s archive %q", s.Format, s.Path)
}

// History is one image config history entry.
type History struct {
	CreatedBy  string
	EmptyLayer bool
}

// Layer is one filesystem layer in build order.
type Layer struct {
	Index int
	// DiffID is the sha256 of the uncompressed layer tar ("sha256:<hex>")
	DiffID string
	// Digest is the sha256 of the stored (possibly compressed) layer bytes; equal to DiffID when uncompressed
	Digest string
	// Size is the stored size in bytes
	Size int64
	// MediaType is the OCI layer media type matching the compression found by sniffing the content
	// (the archive's own media type strings are not trusted). With Options.OnDemand the content has not
	// been read yet and this is the archive's claim, unverified.
	MediaType string
	// Command is the history entry that created the layer, "(missing)" when the image has none for it
	Command string

	open func() (io.ReadCloser, error)
}

// Open returns the layer's stored bytes, still compressed when MediaType says so.
func (l Layer) Open() (io.ReadCloser, error) {
	return l.open()
}

// Image is the unified representation every archive format parses into.
type Image struct {
	Source Source
	Tags   []string
	// Config is the raw image config JSON
	Config []byte
	// Manifest is the raw OCI manifest JSON the image was selected from, nil for docker saves
	Manifest []byte
	// History is the config history as written, empty layers included
	History []History
	// Layers is in build order; Layers[i].Command pairs with the non-empty history entries
	Layers []Layer

	cleanup func() error
}

// Close releases resources Parse allocated (the spool dir it created when Options.TempDir was empty).
// An Image parsed with a caller provided TempDir owns nothing and Close is a no-op.
func (i *Image) Close() error {
	if i == nil || i.cleanup == nil {
		return nil
	}
	return i.cleanup()
}

// Options controls how Parse reads an archive.
type Options struct {
	// Platform selects a manifest from a multi-platform OCI index (e.g. Platform{OS: "linux",
	// Architecture: "arm64"}). Nil means the host platform. Docker saves hold a single image and
	// ignore it.
	Platform *Platform
	// Format requires this layout; empty detects it from the content.
	Format Format
	// TempDir is where layer payloads are spooled. Empty makes Parse create (and own) a temp dir.
	TempDir string
	// OnDemand defers layer payload reads to the first Layer.Open instead of spooling them during
	// Parse: no temp disk and no parse-time decompression, but every Open re-scans the archive, and
	// layer digest verification (and with it the manifest/config order cross-check) only happens when
	// the layer is read, not at parse time. See DESIGN.md for the trade-off.
	OnDemand bool
	// MaxIndexDepth bounds how deep OCI indexes may nest. Zero means 8.
	MaxIndexDepth int
}

func (o Options) withDefaults() Options {
	if o.MaxIndexDepth <= 0 {
		o.MaxIndexDepth = 8
	}
	return o
}

func (o Options) platform() Platform {
	if o.Platform != nil {
		return *o.Platform
	}
	return Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}
}

// Parse reads the image archive at path (a tarball, possibly gzip or zstd compressed, or an OCI layout
// directory) into the unified Image. The layout is detected from the content unless Options.Format pins
// it. Layer payloads of a tarball are spooled to Options.TempDir unless Options.OnDemand is set.
func Parse(path string, opts Options) (*Image, error) {
	opts = opts.withDefaults()

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read image archive: %w", err)
	}
	if info.IsDir() {
		if opts.Format == FormatDockerSave {
			return nil, fmt.Errorf("%q is a directory, not a docker save archive", path)
		}
		return parseOCIDir(path, opts)
	}
	return parseTar(path, opts)
}
