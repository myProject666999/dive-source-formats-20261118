package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"

	"github.com/wagoodman/dive/internal/image/archive"
)

// archiveProvider reads an image archive (docker save, podman save or OCI layout, as a tarball or a
// directory) with dive's own parser (internal/image/archive) and adapts the result to a stereoscope
// image, so everything downstream of Load works exactly as with stereoscope's own providers.
type archiveProvider struct {
	name     string
	path     string
	platform *image.Platform
	format   archive.Format
	tmp      *file.TempDirGenerator
}

func newArchiveProvider(name string, tmp *file.TempDirGenerator, path string, platform *image.Platform, format archive.Format) image.Provider {
	return &archiveProvider{name: name, path: path, platform: platform, format: format, tmp: tmp}
}

func (p *archiveProvider) Name() string {
	return p.name
}

func (p *archiveProvider) Provide(ctx context.Context) (*image.Image, error) {
	spoolDir, err := p.tmp.NewDirectory("archive-spool")
	if err != nil {
		return nil, err
	}
	opts := archive.Options{TempDir: spoolDir, Format: p.format}
	// a docker save holds a single image, there is nothing to select a platform from
	if p.format == archive.FormatOCI && p.platform != nil {
		opts.Platform = &archive.Platform{OS: p.platform.OS, Architecture: p.platform.Architecture, Variant: p.platform.Variant}
	}
	parsed, err := archive.Parse(p.path, opts)
	if err != nil {
		return nil, err
	}

	v1img, err := v1Image(parsed)
	if err != nil {
		return nil, fmt.Errorf("unable to adapt %s: %w", parsed.Source, err)
	}

	contentDir, err := p.tmp.NewDirectory("archive-content")
	if err != nil {
		return nil, err
	}
	metadata := []image.AdditionalMetadata{
		image.WithTags(parsed.Tags...),
		image.WithConfig(parsed.Config),
	}
	if parsed.Manifest != nil {
		metadata = append(metadata, image.WithManifest(parsed.Manifest))
	}
	out := image.New(v1img, p.tmp, contentDir, metadata...)
	if err := out.Read(ctx); err != nil {
		return nil, errors.Join(err, out.Cleanup())
	}
	return out, nil
}

// v1Image builds a go-containerregistry image over the parsed layers. Layer payloads stay where the
// parser put them (spooled temp files, memory buffers or blobs on disk); go-containerregistry sniffs
// their compression itself when reading.
func v1Image(parsed *archive.Image) (v1.Image, error) {
	img := empty.Image
	var adds []mutate.Addendum
	for _, l := range parsed.Layers {
		layer, err := tarball.LayerFromOpener(l.Open, tarball.WithMediaType(types.MediaType(l.MediaType)))
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", l.Index, err)
		}
		adds = append(adds, mutate.Addendum{Layer: layer})
	}
	if len(adds) > 0 {
		var err error
		img, err = mutate.Append(img, adds...)
		if err != nil {
			return nil, err
		}
	}
	// the config as the archive wrote it: full history (empty layers included), rootfs diff_ids, os/arch
	var cfg v1.ConfigFile
	if err := json.Unmarshal(parsed.Config, &cfg); err != nil {
		return nil, fmt.Errorf("config is not valid JSON: %w", err)
	}
	return mutate.ConfigFile(img, &cfg)
}
