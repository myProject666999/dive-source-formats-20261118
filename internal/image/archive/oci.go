package archive

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// descriptor is an OCI content descriptor.
type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *Platform         `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

// indexJSON is an OCI image index.
type indexJSON struct {
	Manifests []descriptor `json:"manifests"`
}

// manifestJSON is an OCI image manifest.
type manifestJSON struct {
	Config descriptor   `json:"config"`
	Layers []descriptor `json:"layers"`
}

// blobStore finds the content addressed blobs of an OCI layout.
type blobStore interface {
	// read returns a small blob (an index, manifest or config JSON), verifying its digest
	read(digest, doc string) ([]byte, error)
	// layer prepares access to a layer blob
	layer(d descriptor, index int) (*layerBuilder, error)
}

// blobName maps a digest to its blob path within the layout. The digest is validated first: it is
// the only thing standing between a crafted digest like "sha256:../oci-layout" and the filesystem.
func blobName(digest string) (string, error) {
	if err := checkDigest(digest); err != nil {
		return "", err
	}
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:"), nil
}

// verifyBlob checks that data hashes to the digest it was addressed by.
func verifyBlob(src Source, doc, digest string, data []byte) error {
	got, err := digestOf(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if got != digest {
		return fmt.Errorf("%s: %s hashes to %s but is addressed as %s — the archive may be corrupt", src, doc, got, digest)
	}
	return nil
}

// tarBlobs is a blobStore over the first pass of an OCI layout tarball.
type tarBlobs struct {
	contents *tarContents
}

func (s *tarBlobs) read(digest, doc string) ([]byte, error) {
	name, err := blobName(digest)
	if err != nil {
		return nil, err
	}
	data, ok := s.contents.meta[name]
	if !ok {
		return nil, fmt.Errorf("%s is not in the archive", doc)
	}
	return data, nil
}

func (s *tarBlobs) layer(d descriptor, index int) (*layerBuilder, error) {
	name, err := blobName(d.Digest)
	if err != nil {
		return nil, err
	}
	b := &layerBuilder{
		index:        index,
		doc:          fmt.Sprintf("layer %d (%s)", index, d.Digest),
		entry:        name,
		size:         d.Size,
		storedDigest: d.Digest,
		mediaType:    d.MediaType,
	}
	if data, ok := s.contents.meta[name]; ok {
		b.data = data
		b.size = int64(len(data))
	} else if size, ok := s.contents.big[name]; ok {
		b.size = size
	} else {
		return nil, fmt.Errorf("blob %s of %s is not in the archive", d.Digest, b.doc)
	}
	return b, nil
}

// dirBlobs is a blobStore over an OCI layout directory on disk.
type dirBlobs struct {
	root string
}

func (s *dirBlobs) read(digest, doc string) ([]byte, error) {
	name, err := blobName(digest)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(s.root, filepath.FromSlash(name)))
	if err != nil {
		return nil, fmt.Errorf("%s is not readable: %w", doc, err)
	}
	defer f.Close() // nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(f, maxMetaFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", doc, err)
	}
	if len(data) > maxMetaFileSize {
		return nil, fmt.Errorf("%s is too large to be a JSON document", doc)
	}
	return data, nil
}

func (s *dirBlobs) layer(d descriptor, index int) (*layerBuilder, error) {
	name, err := blobName(d.Digest)
	if err != nil {
		return nil, err
	}
	return &layerBuilder{
		index:        index,
		doc:          fmt.Sprintf("layer %d (%s)", index, d.Digest),
		file:         filepath.Join(s.root, filepath.FromSlash(name)),
		size:         d.Size,
		storedDigest: d.Digest,
		mediaType:    d.MediaType,
	}, nil
}

// parseOCI reads an OCI image layout, from a tarball or a directory, through the given blob store.
func parseOCI(path string, store blobStore, opts Options) (*Image, error) {
	src := Source{Path: path, Format: FormatOCI}
	ctx := &parseContext{opts: opts, src: src}
	if _, isTar := store.(*tarBlobs); isTar {
		ctx.archivePath = path
	}

	rawIndex, err := readLayoutFile(store, path, "index.json")
	if err != nil {
		return nil, err
	}
	var index indexJSON
	if err := json.Unmarshal(rawIndex, &index); err != nil {
		return nil, fmt.Errorf("%s: index.json is not valid JSON: %w", src, err)
	}

	var available []string
	desc, err := selectManifest(store, src, &index, opts.platform(), 0, opts.MaxIndexDepth, &available)
	if err != nil {
		return nil, err
	}
	if desc == nil {
		return nil, fmt.Errorf("%s: no manifest matches platform %s (available: %s)",
			src, opts.platform(), strings.Join(available, ", "))
	}
	src.ManifestDigest = desc.Digest
	if desc.Platform != nil {
		src.Platform = *desc.Platform
	}

	manifestDoc := fmt.Sprintf("manifest %s", desc.Digest)
	rawManifest, err := store.read(desc.Digest, manifestDoc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	if err := verifyBlob(src, manifestDoc, desc.Digest, rawManifest); err != nil {
		return nil, err
	}
	var manifest manifestJSON
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return nil, fmt.Errorf("%s: %s is not valid JSON: %w", src, manifestDoc, err)
	}

	configDoc := fmt.Sprintf("config %s", manifest.Config.Digest)
	rawConfig, err := store.read(manifest.Config.Digest, configDoc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	if err := verifyBlob(src, configDoc, manifest.Config.Digest, rawConfig); err != nil {
		return nil, err
	}
	cfg, err := parseConfig(rawConfig, configDoc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}

	lbs := make([]*layerBuilder, len(manifest.Layers))
	for i, d := range manifest.Layers {
		b, err := store.layer(d, i)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
		lbs[i] = b
	}

	img := &Image{
		Source:   src,
		Tags:     ociTags(desc),
		Config:   rawConfig,
		Manifest: rawManifest,
		History:  cfg.history(),
	}
	if err := resolveLayers(ctx, img, lbs, cfg.RootFS.DiffIDs, manifestDoc, configDoc); err != nil {
		return nil, err
	}
	img.cleanup = ctx.cleanup
	return img, nil
}

// readLayoutFile reads index.json, which (unlike blobs) is addressed by name.
func readLayoutFile(store blobStore, path, name string) ([]byte, error) {
	switch s := store.(type) {
	case *tarBlobs:
		data, ok := s.contents.meta[name]
		if !ok {
			return nil, fmt.Errorf("oci archive %q: no %s", path, name)
		}
		return data, nil
	case *dirBlobs:
		data, err := os.ReadFile(filepath.Join(s.root, name))
		if err != nil {
			return nil, fmt.Errorf("oci layout %q: no readable %s", path, name)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unknown blob store %T", store)
	}
}

// selectManifest picks the manifest for the wanted platform from an index, recursing into nested
// indexes up to maxDepth. Descriptors carry their platform; one without a platform cannot be
// disproved and is a fallback behind every exact match. "unknown/unknown" marks an attestation
// manifest and is never selected. The platforms of every manifest seen are collected into available
// for the error when nothing matches.
func selectManifest(store blobStore, src Source, index *indexJSON, want Platform, depth, maxDepth int, available *[]string) (*descriptor, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%s: OCI indexes nest deeper than %d levels", src, maxDepth)
	}
	var fallbacks []descriptor
	for i := range index.Manifests {
		d := &index.Manifests[i]
		if d.Platform != nil {
			*available = append(*available, d.Platform.String())
			if d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown" {
				continue // attestation manifests carry no image
			}
			if !d.Platform.matches(want) {
				continue
			}
		}
		isIndex, nested, err := classifyBlob(store, src, d)
		if err != nil {
			return nil, err
		}
		if isIndex {
			found, err := selectManifest(store, src, nested, want, depth+1, maxDepth, available)
			if err != nil {
				return nil, err
			}
			if found != nil {
				return found, nil
			}
			continue
		}
		if d.Platform != nil {
			return d, nil // exact platform match wins immediately
		}
		fallbacks = append(fallbacks, *d)
	}
	if len(fallbacks) > 0 {
		return &fallbacks[0], nil
	}
	return nil, nil
}

// classifyBlob reads a descriptor's blob (verifying its digest) and reports whether it is a nested
// index, decoding it if so. The content decides (an index has a "manifests" key, a manifest has
// "layers"); the media type is only a claim.
func classifyBlob(store blobStore, src Source, d *descriptor) (bool, *indexJSON, error) {
	doc := fmt.Sprintf("blob %s", d.Digest)
	raw, err := store.read(d.Digest, doc)
	if err != nil {
		return false, nil, fmt.Errorf("%s: %w", src, err)
	}
	if err := verifyBlob(src, doc, d.Digest, raw); err != nil {
		return false, nil, err
	}
	var probe struct {
		Manifests json.RawMessage `json:"manifests"`
		Layers    json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false, nil, fmt.Errorf("%s: %s is not valid JSON: %w", src, doc, err)
	}
	if probe.Manifests == nil || probe.Layers != nil {
		return false, nil, nil
	}
	var index indexJSON
	if err := json.Unmarshal(raw, &index); err != nil {
		return false, nil, fmt.Errorf("%s: %s is not valid JSON: %w", src, doc, err)
	}
	return true, &index, nil
}

// ociTags derives image tags from the selected descriptor's annotations.
func ociTags(d *descriptor) []string {
	if d.Annotations == nil {
		return nil
	}
	// docker's OCI layout saves carry the full reference; a plain OCI layout only the tag
	if name := d.Annotations["io.containerd.image.name"]; name != "" {
		return []string{name}
	}
	if ref := d.Annotations["org.opencontainers.image.ref.name"]; ref != "" {
		return []string{ref}
	}
	return nil
}
