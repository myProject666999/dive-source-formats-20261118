package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wagoodman/dive/internal/imagefixture"
)

// writeTarFiles writes files as a tar archive and returns its path.
func writeTarFiles(t *testing.T, files map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "img.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	tw := tar.NewWriter(f)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(files[name]))}))
		_, err := tw.Write(files[name])
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())
	return path
}

// writeSpecTar writes the fixture spec as a tarball and returns its path.
func writeSpecTar(t *testing.T, spec imagefixture.Spec) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "img.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, spec.Write(f))
	require.NoError(t, f.Close())
	return path
}

// the fixture with interleaved empty-layer history entries, built to expose history/layer misalignment
func alignmentSpec(format imagefixture.Format, compression imagefixture.Compression) imagefixture.Spec {
	spec := imagefixture.Fixtures()["empty-layer-history"]
	spec.Format = format
	spec.Compression = compression
	return spec
}

func parse(t *testing.T, path string, opts Options) *Image {
	t.Helper()
	img, err := Parse(path, opts)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, img.Close()) })
	return img
}

func layerSummary(img *Image) (diffIDs, digests, commands, mediaTypes []string) {
	for _, l := range img.Layers {
		diffIDs = append(diffIDs, l.DiffID)
		digests = append(digests, l.Digest)
		commands = append(commands, l.Command)
		mediaTypes = append(mediaTypes, l.MediaType)
	}
	return
}

func emptyLayerFlags(img *Image) []bool {
	var out []bool
	for _, h := range img.History {
		out = append(out, h.EmptyLayer)
	}
	return out
}

// the same image packed as a docker save (legacy and docker 25+), a podman save, an OCI archive and
// an OCI layout directory parses into the same layers, commands and digests
func TestParse_formatsAgree(t *testing.T) {
	variants := []struct {
		name        string
		format      imagefixture.Format
		compression imagefixture.Compression
		opts        Options
		asDir       bool
	}{
		{name: "docker legacy save", format: imagefixture.LegacySave},
		{name: "podman save", format: imagefixture.PodmanSave},
		{name: "docker 25+ save", format: imagefixture.OCISave},
		{name: "oci archive", format: imagefixture.OCIArchive, opts: Options{Format: FormatOCI}},
		{name: "oci archive gzip", format: imagefixture.OCIArchive, compression: imagefixture.Gzip, opts: Options{Format: FormatOCI}},
		{name: "oci archive zstd", format: imagefixture.OCIArchive, compression: imagefixture.Zstd, opts: Options{Format: FormatOCI}},
		{name: "oci dir", format: imagefixture.OCIArchive, asDir: true},
	}

	wantCommands := []string{
		"/bin/sh -c #(nop) ADD file:aaaa in / ",
		"/bin/sh -c echo 22 > /a/two",
		"RUN |1 VERSION=1 /bin/sh -c echo 333 > /a/three # buildkit",
	}

	var reference []string
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			spec := alignmentSpec(v.format, v.compression)
			opts := v.opts
			if opts.Format == "" && !v.asDir {
				opts.Format = FormatDockerSave
			}
			opts.TempDir = t.TempDir()

			var img *Image
			if v.asDir {
				dir := filepath.Join(t.TempDir(), "layout")
				require.NoError(t, spec.WriteDir(dir))
				img = parse(t, dir, opts)
			} else {
				img = parse(t, writeSpecTar(t, spec), opts)
			}

			diffIDs, digests, commands, mediaTypes := layerSummary(img)
			assert.Equal(t, wantCommands, commands, "history commands paired to the wrong layers")
			if reference == nil {
				reference = diffIDs
			} else {
				assert.Equal(t, reference, diffIDs, "diff IDs differ between formats")
			}

			// the full history, empty entries included, is preserved
			require.Len(t, img.History, 8)
			assert.Equal(t, []bool{true, false, true, true, false, true, false, true}, emptyLayerFlags(img))

			if v.compression == imagefixture.Uncompressed {
				assert.Equal(t, diffIDs, digests, "uncompressed layers hash to their diff ID")
				for _, mt := range mediaTypes {
					assert.Equal(t, "application/vnd.oci.image.layer.v1.tar", mt)
				}
			} else {
				for i, d := range digests {
					assert.NotEqual(t, diffIDs[i], d, "compressed layers differ from their diff ID")
				}
				suffix := map[imagefixture.Compression]string{imagefixture.Gzip: "+gzip", imagefixture.Zstd: "+zstd"}[v.compression]
				for _, mt := range mediaTypes {
					assert.Equal(t, "application/vnd.oci.image.layer.v1.tar"+suffix, mt, "compression must be sniffed from the content")
				}
			}

			// the layer content is readable and hashes to the reported digest
			for _, l := range img.Layers {
				rc, err := l.Open()
				require.NoError(t, err)
				got, err := digestOf(rc)
				require.NoError(t, err)
				require.NoError(t, rc.Close())
				assert.Equal(t, l.Digest, got)
			}
		})
	}
}

// source information is kept per format
func TestParse_sourceInfo(t *testing.T) {
	img := parse(t, writeSpecTar(t, alignmentSpec(imagefixture.PodmanSave, imagefixture.Uncompressed)), Options{Format: FormatDockerSave, TempDir: t.TempDir()})
	assert.Equal(t, FormatDockerSave, img.Source.Format)
	assert.Equal(t, []string{"dive-fixture:latest"}, img.Tags)

	// a docker 25+ save has both manifest.json and index.json; manifest.json wins
	img = parse(t, writeSpecTar(t, alignmentSpec(imagefixture.OCISave, imagefixture.Uncompressed)), Options{Format: FormatDockerSave, TempDir: t.TempDir()})
	assert.Equal(t, FormatDockerSave, img.Source.Format)
	assert.Equal(t, []string{"dive-fixture:latest"}, img.Tags)

	img = parse(t, writeSpecTar(t, alignmentSpec(imagefixture.OCIArchive, imagefixture.Uncompressed)), Options{Format: FormatOCI, TempDir: t.TempDir()})
	assert.Equal(t, FormatOCI, img.Source.Format)
	assert.NotEmpty(t, img.Source.ManifestDigest)
	assert.Equal(t, []string{"docker.io/library/dive-fixture:latest"}, img.Tags)
	assert.NotEmpty(t, img.Manifest, "the selected OCI manifest is kept")
}

// on-demand parsing defers payload reads but yields the same model and content
func TestParse_onDemand(t *testing.T) {
	path := writeSpecTar(t, alignmentSpec(imagefixture.OCISave, imagefixture.Gzip))

	spooled := parse(t, path, Options{Format: FormatDockerSave, TempDir: t.TempDir()})
	onDemand := parse(t, path, Options{Format: FormatDockerSave, OnDemand: true})

	wantDiffs, _, wantCmds, _ := layerSummary(spooled)
	gotDiffs, _, gotCmds, _ := layerSummary(onDemand)
	assert.Equal(t, wantDiffs, gotDiffs)
	assert.Equal(t, wantCmds, gotCmds)

	// the layer content comes out of the archive on demand and matches the spooled parse
	for i, l := range onDemand.Layers {
		rc, err := l.Open()
		require.NoError(t, err)
		got, err := digestOf(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())

		want, err := spooled.Layers[i].Open()
		require.NoError(t, err)
		wantDigest, err := digestOf(want)
		require.NoError(t, err)
		require.NoError(t, want.Close())
		assert.Equal(t, wantDigest, got)
	}
}

// a gzip layer labeled with the uncompressed media type still parses: the content decides
func TestParse_untrustedMediaType(t *testing.T) {
	layer, diffID := testLayer(t, "app/data", "payload")
	compressed := gzipBytes(t, layer)
	layerDigest := digestOfBytes(compressed)

	cfg := buildConfig(t, []string{diffID}, nil)
	cfgDigest := digestOfBytes(cfg)
	manifest := buildManifest(t, cfgDigest, int64(len(cfg)), []descJSON{
		{mediaType: "application/vnd.oci.image.layer.v1.tar", digest: layerDigest, size: int64(len(compressed))},
	})
	manifestDigest := digestOfBytes(manifest)

	dir := t.TempDir()
	writeBlobFile(t, dir, cfgDigest, cfg)
	writeBlobFile(t, dir, manifestDigest, manifest)
	writeBlobFile(t, dir, layerDigest, compressed)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"),
		buildIndex(t, []descJSON{{digest: manifestDigest, size: int64(len(manifest))}}), 0o644))

	img := parse(t, dir, Options{})
	require.Len(t, img.Layers, 1)
	assert.Equal(t, diffID, img.Layers[0].DiffID)
	assert.Equal(t, "application/vnd.oci.image.layer.v1.tar+gzip", img.Layers[0].MediaType,
		"the media type claim says uncompressed, the content is gzip")
}

// --- helpers for hand built OCI layouts ---

type descJSON struct {
	mediaType string
	digest    string
	size      int64
	platform  *Platform
}

func testLayer(t *testing.T, name, content string) (tarBytes []byte, diffID string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}))
	_, err := tw.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	return buf.Bytes(), digestOfBytes(buf.Bytes())
}

func digestOfBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func buildConfig(t *testing.T, diffIDs []string, history []History) []byte {
	t.Helper()
	type hist struct {
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer,omitempty"`
	}
	cfg := map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"rootfs":       map[string]any{"type": "layers", "diff_ids": diffIDs},
	}
	var hs []hist
	for _, h := range history {
		hs = append(hs, hist{CreatedBy: h.CreatedBy, EmptyLayer: h.EmptyLayer})
	}
	if hs != nil {
		cfg["history"] = hs
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	return data
}

func buildManifest(t *testing.T, configDigest string, configSize int64, layers []descJSON) []byte {
	t.Helper()
	type desc struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
	var ls []desc
	for _, l := range layers {
		mt := l.mediaType
		if mt == "" {
			mt = "application/vnd.oci.image.layer.v1.tar"
		}
		ls = append(ls, desc{MediaType: mt, Digest: l.digest, Size: l.size})
	}
	data, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        desc{MediaType: "application/vnd.oci.image.config.v1+json", Digest: configDigest, Size: configSize},
		"layers":        ls,
	})
	require.NoError(t, err)
	return data
}

func buildIndex(t *testing.T, manifests []descJSON) []byte {
	t.Helper()
	type desc struct {
		MediaType string    `json:"mediaType"`
		Digest    string    `json:"digest"`
		Size      int64     `json:"size"`
		Platform  *Platform `json:"platform,omitempty"`
	}
	var ds []desc
	for _, m := range manifests {
		mt := m.mediaType
		if mt == "" {
			mt = "application/vnd.oci.image.manifest.v1+json"
		}
		ds = append(ds, desc{MediaType: mt, Digest: m.digest, Size: m.size, Platform: m.platform})
	}
	data, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": ds})
	require.NoError(t, err)
	return data
}

func writeBlobFile(t *testing.T, dir, digest string, data []byte) {
	t.Helper()
	blobDir := filepath.Join(dir, "blobs", "sha256")
	require.NoError(t, os.MkdirAll(blobDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(blobDir, digest[len("sha256:"):]), data, 0o644))
}
