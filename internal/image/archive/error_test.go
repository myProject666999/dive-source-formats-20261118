package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// a docker save whose config orders the diff_ids differently than manifest.json orders the layers
// is inconsistent and must not be silently resolved
func TestParse_orderConflict(t *testing.T) {
	layerA, diffA := testLayer(t, "a", "aaa")
	layerB, diffB := testLayer(t, "b", "bbb")

	config := buildConfig(t, []string{diffB, diffA}, nil) // swapped: config disagrees with the layer order
	manifest, err := json.Marshal([]map[string]any{{
		"Config":   "config.json",
		"RepoTags": []string{"test:latest"},
		"Layers":   []string{"a.tar", "b.tar"},
	}})
	require.NoError(t, err)

	path := writeTarFiles(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   config,
		"a.tar":         layerA,
		"b.tar":         layerB,
	})

	_, err = Parse(path, Options{Format: FormatDockerSave, TempDir: t.TempDir()})
	require.ErrorContains(t, err, "inconsistent")
	assert.Contains(t, err.Error(), "manifest.json")
	assert.Contains(t, err.Error(), "config")
	assert.Contains(t, err.Error(), path, "the error names the archive at fault")
}

// a diff_ids count that does not match the layer count is inconsistent too
func TestParse_diffIDCountMismatch(t *testing.T) {
	layerA, diffA := testLayer(t, "a", "aaa")
	layerB, diffB := testLayer(t, "b", "bbb")

	config := buildConfig(t, []string{diffA, diffB, diffA}, nil) // one diff_id too many
	manifest, err := json.Marshal([]map[string]any{{
		"Config": "config.json",
		"Layers": []string{"a.tar", "b.tar"},
	}})
	require.NoError(t, err)

	path := writeTarFiles(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   config,
		"a.tar":         layerA,
		"b.tar":         layerB,
	})

	_, err = Parse(path, Options{Format: FormatDockerSave, TempDir: t.TempDir()})
	require.ErrorContains(t, err, "inconsistent")
	assert.Contains(t, err.Error(), "3 rootfs.diff_ids")
}

// a tampered OCI layer blob fails the digest check
func TestParse_tamperedLayerBlob(t *testing.T) {
	layer, diffID := testLayer(t, "a", "aaa")
	layerDigest := digestOfBytes(layer)
	cfg := buildConfig(t, []string{diffID}, nil)
	cfgDigest := digestOfBytes(cfg)
	manifest := buildManifest(t, cfgDigest, int64(len(cfg)), []descJSON{{digest: layerDigest, size: int64(len(layer))}})
	manifestDigest := digestOfBytes(manifest)

	dir := t.TempDir()
	writeBlobFile(t, dir, cfgDigest, cfg)
	writeBlobFile(t, dir, manifestDigest, manifest)
	tampered := bytes.Clone(layer)
	tampered[512] ^= 0xff // first tar block, still a plausible size
	writeBlobFile(t, dir, layerDigest, tampered)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"),
		buildIndex(t, []descJSON{{digest: manifestDigest, size: int64(len(manifest))}}), 0o644))

	_, err := Parse(dir, Options{})
	require.ErrorContains(t, err, "corrupt")
	assert.Contains(t, err.Error(), layerDigest)
}

// a tampered config blob fails the digest check and names the config
func TestParse_tamperedConfigBlob(t *testing.T) {
	layer, diffID := testLayer(t, "a", "aaa")
	layerDigest := digestOfBytes(layer)
	cfg := buildConfig(t, []string{diffID}, nil)
	cfgDigest := digestOfBytes(cfg)
	manifest := buildManifest(t, cfgDigest, int64(len(cfg)), []descJSON{{digest: layerDigest, size: int64(len(layer))}})
	manifestDigest := digestOfBytes(manifest)

	dir := t.TempDir()
	writeBlobFile(t, dir, cfgDigest, []byte(`{"architecture":"amd64"}`)) // not what the digest addresses
	writeBlobFile(t, dir, manifestDigest, manifest)
	writeBlobFile(t, dir, layerDigest, layer)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"),
		buildIndex(t, []descJSON{{digest: manifestDigest, size: int64(len(manifest))}}), 0o644))

	_, err := Parse(dir, Options{})
	require.ErrorContains(t, err, "corrupt")
	assert.Contains(t, err.Error(), "config "+cfgDigest)
}

// tar entries that walk up out of the archive root are rejected
func TestParse_pathTraversal(t *testing.T) {
	for _, name := range []string{"../evil.json", "a/../../evil.json", "/etc/passwd"} {
		t.Run(name, func(t *testing.T) {
			path := writeTarFiles(t, map[string][]byte{name: []byte("x"), "manifest.json": []byte("[]")})
			_, err := Parse(path, Options{Format: FormatDockerSave, TempDir: t.TempDir()})
			require.ErrorContains(t, err, "unsafe tar entry")
		})
	}
}

// a digest crafted to escape the blob directory is rejected before it becomes a path
func TestParse_digestTraversal(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"),
		buildIndex(t, []descJSON{{digest: "sha256:../index.json", size: 10}}), 0o644))
	_, err := Parse(dir, Options{})
	require.ErrorContains(t, err, "invalid sha256 digest")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"),
		buildIndex(t, []descJSON{{digest: "sha512:" + strings.Repeat("ab", 32), size: 10}}), 0o644))
	_, err = Parse(dir, Options{})
	require.ErrorContains(t, err, "only sha256")
}

// platform selection: the requested platform wins, the host platform is the default, and a platform
// the index does not have is an error listing what is available
func TestParse_platformSelection(t *testing.T) {
	newLayout := func(t *testing.T) string {
		dir := t.TempDir()
		var manifests []descJSON
		for _, arch := range []string{"amd64", "arm64"} {
			layer, diffID := testLayer(t, arch, arch)
			layerDigest := digestOfBytes(layer)
			cfg := buildConfig(t, []string{diffID}, nil)
			cfgDigest := digestOfBytes(cfg)
			manifest := buildManifest(t, cfgDigest, int64(len(cfg)), []descJSON{{digest: layerDigest, size: int64(len(layer))}})
			manifestDigest := digestOfBytes(manifest)
			writeBlobFile(t, dir, layerDigest, layer)
			writeBlobFile(t, dir, cfgDigest, cfg)
			writeBlobFile(t, dir, manifestDigest, manifest)
			manifests = append(manifests, descJSON{digest: manifestDigest, size: int64(len(manifest)), platform: &Platform{OS: "linux", Architecture: arch}})
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), buildIndex(t, manifests), 0o644))
		return dir
	}

	t.Run("requested platform", func(t *testing.T) {
		img := parse(t, newLayout(t), Options{Platform: &Platform{OS: "linux", Architecture: "arm64"}})
		require.Len(t, img.Layers, 1)
		assert.Equal(t, Platform{OS: "linux", Architecture: "arm64"}, img.Source.Platform)
	})

	t.Run("host platform is the default", func(t *testing.T) {
		img := parse(t, newLayout(t), Options{})
		assert.Equal(t, runtime.GOARCH, img.Source.Platform.Architecture)
	})

	t.Run("no match lists the available platforms", func(t *testing.T) {
		_, err := Parse(newLayout(t), Options{Platform: &Platform{OS: "linux", Architecture: "s390x"}})
		require.ErrorContains(t, err, "linux/s390x")
		assert.Contains(t, err.Error(), "linux/amd64")
		assert.Contains(t, err.Error(), "linux/arm64")
	})
}

// nested indexes are followed, up to the depth limit
func TestParse_nestedIndex(t *testing.T) {
	layer, diffID := testLayer(t, "a", "aaa")
	layerDigest := digestOfBytes(layer)
	cfg := buildConfig(t, []string{diffID}, nil)
	cfgDigest := digestOfBytes(cfg)
	manifest := buildManifest(t, cfgDigest, int64(len(cfg)), []descJSON{{digest: layerDigest, size: int64(len(layer))}})

	// chain of nested indexes ending at the manifest
	chain := func(t *testing.T, dir string, depth int) []byte {
		digest := digestOfBytes(manifest)
		mediaType := "application/vnd.oci.image.manifest.v1+json"
		size := int64(len(manifest))
		for i := 0; i < depth; i++ {
			idx := buildIndex(t, []descJSON{{mediaType: mediaType, digest: digest, size: size}})
			writeBlobFile(t, dir, digestOfBytes(idx), idx)
			digest = digestOfBytes(idx)
			mediaType = "application/vnd.oci.image.index.v1+json"
			size = int64(len(idx))
		}
		return buildIndex(t, []descJSON{{mediaType: mediaType, digest: digest, size: size}})
	}

	t.Run("within the limit", func(t *testing.T) {
		dir := t.TempDir()
		writeBlobFile(t, dir, layerDigest, layer)
		writeBlobFile(t, dir, cfgDigest, cfg)
		writeBlobFile(t, dir, digestOfBytes(manifest), manifest)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), chain(t, dir, 3), 0o644))
		img := parse(t, dir, Options{})
		require.Len(t, img.Layers, 1)
		assert.Equal(t, diffID, img.Layers[0].DiffID)
	})

	t.Run("beyond the limit", func(t *testing.T) {
		dir := t.TempDir()
		writeBlobFile(t, dir, layerDigest, layer)
		writeBlobFile(t, dir, cfgDigest, cfg)
		writeBlobFile(t, dir, digestOfBytes(manifest), manifest)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), chain(t, dir, 9), 0o644))
		_, err := Parse(dir, Options{})
		require.ErrorContains(t, err, "nest deeper")
	})
}

// a docker save with several images is refused, naming them
func TestParse_multipleImages(t *testing.T) {
	manifest, err := json.Marshal([]map[string]any{
		{"Config": "a.json", "RepoTags": []string{"one:1"}, "Layers": []string{}},
		{"Config": "b.json", "RepoTags": []string{"two:2"}, "Layers": []string{}},
	})
	require.NoError(t, err)
	path := writeTarFiles(t, map[string][]byte{"manifest.json": manifest})
	_, err = Parse(path, Options{Format: FormatDockerSave, TempDir: t.TempDir()})
	require.ErrorContains(t, err, "2 images")
	assert.Contains(t, err.Error(), "one:1")
	assert.Contains(t, err.Error(), "two:2")
}

// small malformed inputs get clear errors
func TestParse_malformed(t *testing.T) {
	t.Run("not an image archive", func(t *testing.T) {
		path := writeTarFiles(t, map[string][]byte{"readme.txt": []byte("hello")})
		_, err := Parse(path, Options{})
		require.ErrorContains(t, err, "not a recognized image archive")
	})

	t.Run("not a tar", func(t *testing.T) {
		path := writeTarFiles(t, nil)
		require.NoError(t, os.WriteFile(path, []byte("this is not a tar file at all..........."), 0o644))
		_, err := Parse(path, Options{})
		require.ErrorContains(t, err, "unable to read archive")
	})

	t.Run("missing archive", func(t *testing.T) {
		_, err := Parse(filepath.Join(t.TempDir(), "nope.tar"), Options{})
		require.Error(t, err)
	})

	t.Run("layer missing from the archive", func(t *testing.T) {
		config := buildConfig(t, nil, nil)
		manifest, err := json.Marshal([]map[string]any{{"Config": "config.json", "Layers": []string{"gone.tar"}}})
		require.NoError(t, err)
		path := writeTarFiles(t, map[string][]byte{"manifest.json": manifest, "config.json": config})
		_, err = Parse(path, Options{Format: FormatDockerSave, TempDir: t.TempDir()})
		require.ErrorContains(t, err, `"gone.tar"`)
	})

	t.Run("config missing from the archive", func(t *testing.T) {
		manifest, err := json.Marshal([]map[string]any{{"Config": "gone.json", "Layers": []string{}}})
		require.NoError(t, err)
		path := writeTarFiles(t, map[string][]byte{"manifest.json": manifest})
		_, err = Parse(path, Options{Format: FormatDockerSave, TempDir: t.TempDir()})
		require.ErrorContains(t, err, `"gone.json"`)
	})

	t.Run("oci dir without index.json", func(t *testing.T) {
		_, err := Parse(t.TempDir(), Options{})
		require.ErrorContains(t, err, "not an OCI image layout")
	})

	t.Run("format pinned to the wrong layout", func(t *testing.T) {
		path := writeTarFiles(t, map[string][]byte{"manifest.json": []byte("[]")})
		_, err := Parse(path, Options{Format: FormatOCI})
		require.ErrorContains(t, err, "not an OCI image archive")
	})
}

// a gzipped tar archive reads like the plain one
func TestParse_gzippedArchive(t *testing.T) {
	layer, diffID := testLayer(t, "a", "aaa")
	config := buildConfig(t, []string{diffID}, []History{{CreatedBy: "ADD /"}})
	manifest, err := json.Marshal([]map[string]any{{"Config": "config.json", "Layers": []string{"a.tar"}}})
	require.NoError(t, err)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range map[string][]byte{"manifest.json": manifest, "config.json": config, "a.tar": layer} {
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	path := filepath.Join(t.TempDir(), "img.tar.gz")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))

	img := parse(t, path, Options{Format: FormatDockerSave, TempDir: t.TempDir()})
	require.Len(t, img.Layers, 1)
	assert.Equal(t, diffID, img.Layers[0].DiffID)
	assert.Equal(t, "ADD /", img.Layers[0].Command)
}
