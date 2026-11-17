package archive

import (
	"encoding/json"
	"fmt"
	"strings"
)

// dockerManifestEntry is one image of a docker save's manifest.json.
type dockerManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// parseDockerSave reads the manifest.json layout of `docker save` and `podman save`. The layer order
// comes from the manifest's Layers list; the config it names only cross-checks. Entry names are
// followed as given, so the legacy (<id>/layer.tar), docker 25+ (blobs/sha256/…), podman (<hex>.tar)
// and kaniko (sha256:<hex>.json config, <hex>.tar.gz layers) namings all read the same way.
func parseDockerSave(path string, contents *tarContents, opts Options) (*Image, error) {
	src := Source{Path: path, Format: FormatDockerSave}

	raw, ok := contents.meta["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("%s: manifest.json is too large to be a manifest", src)
	}
	var manifests []dockerManifestEntry
	if err := json.Unmarshal(raw, &manifests); err != nil {
		return nil, fmt.Errorf("%s: manifest.json is not valid JSON: %w", src, err)
	}
	if len(manifests) == 0 {
		return nil, fmt.Errorf("%s: manifest.json lists no images", src)
	}
	if len(manifests) > 1 {
		var tags []string
		for _, m := range manifests {
			tags = append(tags, strings.Join(m.RepoTags, ", "))
		}
		return nil, fmt.Errorf("%s: manifest.json lists %d images (%s); dive reads single-image archives", src, len(manifests), strings.Join(tags, "; "))
	}
	m := manifests[0]

	rawConfig, ok := contents.meta[m.Config]
	if !ok {
		return nil, fmt.Errorf("%s: config %q named by manifest.json is not in the archive", src, m.Config)
	}
	configDoc := fmt.Sprintf("config %q", m.Config)
	cfg, err := parseConfig(rawConfig, configDoc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}

	lbs := make([]*layerBuilder, len(m.Layers))
	for i, entry := range m.Layers {
		b := &layerBuilder{index: i, doc: fmt.Sprintf("layer %d (%q)", i, entry), entry: entry}
		if data, ok := contents.meta[entry]; ok {
			b.data = data
			b.size = int64(len(data))
		} else if size, ok := contents.big[entry]; ok {
			b.size = size
		} else {
			return nil, fmt.Errorf("%s: layer %q named by manifest.json is not in the archive", src, entry)
		}
		lbs[i] = b
	}

	img := &Image{
		Source:  src,
		Tags:    m.RepoTags,
		Config:  rawConfig,
		History: cfg.history(),
	}
	ctx := &parseContext{opts: opts, src: src, archivePath: path}
	if err := resolveLayers(ctx, img, lbs, cfg.RootFS.DiffIDs, "manifest.json", configDoc); err != nil {
		return nil, err
	}
	img.cleanup = ctx.cleanup
	return img, nil
}
