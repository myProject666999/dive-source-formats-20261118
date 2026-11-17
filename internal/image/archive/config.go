package archive

import (
	"encoding/json"
	"fmt"
)

// imageConfig is the part of the image config this package reads.
type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	History []struct {
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

// parseConfig decodes the raw image config JSON. doc names it in errors ("config sha256:…").
func parseConfig(raw []byte, doc string) (*imageConfig, error) {
	var cfg imageConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s is not valid image config JSON: %w", doc, err)
	}
	return &cfg, nil
}

func (c *imageConfig) history() []History {
	var out []History
	for _, h := range c.History {
		out = append(out, History{CreatedBy: h.CreatedBy, EmptyLayer: h.EmptyLayer})
	}
	return out
}

// pairCommands matches each layer with the history entry that created it. History entries flagged
// empty_layer are metadata-only instructions (ENV, LABEL, CMD, …) that produced no filesystem layer,
// so they are skipped; indexing history directly against layers shifts every later pairing by one.
// Layers left over (history is optional, and may be shorter) get "(missing)".
func pairCommands(history []History, layers int) []string {
	commands := make([]string, layers)
	histIdx := 0
	for i := range layers {
		commands[i] = "(missing)"
		for histIdx < len(history) && history[histIdx].EmptyLayer {
			histIdx++
		}
		if histIdx < len(history) {
			commands[i] = history[histIdx].CreatedBy
			histIdx++
		}
	}
	return commands
}

// checkDiffIDs cross-checks the layer order the manifest gave against the config's rootfs.diff_ids.
// The manifest order is authoritative; the config only verifies it. A disagreement (different count,
// or a layer whose uncompressed digest is not the diff_id at its position) means the two documents
// order the layers differently or one of them is corrupt — either way the archive is inconsistent and
// reported, never silently resolved. A config without diff_ids offers nothing to check against.
func checkDiffIDs(src Source, manifestDoc, configDoc string, diffIDs, computed []string) error {
	if len(diffIDs) == 0 {
		return nil
	}
	if len(diffIDs) != len(computed) {
		return fmt.Errorf("%s: inconsistent archive: %s lists %d layers but %s has %d rootfs.diff_ids entries",
			src, manifestDoc, len(computed), configDoc, len(diffIDs))
	}
	for i := range diffIDs {
		if diffIDs[i] != computed[i] {
			return fmt.Errorf("%s: inconsistent archive: layer %d hashes to %s but %s has %s at that position — %s and %s order the layers differently",
				src, i, computed[i], configDoc, diffIDs[i], manifestDoc, configDoc)
		}
	}
	return nil
}
