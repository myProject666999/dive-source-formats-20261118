package archive

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// layerBuilder tracks where one layer's stored bytes come from while parsing.
type layerBuilder struct {
	index int
	// doc labels the layer for errors, e.g. `layer 2 (blobs/sha256/abc…)`
	doc string

	entry string // tar entry name (archive file sources)
	file  string // blob file path (OCI layout directory)
	data  []byte // buffered content, when the payload was small enough to keep
	spool string // temp file the payload was spooled to

	size         int64
	storedDigest string // sha256 the stored bytes must hash to, "" when the format does not say
	mediaType    string // the archive's own media type claim, used only until the content is sniffed
}

// storedBytes opens the layer's stored bytes in spool mode, when they are addressable without
// re-reading the archive.
func (b *layerBuilder) storedBytes() (io.ReadCloser, error) {
	switch {
	case b.data != nil:
		return io.NopCloser(bytes.NewReader(b.data)), nil
	case b.file != "":
		return os.Open(b.file)
	case b.spool != "":
		return os.Open(b.spool)
	default:
		return nil, fmt.Errorf("%s has no readable payload", b.doc)
	}
}

// finalize reads the layer's stored bytes, verifies the stored digest when the format provides one,
// and computes the diff ID. The compression is sniffed from the content.
func (b *layerBuilder) finalize(src Source) (Layer, error) {
	digest, size, err := b.storedSum()
	if err != nil {
		return Layer{}, fmt.Errorf("%s: %w", src, err)
	}
	if b.storedDigest != "" && digest != b.storedDigest {
		return Layer{}, fmt.Errorf("%s: %s hashes to %s but should be %s — the archive may be corrupt",
			src, b.doc, digest, b.storedDigest)
	}

	rc, err := b.storedBytes()
	if err != nil {
		return Layer{}, fmt.Errorf("%s: %w", src, err)
	}
	defer rc.Close() // nolint:errcheck
	dr, comp, err := decompress(rc)
	if err != nil {
		return Layer{}, fmt.Errorf("%s: %s: %w", src, b.doc, err)
	}
	diffID, err := digestOf(dr)
	dr.Close() // nolint:errcheck
	if err != nil {
		return Layer{}, fmt.Errorf("%s: reading %s: %w", src, b.doc, err)
	}

	b.size = size
	return Layer{
		Index:     b.index,
		DiffID:    diffID,
		Digest:    digest,
		Size:      size,
		MediaType: comp.mediaType(),
		open:      b.storedBytes,
	}, nil
}

// storedSum hashes the stored bytes and reports their size.
func (b *layerBuilder) storedSum() (string, int64, error) {
	rc, err := b.storedBytes()
	if err != nil {
		return "", 0, err
	}
	defer rc.Close() // nolint:errcheck
	digest, size, err := sumAndSize(rc)
	if err != nil {
		return "", 0, fmt.Errorf("reading %s: %w", b.doc, err)
	}
	return digest, size, nil
}

// resolveLayers turns the manifest's layer list into the image's Layers. In the default spool mode
// every layer payload is read and verified now, and the order is cross-checked against the config's
// rootfs.diff_ids. In OnDemand mode payloads are only read on Layer.Open: no temp disk and no
// decompression now, but the digest checks (and with them the order cross-check) are deferred to
// whoever reads the layers, and DiffID/Digest/MediaType here are the archive's unverified claims.
func resolveLayers(ctx *parseContext, img *Image, lbs []*layerBuilder, diffIDs []string, manifestDoc, configDoc string) error {
	if len(diffIDs) != 0 && len(diffIDs) != len(lbs) {
		return fmt.Errorf("%s: inconsistent archive: %s lists %d layers but %s has %d rootfs.diff_ids entries",
			img.Source, manifestDoc, len(lbs), configDoc, len(diffIDs))
	}

	if ctx.opts.OnDemand {
		for i, b := range lbs {
			img.Layers = append(img.Layers, onDemandLayer(ctx, b, diffIDs, i))
		}
	} else {
		if err := spoolMissing(ctx, lbs); err != nil {
			return fmt.Errorf("%s: %w", img.Source, err)
		}
		computed := make([]string, len(lbs))
		for i, b := range lbs {
			l, err := b.finalize(img.Source)
			if err != nil {
				return err
			}
			computed[i] = l.DiffID
			img.Layers = append(img.Layers, l)
		}
		if err := checkDiffIDs(img.Source, manifestDoc, configDoc, diffIDs, computed); err != nil {
			return err
		}
	}

	commands := pairCommands(img.History, len(img.Layers))
	for i := range img.Layers {
		img.Layers[i].Command = commands[i]
	}
	return nil
}

// spoolMissing copies every layer payload that is neither buffered nor already a file out of the
// archive into the spool dir, in a single pass.
func spoolMissing(ctx *parseContext, lbs []*layerBuilder) error {
	if ctx.archivePath == "" {
		return nil // an OCI layout directory needs no spooling
	}
	var need []string
	byEntry := map[string]*layerBuilder{}
	for _, b := range lbs {
		if b.data == nil && b.file == "" && b.spool == "" {
			need = append(need, b.entry)
			byEntry[b.entry] = b
		}
	}
	if len(need) == 0 {
		return nil
	}
	dir, cleanup, err := ctx.spoolDir()
	if err != nil {
		return err
	}
	spooled, err := spoolEntries(ctx.archivePath, need, dir)
	if err != nil {
		cleanup() // nolint:errcheck
		return err
	}
	for entry, s := range spooled {
		b := byEntry[entry]
		b.spool = s.path
		b.size = s.size
		if b.storedDigest == "" {
			b.storedDigest = s.digest // computed while spooling; finalize re-checks cheaply
		} else if b.storedDigest != s.digest {
			return fmt.Errorf("%s hashes to %s but should be %s — the archive may be corrupt", b.doc, s.digest, b.storedDigest)
		}
	}
	return nil
}

// onDemandLayer builds a layer whose payload is read (and verified) only when opened.
func onDemandLayer(ctx *parseContext, b *layerBuilder, diffIDs []string, i int) Layer {
	l := Layer{
		Index:     b.index,
		Digest:    b.storedDigest,
		Size:      b.size,
		MediaType: b.mediaType,
	}
	if i < len(diffIDs) {
		l.DiffID = diffIDs[i]
	}
	if l.Digest == "" {
		l.Digest = l.DiffID
	}
	l.open = func() (io.ReadCloser, error) {
		var rc io.ReadCloser
		var err error
		switch {
		case b.data != nil:
			rc = io.NopCloser(bytes.NewReader(b.data))
		case b.file != "":
			rc, err = os.Open(b.file)
		default:
			rc, err = openTarEntry(ctx.archivePath, b.entry)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ctx.src, err)
		}
		if b.storedDigest != "" {
			rc = &verifyingReadCloser{ReadCloser: rc, want: b.storedDigest, doc: b.doc, src: ctx.src}
		}
		return rc, nil
	}
	return l
}
