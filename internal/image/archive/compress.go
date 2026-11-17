package archive

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// compression is a detected payload encoding.
type compression int

const (
	uncompressed compression = iota
	gzipCompressed
	zstdCompressed
)

// mediaType is the OCI layer media type for the detected compression.
func (c compression) mediaType() string {
	switch c {
	case gzipCompressed:
		return "application/vnd.oci.image.layer.v1.tar+gzip"
	case zstdCompressed:
		return "application/vnd.oci.image.layer.v1.tar+zstd"
	default:
		return "application/vnd.oci.image.layer.v1.tar"
	}
}

// decompress wraps r with the decompressor its leading bytes indicate (gzip or zstd magic); anything
// else is treated as an uncompressed tar. The archive's media type strings are deliberately not
// consulted: they are claims, the content is the fact. The detected compression is returned alongside.
func decompress(r io.Reader) (io.ReadCloser, compression, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(4)
	if err != nil && err != io.EOF {
		return nil, 0, err
	}
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid gzip stream: %w", err)
		}
		return zr, gzipCompressed, nil
	case len(head) >= 4 && head[0] == 0x28 && head[1] == 0xb5 && head[2] == 0x2f && head[3] == 0xfd:
		zr, err := zstd.NewReader(br)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid zstd stream: %w", err)
		}
		return zr.IOReadCloser(), zstdCompressed, nil
	default:
		return io.NopCloser(br), uncompressed, nil
	}
}
