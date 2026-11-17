package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

// digestOf hashes what r yields and returns the "sha256:<hex>" digest.
func digestOf(r io.Reader) (string, error) {
	digest, _, err := sumAndSize(r)
	return digest, err
}

// sumAndSize hashes what r yields and also reports its length in bytes.
func sumAndSize(r io.Reader) (string, int64, error) {
	h := sha256.New()
	size, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), size, nil
}

// verifyingReadCloser hashes what is read and, at EOF, fails the read when the digest is not want.
type verifyingReadCloser struct {
	io.ReadCloser
	h    hash.Hash
	want string
	doc  string
	src  Source
	done bool
}

func (r *verifyingReadCloser) Read(p []byte) (int, error) {
	if r.h == nil {
		r.h = sha256.New()
	}
	n, err := r.ReadCloser.Read(p)
	r.h.Write(p[:n])
	if err != nil && !errors.Is(err, io.EOF) {
		return n, err
	}
	if err != nil && !r.done {
		r.done = true
		got := "sha256:" + hex.EncodeToString(r.h.Sum(nil))
		if got != r.want {
			return n, fmt.Errorf("%s: %s hashes to %s but should be %s — the archive may be corrupt", r.src, r.doc, got, r.want)
		}
	}
	return n, err
}

// checkDigest validates the form of a content digest. Only sha256 is supported: every blob address in
// the layouts this package reads is one, and anything else (including a digest crafted to traverse out
// of a blob directory, like "sha256:../x") is rejected here before it is ever turned into a path.
func checkDigest(digest string) error {
	algo, hexPart, ok := strings.Cut(digest, ":")
	if !ok || algo != "sha256" {
		return fmt.Errorf("unsupported digest %q (only sha256 is supported)", algo+":"+hexPart)
	}
	if len(hexPart) != sha256.Size*2 {
		return fmt.Errorf("invalid sha256 digest %q", digest)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Errorf("invalid sha256 digest %q", digest)
	}
	return nil
}
