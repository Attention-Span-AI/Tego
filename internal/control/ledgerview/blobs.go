// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/linewords"
)

// The line page's blobs: every payload field the writer moved to <run>/blobs/<sha256> because it was over its blob
// threshold. It names the blob as <field>_blob, or as blob for a body (internal/ledger/blob.go blobKey). A request
// body stored as a splice (body_sha256, frame, messages) is no file holding the body whole, so it is named and not read
// (spliceKeys). Each blob is read as ReadBlob reads one: read-only, no link followed, a regular file of at most
// MaxBlobBytes whose sha256 is its name. A blob that fails any check is shown as not verified, and none of its
// content is shown.

// BlobRef is one blob a line names, as the line page shows it.
type BlobRef struct {
	SHA string
	// Size is the blob file's size, 0 when it could not be looked at.
	Size int64
	// Verified is set when the file was read whole and hashes to SHA. Only then is Inline set.
	Verified bool
	// Inline is the content as text, credential-looking values hidden (linewords.Mask): a list of strings (an argv,
	// a command) joined with spaces, other text as it is. It is "" when the content is not text.
	Inline string
	// Binary is set for verified content that is not UTF-8 text (a compressed body), which is not shown.
	Binary bool
	// Why is why the blob is not verified, in words, "" when it is.
	Why string
}

// spliceKeys are the fields of a request body stored as a splice (internal/ledger messages.go): hashes that name
// pieces of the body, not a file holding it.
var spliceKeys = map[string]bool{"body_sha256": true, "frame": true, "messages": true}

// isBlobKey reports whether a payload key names a whole blob: <field>_blob, or blob.
func isBlobKey(key string) bool {
	return key == "blob" || (strings.HasSuffix(key, "_blob") && !strings.Contains(key, "."))
}

// resolveBlobRef reads blob sha of runDir for the line page.
func resolveBlobRef(runDir, sha string) *BlobRef {
	b := &BlobRef{SHA: sha}
	if validSHA(sha) {
		if fi, err := os.Lstat(filepath.Join(runDir, "blobs", sha)); err == nil && fi.Mode().IsRegular() {
			b.Size = fi.Size()
		}
	}
	content, err := ReadBlob(runDir, sha, MaxBlobBytes)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			b.Why = "the blob file is missing"
		case errors.Is(err, syscall.ELOOP):
			b.Why = "the blob is a symbolic link, which Tego never writes"
		case b.Size > MaxBlobBytes:
			b.Why = "the blob is larger than the dashboard reads"
		case errors.Is(err, ErrBlob) && strings.Contains(err.Error(), "does not hash"):
			b.Why = "the blob's content does not match its hash: it was changed after it was written"
		default:
			b.Why = "the blob could not be read"
		}
		return b
	}
	b.Verified = true
	var list []string
	switch {
	case json.Unmarshal(content, &list) == nil:
		b.Inline = linewords.Mask(strings.Join(list, " "))
	case utf8.Valid(content):
		b.Inline = linewords.Mask(string(content))
	default:
		b.Binary = true
	}
	return b
}
