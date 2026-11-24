// SPDX-License-Identifier: Apache-2.0

package pricetable

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// racyWindow is how recent a file's time stamps must be for them not to prove the file unchanged: a file written, and
// written again, within one tick of the file system's clock (which can be milliseconds, or whole seconds) has the same
// stamps both times, and a replacement made by rename can reuse the inode the last one freed. Inside the window the
// content decides.
const racyWindow = 3 * time.Second

// maxHashed bounds the bytes Identity reads of a table: a price table is a few kilobytes; a file past this is told
// apart by its stamps and its size alone.
const maxHashed = 4 << 20

// Identity names the price table file at path as it is now, so a reader that keeps what it computed from the table
// (the dashboard's receipts) computes again when the table has been replaced or edited, and never otherwise reuses it:
// the device, inode, size, modification time and change time from one stat of the open file, and, while any of those
// times is within racyWindow of now (the stamps then cannot tell two writes apart), the SHA-256 of the bytes read
// from that same open file. A file that cannot be read is named by its error, so its appearing changes the identity.
func Identity(path string) string {
	return identityAt(path, time.Now())
}

func identityAt(path string, now time.Time) string {
	f, err := os.Open(path)
	if err != nil {
		return path + "\x00absent:" + errKind(err)
	}
	defer func() { _ = f.Close() }() // read-only
	st, err := f.Stat()
	if err != nil {
		return path + "\x00unreadable"
	}
	stamps, newest, ok := fileStamps(st)
	var b strings.Builder
	b.WriteString(path)
	b.WriteByte(0)
	b.WriteString(stamps)
	if !ok || !now.Add(-racyWindow).After(newest) || newest.After(now) {
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, maxHashed+1))
		if err != nil || n > maxHashed {
			b.WriteString("\x00unhashed")
		} else {
			b.WriteString("\x00sha256:")
			b.WriteString(hex.EncodeToString(h.Sum(nil)))
		}
	}
	return b.String()
}

func errKind(err error) string {
	if os.IsNotExist(err) {
		return "missing"
	}
	return strconv.Quote(err.Error())
}
