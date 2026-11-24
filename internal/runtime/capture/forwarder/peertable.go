// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
)

// tcpTableOpened, when set, is called with the name of each /proc/net/tcp-shaped table a read opens; a test counts
// reads with it.
var tcpTableOpened func(name string)

// tcpTables reads the kernel's TCP tables for peerSocketInode, where sock_diag does not answer.
//
// The table lists every TCP socket of the network namespace, and one lookup reads it row by row: 20 to 35 ms for
// 100,000 rows. Each connection's lookup read it whole, so a pool of agent connections opened together read it once
// each, on the accepting goroutines, and a busy host's cost grew with its connections times the connections arriving.
// Now the lookups share reads. A lookup registers its connection in the batch that has not started reading, and one
// read of the tables, started after every lookup in it registered, answers all of them; lookups that arrive while
// a read runs make the next batch, and a read starts right after the last one ends. So N concurrent lookups cost at
// most two reads, however large the table, and no connection is answered from a table older than its own arrival:
// nothing is cached across batches, so a connection the record needs is never hidden by a stale snapshot. A lookup
// still waits for a read of the whole table (one read, not one per connection ahead of it); the batch is bounded by
// the connections open at once (Options.MaxConns), and the rows are matched as they stream, never held.
type tcpTableReader struct {
	mu      sync.Mutex
	next    *tcpBatch // lookups waiting for the next read
	reading bool      // a read is running or handed on
}

// tcpBatch is the lookups one read answers.
type tcpBatch struct {
	wants map[connKey]*tcpWant
	done  chan struct{}
}

// tcpWant is one lookup's answer, written by the read before done closes.
type tcpWant struct {
	inode   uint64
	found   bool
	err     error
	decided bool
}

// tcpTables is the process's reader.
var tcpTables = &tcpTableReader{}

// lookup is peerSocketInode's answer for the connection peer -> local through a shared read.
func (t *tcpTableReader) lookup(peer, local netip.AddrPort) (uint64, error) {
	k := connKey{peer: peer, local: local}
	t.mu.Lock()
	b := t.next
	if b == nil {
		b = &tcpBatch{wants: map[connKey]*tcpWant{}, done: make(chan struct{})}
		t.next = b
	}
	w := b.wants[k]
	if w == nil {
		w = &tcpWant{}
		b.wants[k] = w
	}
	lead := !t.reading
	t.reading = true
	t.mu.Unlock()
	if lead {
		t.drive()
	}
	<-b.done
	if w.err != nil {
		return 0, w.err
	}
	return w.inode, nil
}

// drive reads for the batch that is waiting and answers it, then hands the next batch, if one gathered meanwhile, to
// another goroutine, so the lookup that led this read returns with its own answer.
func (t *tcpTableReader) drive() {
	t.mu.Lock()
	b := t.next
	t.next = nil
	t.mu.Unlock()
	readTables(b.wants)
	close(b.done)
	t.mu.Lock()
	if t.next != nil {
		go t.drive()
	} else {
		t.reading = false
	}
	t.mu.Unlock()
}

// readTables answers every lookup of wants from one pass over the tables, in peerSocketInode's order and with its
// errors: the first table that holds the connection answers it, a row with no inode is that connection's error alone,
// and a table that cannot be read is every undecided connection's.
func readTables(wants map[connKey]*tcpWant) {
	undecided := len(wants)
	fail := func(err error) {
		for _, w := range wants {
			if !w.decided {
				w.err, w.decided = err, true
			}
		}
	}
	for _, name := range procNetTCP {
		if undecided == 0 {
			return
		}
		if tcpTableOpened != nil {
			tcpTableOpened(name)
		}
		f, err := os.Open(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // a kernel built without IPv6 has no tcp6 table
			}
			fail(fmt.Errorf("%w: open %s: %w", ErrPeer, name, err))
			return
		}
		n, err := scanTCPTableSet(f, wants)
		_ = f.Close()
		if err != nil {
			fail(err)
			return
		}
		undecided -= n
	}
	for k, w := range wants {
		if !w.decided {
			w.err, w.decided = fmt.Errorf("%w: no socket for %s -> %s in the kernel's tcp table", ErrPeer, k.peer, k.local), true
		}
	}
}

// scanTCPTableSet is scanTCPTable for many connections at once: it reads one /proc/net/tcp-shaped table and decides
// each undecided connection of wants whose row it holds, returning how many it decided. A connection's first row wins,
// as scanTCPTable's does.
func scanTCPTableSet(r io.Reader, wants map[connKey]*tcpWant) (int, error) {
	decided := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	sc.Scan() // the column header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) <= tcpTableInodeField {
			continue
		}
		rowLocal, ok := parseProcAddrPort(fields[1])
		if !ok {
			continue
		}
		rowRemote, ok := parseProcAddrPort(fields[2])
		if !ok {
			continue
		}
		w := wants[connKey{peer: rowLocal, local: rowRemote}]
		if w == nil || w.decided {
			continue
		}
		w.decided = true
		decided++
		inode, err := strconv.ParseUint(fields[tcpTableInodeField], 10, 64)
		switch {
		case err != nil:
			w.err = fmt.Errorf("%w: tcp table inode %q: %w", ErrPeer, fields[tcpTableInodeField], err)
		case inode == 0:
			// An orphaned socket, closed by its process and lingering in FIN_WAIT2 or TIME_WAIT, has no inode (see
			// scanTCPTable).
			w.err = fmt.Errorf("%w: the socket for %s -> %s has no inode: no process holds it", ErrPeer, rowLocal, rowRemote)
		default:
			w.inode, w.found = inode, true
		}
	}
	if err := sc.Err(); err != nil {
		return decided, fmt.Errorf("%w: read tcp table: %w", ErrPeer, err)
	}
	return decided, nil
}
