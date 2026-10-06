// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/net/dns/dnsmessage"
)

func init() { register(cmdDNS) }

func cmdDNS() Command {
	var runDir, typ string
	var serverPID int
	var asJSON bool
	return Command{Name: "dns", Summary: "query the governed run's DNS broker", Usage: "<name> [--type A] [--run-dir path] [--server-pid pid] [--json]",
		Flags: func(f *flag.FlagSet) {
			pid, _ := strconv.Atoi(os.Getenv("TEGO_DNS_BROKER_PID"))
			f.StringVar(&runDir, "run-dir", os.Getenv("TEGO_DNS_BROKER_DIR"), "private broker socket directory announced by the run (not its ledger directory)")
			f.IntVar(&serverPID, "server-pid", pid, "expected broker launcher PID")
			f.StringVar(&typ, "type", "A", "DNS question type")
			f.BoolVar(&asJSON, "json", false, "one JSON response object")
		}, Run: func(ctx context.Context, f *flag.FlagSet, out, errs io.Writer) int {
			if f.NArg() != 1 || runDir == "" || serverPID <= 0 {
				message(errs, "", 0, 0, "tego dns: one name and an authenticated run broker are required (--run-dir/--server-pid or governed broker environment)", codeUsage)
				return identity.ExitUsage
			}
			name, e := dnspolicy.CanonicalName(f.Arg(0))
			typeID, valid := dnspolicy.Type(typ)
			if e != nil || !valid {
				message(errs, "", 0, 0, "tego dns: invalid name or question type", codeUsage)
				return identity.ExitUsage
			}
			if name != "." {
				name += "."
			}
			wireName, e := dnsmessage.NewName(name)
			if e != nil {
				message(errs, "", 0, 0, "tego dns: invalid DNS name", codeUsage)
				return identity.ExitUsage
			}
			var id [2]byte
			if _, e = rand.Read(id[:]); e != nil {
				message(errs, "", 0, 0, "tego dns: "+e.Error(), codeIO)
				return identity.ExitError
			}
			q := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: wireName, Type: dnsmessage.Type(typeID), Class: dnsmessage.ClassINET}}}
			raw, e := q.Pack()
			if e == nil {
				raw, e = dnsbroker.Exchange(ctx, runDir, serverPID, raw)
			}
			if e != nil {
				message(errs, "", 0, 0, "tego dns: "+e.Error(), codeIO)
				return identity.ExitError
			}
			var response dnsmessage.Message
			if e = response.Unpack(raw); e != nil {
				message(errs, "", 0, 0, "tego dns: invalid broker response", codeIO)
				return identity.ExitError
			}
			if asJSON {
				e = json.NewEncoder(out).Encode(struct {
					Name    string                `json:"name"`
					Type    string                `json:"type"`
					RCode   string                `json:"rcode"`
					Answers []dnsmessage.Resource `json:"answers"`
				}{name, dnsmessage.Type(typeID).String(), response.RCode.String(), response.Answers})
			} else {
				_, e = fmt.Fprintf(out, "%s %s %s\n", name, dnsmessage.Type(typeID), response.RCode)
				for _, a := range response.Answers {
					if e != nil {
						break
					}
					var body []byte
					body, e = json.Marshal(a.Body)
					if e == nil {
						_, e = fmt.Fprintf(out, "%s %d %s %s\n", record.Printable(a.Header.Name.String()), a.Header.TTL, a.Header.Type, body)
					}
				}
			}
			if e != nil {
				message(errs, "", 0, 0, "tego dns: output: "+e.Error(), codeIO)
				return identity.ExitError
			}
			if response.RCode != dnsmessage.RCodeSuccess {
				return identity.ExitFinding
			}
			return identity.ExitOK
		}}
}
