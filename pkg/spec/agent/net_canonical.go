// SPDX-License-Identifier: Apache-2.0

package agent

import "gopkg.in/yaml.v3"

// MarshalYAML preserves explicit empty admission lists. Dropping [] would turn
// a deny-all policy into the absent, unrestricted policy on ledger reload.
func (s NetSection) MarshalYAML() (any, error) {
	type plain NetSection
	p := plain(s)
	var empty []string
	if s.Listen != nil && len(s.Listen) == 0 {
		p.Listen = []string{""}
		empty = append(empty, "listen")
	}
	if s.Ingress != nil && len(s.Ingress) == 0 {
		p.Ingress = []IngressRule{{}}
		empty = append(empty, "ingress")
	}
	return marshalNetworkLists(p, empty)
}

// MarshalYAML retains deny-all names/types independently of their defaults.
func (s DNSPolicy) MarshalYAML() (any, error) {
	type plain DNSPolicy
	p := plain(s)
	var empty []string
	if s.Allow != nil && len(s.Allow) == 0 {
		p.Allow = []string{""}
		empty = append(empty, "allow")
	}
	if s.Types != nil && len(s.Types) == 0 {
		p.Types = []string{""}
		empty = append(empty, "types")
	}
	return marshalNetworkLists(p, empty)
}

func marshalNetworkLists(value any, empty []string) (any, error) {
	if len(empty) == 0 {
		return value, nil
	}
	var n yaml.Node
	if err := n.Encode(value); err != nil {
		return nil, err
	}
	untagMerge(&n)
	for i := 0; i+1 < len(n.Content); i += 2 {
		for _, key := range empty {
			if n.Content[i].Value == key {
				n.Content[i+1].Content = nil
			}
		}
	}
	return &n, nil
}
