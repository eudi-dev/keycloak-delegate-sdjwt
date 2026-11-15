// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command vectorgen writes the Delegate SD-JWT test vectors of the Java tests.
// The eudi-dev Go library builds and checks each chain, so both
// implementations read the same bytes.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

const (
	issuerURL = "https://register.example"
	audience  = "https://iam.acme.example/realms/acme"
	nonce     = "YWNtZS1ub25jZQ"
	now       = 1794571300
)

type vector struct {
	Description string         `json:"description"`
	IssuerJWK   map[string]any `json:"issuer_jwk"`
	Audience    string         `json:"audience"`
	Nonce       string         `json:"nonce"`
	Now         int64          `json:"now"`
	Valid       bool           `json:"valid"`
	Principal   string         `json:"principal"`
	Agents      []string       `json:"agents"`
	Actions     []string       `json:"actions"`
	Chain       string         `json:"chain"`
}

func main() {
	out := flag.String("out", "src/test/resources/vectors", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	for _, links := range []int{1, 2, 4, 5} {
		v, err := build(links)
		if err != nil {
			log.Fatalf("%d links: %v", links, err)
		}
		encoded, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		name := filepath.Join(*out, fmt.Sprintf("chain-%d-links.json", links))
		if err := os.WriteFile(name, append(encoded, '\n'), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

// linkActions narrows the delegated actions with each link.
var linkActions = [][]string{
	{"invoice.approve", "invoice.read", "order.create"},
	{"invoice.approve", "invoice.read"},
	{"invoice.approve", "invoice.read"},
	{"invoice.approve"},
	{"invoice.approve"},
}

func build(links int) (*vector, error) {
	issuer := newKey()
	holder := newKey()
	credential, err := issueCredential(issuer, holder)
	if err != nil {
		return nil, err
	}

	chain := credential
	signer := holder
	var agents []string
	for i := range links {
		agent := newKey()
		id := fmt.Sprintf("urn:eudi-test:agent:procurement-%d", i+1)
		agents = append(agents, id)
		purpose := disclosure("purpose", "Pay supplier invoices of Bolt Supplies B.V.")
		payload := map[string]any{
			"vct": "urn:eudi-test:business:agent-mandate:1",
			"iat": now - 100,
			"exp": now + 3600,
			"cnf": map[string]any{"jwk": publicJWK(agent)},
			"agent": map[string]any{
				"id":   id,
				"name": fmt.Sprintf("Procurement agent %d", i+1),
			},
			"mandate": map[string]any{
				"actions": linkActions[i],
				"limit":   map[string]any{"amount": "5000.00", "currency": "EUR"},
				"_sd":     []any{digest(purpose)},
			},
		}
		chain, err = delegate.Append(chain, delegate.KBSDJWT{
			Type: delegate.TypeKBSDJWTKB,
			// The second link binds with issuer_jwt_hash so both hash claims
			// appear in the vectors.
			IssuerJWTHash: i == 1,
			Payloads: []delegate.PayloadDisclosure{{
				Disclosure:  disclosure(payload),
				Disclosures: []string{purpose},
			}},
			Claims: map[string]any{
				"iat":   now - 50,
				"aud":   id,
				"nonce": fmt.Sprintf("link-%d-nonce", i+1),
			},
		}, signer)
		if err != nil {
			return nil, err
		}
		signer = agent
	}

	last := chain[lastSegmentStart(chain):]
	sdHash, err := sdjwt.SDHash(last, "sha-256")
	if err != nil {
		return nil, err
	}
	kb, err := sign(signer, map[string]any{"typ": "kb+jwt", "alg": "ES256"}, map[string]any{
		"iat":     now - 10,
		"aud":     audience,
		"nonce":   nonce,
		"sd_hash": sdHash,
	})
	if err != nil {
		return nil, err
	}
	chain += kb

	_, verifyErr := delegate.Verify(chain, &issuer.PublicKey, delegate.Options{
		Now:               time.Unix(now, 0),
		Audience:          audience,
		Nonce:             nonce,
		MaxAge:            5 * time.Minute,
		RequireKeyBinding: true,
	})
	valid := links <= delegate.MaxLinks
	if valid != (verifyErr == nil) {
		return nil, fmt.Errorf("expected valid=%t, the Go verifier says %v", valid, verifyErr)
	}
	return &vector{
		Description: fmt.Sprintf("dSD-JWT+KB with %d KB-SD-JWTs", links),
		IssuerJWK:   publicJWK(issuer),
		Audience:    audience,
		Nonce:       nonce,
		Now:         now,
		Valid:       valid,
		Principal:   "DEACME.HRB4711",
		Agents:      agents,
		Actions:     linkActions[links-1],
		Chain:       chain,
	}, nil
}

func issueCredential(issuer, holder *ecdsa.PrivateKey) (string, error) {
	name := disclosure("legal_name", "Acme Logistics GmbH")
	euid := disclosure("euid_reference", "DEACME.HRB4711")
	jwt, err := sign(issuer, map[string]any{"typ": "dc+sd-jwt", "alg": "ES256"}, map[string]any{
		"iss":     issuerURL,
		"vct":     "urn:eudi-test:business:poa:1",
		"iat":     now - 3600,
		"exp":     now + 86400,
		"cnf":     map[string]any{"jwk": publicJWK(holder)},
		"_sd_alg": "sha-256",
		"_sd":     []any{digest(name), digest(euid)},
	})
	if err != nil {
		return "", err
	}
	return jwt + "~" + name + "~" + euid + "~", nil
}

// lastSegmentStart finds the final KB-SD-JWT of a dSD-JWT. Each segment ends
// with a tilde, and an empty component separates two segments.
func lastSegmentStart(chain string) int {
	for i := len(chain) - 2; i > 0; i-- {
		if chain[i] == '~' && chain[i-1] == '~' {
			return i + 1
		}
	}
	return 0
}

func newKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func publicJWK(key *ecdsa.PrivateKey) map[string]any {
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	// Uncompressed point: 0x04 || X || Y.
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64(encoded[1:33]),
		"y":   b64(encoded[33:]),
	}
}

func disclosure(parts ...any) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}
	encoded, err := json.Marshal(append([]any{b64(salt)}, parts...))
	if err != nil {
		log.Fatal(err)
	}
	return b64(encoded)
}

func digest(disclosure string) string {
	sum := sha256.Sum256([]byte(disclosure))
	return b64(sum[:])
}

// sign builds an ES256 JWS. RFC 7518 §3.4 encodes the signature as R || S.
func sign(key *ecdsa.PrivateKey, header, payload map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + b64(signature), nil
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
