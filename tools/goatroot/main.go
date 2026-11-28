// Command goatroot issues and checks goatnet root documents and creates the
// Ed25519 keys that sign them and that sign network maps.
//
//	goatroot keygen -out key.pem               new PKCS#8 PEM key (mode 0600); prints its document key entry
//	goatroot pubkey -key key.pem               prints the document key entry of a key
//	goatroot sign -doc doc.json -key k.pem -out signed.json [-key k2.pem ...]
//	goatroot verify -held held.json [-candidate next.json]
//	goatroot revoke -key signer.pem -goatnet ID -peer WGKEY -list revocations.json [-reason text]
//
// revoke signs a revocation with a map signer's key and appends it to the
// list management serves (GoatMapSigning.RevocationsFile). A revoked key stays
// revoked for good; a device comes back with a new key and a new enrollment.
//
// A first document must be signed by one of its own root keys; each later
// version by a root key the version before it lists.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/netbirdio/netbird/shared/management/goatrevoke"
	"github.com/netbirdio/netbird/shared/management/goatroot"
)

type keyFiles []string

func (k *keyFiles) String() string     { return strings.Join(*k, ",") }
func (k *keyFiles) Set(v string) error { *k = append(*k, v); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "goatroot:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: goatroot keygen|pubkey|sign|verify [flags]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "keygen":
		path := fs.String("out", "", "key file to create")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return keygen(*path, out)
	case "pubkey":
		path := fs.String("key", "", "key file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		k, err := readKey(*path)
		if err != nil {
			return err
		}
		return printKey(out, k.Public().(ed25519.PublicKey))
	case "sign":
		docPath := fs.String("doc", "", "document JSON")
		outPath := fs.String("out", "", "signed document to write")
		var keys keyFiles
		fs.Var(&keys, "key", "root key file (repeatable)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return sign(*docPath, keys, *outPath)
	case "verify":
		held := fs.String("held", "", "held signed document")
		candidate := fs.String("candidate", "", "signed document that should replace it")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return verify(*held, *candidate, out)
	case "revoke":
		keyPath := fs.String("key", "", "map signer key file")
		goatnet := fs.String("goatnet", "", "goatnet ID")
		peerKey := fs.String("peer", "", "WireGuard public key of the revoked peer")
		listPath := fs.String("list", "", "revocation list to append to (created when missing)")
		reason := fs.String("reason", "", "reason")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return revoke(*keyPath, *goatnet, *peerKey, *listPath, *reason, out)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func keygen(path string, out io.Writer) error {
	if path == "" {
		return errors.New("keygen needs -out")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return printKey(out, pub)
}

func printKey(out io.Writer, pub ed25519.PublicKey) error {
	b, err := json.MarshalIndent(goatroot.NewKey(pub), "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}

func readKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a PEM PRIVATE KEY", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return k, nil
}

func sign(docPath string, keyPaths []string, outPath string) error {
	if docPath == "" || outPath == "" || len(keyPaths) == 0 {
		return errors.New("sign needs -doc, -out and at least one -key")
	}
	b, err := os.ReadFile(docPath)
	if err != nil {
		return err
	}
	doc := &goatroot.Document{}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(doc); err != nil {
		return fmt.Errorf("parse %s: %w", docPath, err)
	}
	keys := make([]ed25519.PrivateKey, 0, len(keyPaths))
	for _, p := range keyPaths {
		k, err := readKey(p)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	signed, err := goatroot.Sign(doc, keys...)
	if err != nil {
		return err
	}
	return goatroot.Store(outPath, signed)
}

func verify(heldPath, candidatePath string, out io.Writer) error {
	if heldPath == "" {
		return errors.New("verify needs -held")
	}
	held, err := goatroot.Load(heldPath)
	if err != nil {
		return fmt.Errorf("held document: %w", err)
	}
	if candidatePath == "" {
		_, err := fmt.Fprintf(out, "ok: %s version %d, %d map signers, %d root keys\n", held.Doc().GoatnetID, held.Doc().Version, len(held.Doc().MapSigners), len(held.Doc().RootKeys))
		return err
	}
	b, err := os.ReadFile(candidatePath)
	if err != nil {
		return err
	}
	candidate, err := goatroot.Parse(b)
	if err != nil {
		return fmt.Errorf("candidate document: %w", err)
	}
	if err := goatroot.Successor(held, candidate); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "ok: version %d may replace version %d\n", candidate.Doc().Version, held.Doc().Version)
	return err
}

func revoke(keyPath, goatnet, peerKey, listPath, reason string, out io.Writer) error {
	if keyPath == "" || goatnet == "" || peerKey == "" || listPath == "" {
		return errors.New("revoke needs -key, -goatnet, -peer and -list")
	}
	k, err := readKey(keyPath)
	if err != nil {
		return err
	}
	signed, err := goatrevoke.Sign(&goatrevoke.Revocation{GoatnetID: goatnet, PeerKey: peerKey, IssuedAtUnixNano: time.Now().UnixNano(), Reason: reason}, k)
	if err != nil {
		return err
	}
	var list []json.RawMessage
	if b, err := os.ReadFile(listPath); err == nil {
		if err := json.Unmarshal(b, &list); err != nil {
			return fmt.Errorf("parse %s: %w", listPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := signed.Marshal()
	if err != nil {
		return err
	}
	list = append(list, b)
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := listPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, listPath); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "revocation %s of %s appended to %s (%d in the list)\n", signed.ID(), peerKey, listPath, len(list))
	return err
}
