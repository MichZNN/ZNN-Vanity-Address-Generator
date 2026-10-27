package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// BIP39 vectors from trezor/python-mnemonic (passphrase "TREZOR").
func TestBIP39Vectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/bip39_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct{ Entropy, Mnemonic, Seed string }
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vs {
		ent, _ := hex.DecodeString(v.Entropy)
		m, err := entropyToMnemonic(ent)
		if err != nil {
			t.Fatal(err)
		}
		if m != v.Mnemonic {
			t.Errorf("mnemonic for %s:\n got  %s\n want %s", v.Entropy, m, v.Mnemonic)
		}
		if s := hex.EncodeToString(mnemonicToSeed(m, "TREZOR")); s != v.Seed {
			t.Errorf("seed for %q:\n got  %s\n want %s", m, s, v.Seed)
		}
	}
}

// From go-zenon common/types/address_test.go (TestPubKeyToAddress).
func TestPubKeyToAddress(t *testing.T) {
	pub := []byte{233, 58, 2, 195, 155, 8, 2, 46, 13, 5, 226, 101, 53, 104, 117, 74, 104, 122, 37, 184, 121, 65, 147, 88, 241, 163, 160, 40, 41, 165, 29, 62}
	if got := pubKeyToAddress(pub); got != "z1qry3r6n4adzwlyqrm6e2s8hz4kff9uzmkqjnqy" {
		t.Errorf("got %s", got)
	}
	if got := pubKeyToAddress(pub[1:]); got != "z1qpg720fhchs4rud5v6zk4w6ch35yjvmyr7hee8" {
		t.Errorf("one byte less: got %s", got)
	}
}

// SLIP-0010 ed25519 test vector 1 (chain m/0'/1'/2'/2'/1000000000').
func TestSLIP10Ed25519(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	n := masterNode(seed)
	if hex.EncodeToString(n.key) != "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7" {
		t.Fatalf("master key %x", n.key)
	}
	for _, i := range []uint32{0, 1, 2, 2, 1000000000} {
		n = n.child(i + firstHardened)
	}
	if hex.EncodeToString(n.key) != "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793" {
		t.Errorf("leaf key %x", n.key)
	}
}

// Keys from go-zenon chain/genesis/mock/embedded_genesis.go, derived with
// wallet.DeriveWithIndex. Their addresses appear in go-zenon's test fixtures.
func TestGoZenonMockAccounts(t *testing.T) {
	cases := []struct {
		seed  string
		index uint32
		addr  string
	}{
		{"01234567890123456789012345678901", 1, "z1qqq43dyrswfehx9w9td43exflqzcxrt7g6alah"}, // Pillar1
		{"01234567890123456789012345678902", 1, "z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz"}, // User1
	}
	for _, c := range cases {
		seed, _ := hex.DecodeString(c.seed)
		if got := deriveAddress(seed, c.index); got != c.addr {
			t.Errorf("seed %s index %d: got %s want %s", c.seed, c.index, got, c.addr)
		}
	}
}

func TestMnemonicShape(t *testing.T) {
	m, err := entropyToMnemonic(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(m)); n != 24 {
		t.Fatalf("got %d words", n)
	}
	a := deriveAddress(mnemonicToSeed(m, ""), 0)
	if len(a) != 40 || !strings.HasPrefix(a, "z1q") || !strings.ContainsRune("qpzr", rune(a[3])) {
		t.Errorf("odd address %s", a)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []struct{ p, s string }{
		{"", ""},      // nothing to search
		{"", "lib"},   // contains i and b
		{"", "1337"},  // contains 1
		{"ae", ""},    // char after z1q must be q/p/z/r
		{"z1qae", ""}, // same, full form
	}
	for _, b := range bad {
		if _, err := buildConfig(b.p, b.s, 1, 1, 1, "x", 1); err == nil {
			t.Errorf("expected error for -p %q -s %q", b.p, b.s)
		}
	}
	c, err := buildConfig("zen", "lyn", 1, 1, 1, "x", 1)
	if err != nil || c.prefix != "z1qzen" || c.suffix != "lyn" {
		t.Fatalf("got %+v, %v", c, err)
	}
	if c.attempts != 4*32*32*32*32*32 {
		t.Errorf("attempts %v", c.attempts)
	}
}
