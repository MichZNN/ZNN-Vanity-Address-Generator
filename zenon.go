package main

// Zenon key derivation, implemented with the Go standard library only.
// It mirrors go-zenon's wallet package (wallet/keystore.go, wallet/derivation.go,
// common/types/address.go) and is checked against its test vectors in zenon_test.go.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	_ "embed"
	"encoding/binary"
	"fmt"
	"strings"
)

//go:embed english.txt
var englishList string

var wordlist = strings.Fields(englishList)

const (
	firstHardened = uint32(0x80000000)
	purpose       = 44
	coinType      = 73404 // Zenon, path m/44'/73404'/<index>'
	userAddrByte  = 0x00
	addrCoreSize  = 19
)

func init() {
	if len(wordlist) != 2048 {
		panic(fmt.Sprintf("bip39 wordlist has %d words, want 2048", len(wordlist)))
	}
}

// entropyToMnemonic implements BIP39 for the English wordlist.
func entropyToMnemonic(entropy []byte) (string, error) {
	n := len(entropy)
	if n < 16 || n > 32 || n%4 != 0 {
		return "", fmt.Errorf("invalid entropy length %d", n)
	}
	sum := sha256.Sum256(entropy)
	csBits := n * 8 / 32
	words := (n*8 + csBits) / 11

	// Bit reader over entropy || checksum.
	data := append(append([]byte{}, entropy...), sum[0])
	if csBits > 8 {
		data = append(data, sum[1])
	}
	bit := func(i int) int { return int(data[i/8]>>(7-uint(i%8))) & 1 }

	out := make([]string, words)
	for w := 0; w < words; w++ {
		idx := 0
		for b := 0; b < 11; b++ {
			idx = idx<<1 | bit(w*11+b)
		}
		out[w] = wordlist[idx]
	}
	return strings.Join(out, " "), nil
}

// mnemonicToSeed implements the BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds).
// English words are plain ASCII, so NFKD normalisation is a no-op.
func mnemonicToSeed(mnemonic, passphrase string) []byte {
	seed, err := pbkdf2.Key(sha512.New, mnemonic, []byte("mnemonic"+passphrase), 2048, 64)
	if err != nil {
		panic(err)
	}
	return seed
}

// slip10 node for ed25519 (hardened derivation only).
type node struct{ key, chain []byte }

func masterNode(seed []byte) node {
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	s := h.Sum(nil)
	return node{s[:32], s[32:]}
}

func (n node) child(i uint32) node {
	var data [37]byte
	copy(data[1:33], n.key)
	binary.BigEndian.PutUint32(data[33:], i)
	h := hmac.New(sha512.New, n.chain)
	h.Write(data[:])
	s := h.Sum(nil)
	return node{s[:32], s[32:]}
}

// accountNode returns the node for m/44'/73404'; deriving index i from it
// gives m/44'/73404'/i' without repeating the first two steps.
func accountNode(seed []byte) node {
	return masterNode(seed).child(purpose + firstHardened).child(coinType + firstHardened)
}

// addressAt returns the Zenon address for m/44'/73404'/index'.
func (n node) addressAt(index uint32) string {
	leaf := n.child(index + firstHardened)
	pub := ed25519.NewKeyFromSeed(leaf.key).Public().(ed25519.PublicKey)
	return pubKeyToAddress(pub)
}

func deriveAddress(seed []byte, index uint32) string {
	return accountNode(seed).addressAt(index)
}

// pubKeyToAddress: 0x00 || sha3-256(pubkey)[:19], bech32 with hrp "z".
func pubKeyToAddress(pub []byte) string {
	h := sha3.Sum256(pub)
	raw := make([]byte, 0, 1+addrCoreSize)
	raw = append(raw, userAddrByte)
	raw = append(raw, h[:addrCoreSize]...)
	return bech32Encode("z", convertBits8to5(raw))
}

// --- bech32 (BIP173) ---

var bech32Gen = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= bech32Gen[i]
			}
		}
	}
	return chk
}

func bech32Encode(hrp string, data []byte) string {
	exp := make([]byte, 0, len(hrp)*2+1+len(data)+6)
	for i := 0; i < len(hrp); i++ {
		exp = append(exp, hrp[i]>>5)
	}
	exp = append(exp, 0)
	for i := 0; i < len(hrp); i++ {
		exp = append(exp, hrp[i]&31)
	}
	exp = append(exp, data...)
	exp = append(exp, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(exp) ^ 1

	var sb strings.Builder
	sb.Grow(len(hrp) + 1 + len(data) + 6)
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, d := range data {
		sb.WriteByte(bech32Charset[d])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(bech32Charset[(mod>>uint(5*(5-i)))&31])
	}
	return sb.String()
}

func convertBits8to5(in []byte) []byte {
	out := make([]byte, 0, (len(in)*8+4)/5)
	acc, bits := uint32(0), uint(0)
	for _, b := range in {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, byte(acc>>bits)&31)
		}
	}
	if bits > 0 {
		out = append(out, byte(acc<<(5-bits))&31)
	}
	return out
}
