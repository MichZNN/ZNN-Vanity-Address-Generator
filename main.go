// znn-vanity: fast, multi-core vanity address generator for Zenon Network (ZNN).
//
// Key derivation follows go-zenon's wallet package exactly (see zenon.go):
// BIP39 24-word mnemonic -> seed -> SLIP-0010 ed25519 on m/44'/73404'/<index>'.
// Every mnemonic it finds can be imported directly into Syrius.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	// Every user address starts with "z1q" followed by one of q/p/z/r
	// (the address type byte 0x00 fixes those bits).
	addrStart  = "z1q"
	secondChar = "qpzr"
	addrLen    = 40
)

var version = "dev"

type config struct {
	prefix   string // full prefix including "z1q", or ""
	suffix   string
	threads  int
	perMnem  int
	maxFound int
	output   string
	interval time.Duration
	attempts float64 // expected attempts per hit
}

func main() {
	var (
		prefix   = flag.String("p", "", "prefix after \"z1q\" (first char must be q, p, z or r); a full \"z1q...\" is accepted too")
		suffix   = flag.String("s", "", "suffix (end of the address)")
		threads  = flag.Int("t", runtime.NumCPU(), "number of worker threads")
		perMnem  = flag.Int("a", 1, "addresses checked per mnemonic (index 0..a-1); 1 = only the first address")
		maxFound = flag.Int("n", 1, "stop after this many matches; 0 = run forever")
		output   = flag.String("o", "results.txt", "output file (matches are appended, never overwritten)")
		interval = flag.Duration("i", 30*time.Second, "progress report interval")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("znn-vanity", version)
		return
	}

	cfg, err := buildConfig(*prefix, *suffix, *threads, *perMnem, *maxFound, *output, *interval)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `znn-vanity %s - Zenon vanity address generator

Usage: znn-vanity [-p prefix] [-s suffix] [options]

Examples:
  znn-vanity -s aeth              address ending in "aeth"
  znn-vanity -p zen -s lyn        address like z1qzen...lyn
  znn-vanity -s aether -n 0       keep searching, append every match

Valid characters: %s  (no 1, b, i, o)

Options:
`, version, bech32Charset)
	flag.PrintDefaults()
}

func buildConfig(prefix, suffix string, threads, perMnem, maxFound int, output string, interval time.Duration) (*config, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	suffix = strings.ToLower(strings.TrimSpace(suffix))

	if prefix == "" && suffix == "" {
		return nil, fmt.Errorf("give a prefix (-p) and/or suffix (-s); see -h")
	}

	// Normalise prefix to the full "z1q..." form.
	if prefix != "" {
		if !strings.HasPrefix(prefix, addrStart) {
			prefix = addrStart + prefix
		}
		if err := checkChars(prefix[2:], "prefix"); err != nil {
			return nil, err
		}
		if len(prefix) > len(addrStart) && !strings.ContainsRune(secondChar, rune(prefix[3])) {
			return nil, fmt.Errorf("prefix %q is impossible: the character after \"z1q\" is always q, p, z or r", prefix)
		}
	}
	if err := checkChars(suffix, "suffix"); err != nil {
		return nil, err
	}
	if len(prefix)+len(suffix) > addrLen {
		return nil, fmt.Errorf("prefix + suffix longer than an address (%d chars)", addrLen)
	}
	if threads < 1 || perMnem < 1 || maxFound < 0 {
		return nil, fmt.Errorf("-t and -a must be >= 1, -n must be >= 0")
	}

	return &config{
		prefix:   prefix,
		suffix:   suffix,
		threads:  threads,
		perMnem:  perMnem,
		maxFound: maxFound,
		output:   output,
		interval: interval,
		attempts: expectedAttempts(prefix, suffix),
	}, nil
}

func checkChars(s, what string) error {
	for _, c := range s {
		if !strings.ContainsRune(bech32Charset, c) {
			return fmt.Errorf("%s contains %q, which never appears in a Zenon address (valid: %s)", what, c, bech32Charset)
		}
	}
	return nil
}

// expectedAttempts is the average number of addresses to check per match.
func expectedAttempts(prefix, suffix string) float64 {
	n := math.Pow(32, float64(len(suffix)))
	if p := len(prefix) - len(addrStart); p > 0 {
		n *= 4 * math.Pow(32, float64(p-1))
	}
	return n
}

type match struct {
	address  string
	index    int
	mnemonic string
}

func run(cfg *config) error {
	// Open the output file up front so a bad path fails immediately.
	f, err := os.OpenFile(cfg.output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("cannot open output file: %w", err)
	}
	defer f.Close()

	target := "?"
	switch {
	case cfg.prefix != "" && cfg.suffix != "":
		target = cfg.prefix + "..." + cfg.suffix
	case cfg.prefix != "":
		target = cfg.prefix + "..."
	default:
		target = "z1q..." + cfg.suffix
	}
	limit := "unlimited"
	if cfg.maxFound > 0 {
		limit = fmt.Sprint(cfg.maxFound)
	}
	fmt.Printf("znn-vanity %s\n", version)
	fmt.Printf("target: %s | threads: %d | addresses/mnemonic: %d | matches wanted: %s\n", target, cfg.threads, cfg.perMnem, limit)
	fmt.Printf("expected addresses per match: %s | output: %s (append)\n", human(cfg.attempts), cfg.output)

	var (
		checked atomic.Uint64
		found   atomic.Int64
		stop    = make(chan struct{})
		once    sync.Once
		matches = make(chan match, 16)
		wg      sync.WaitGroup
	)
	halt := func() { once.Do(func() { close(stop) }) }

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	for w := 0; w < cfg.threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(cfg, &checked, matches, stop)
		}()
	}
	go func() { wg.Wait(); close(matches) }()

	start := time.Now()
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	var exitErr error

	for {
		select {
		case m, ok := <-matches:
			if !ok {
				report(start, checked.Load(), found.Load(), cfg)
				return exitErr
			}
			if cfg.maxFound > 0 && found.Load() >= int64(cfg.maxFound) {
				continue // a worker raced past the limit; ignore extras
			}
			if err := save(f, m); err != nil {
				exitErr = fmt.Errorf("writing match: %w", err)
				halt()
				continue
			}
			n := found.Add(1)
			// The mnemonic is only written to the file, never to the log.
			fmt.Printf("MATCH #%d: %s (index %d) -> saved to %s\n", n, m.address, m.index, cfg.output)
			if cfg.maxFound > 0 && n >= int64(cfg.maxFound) {
				halt()
			}
		case <-ticker.C:
			report(start, checked.Load(), found.Load(), cfg)
		case <-sigs:
			fmt.Println("stopping...")
			halt()
		}
	}
}

func worker(cfg *config, checked *atomic.Uint64, out chan<- match, stop <-chan struct{}) {
	entropy := make([]byte, 32) // 256 bits -> 24 words, like Syrius
	for {
		select {
		case <-stop:
			return
		default:
		}
		if _, err := rand.Read(entropy); err != nil {
			panic(err)
		}
		mnemonic, err := entropyToMnemonic(entropy)
		if err != nil {
			panic(err)
		}
		acct := accountNode(mnemonicToSeed(mnemonic, ""))
		for i := 0; i < cfg.perMnem; i++ {
			addr := acct.addressAt(uint32(i))
			if strings.HasPrefix(addr, cfg.prefix) && strings.HasSuffix(addr, cfg.suffix) {
				select {
				case out <- match{address: addr, index: i, mnemonic: mnemonic}:
				case <-stop:
					return
				}
			}
		}
		checked.Add(uint64(cfg.perMnem))
	}
}

func save(f *os.File, m match) error {
	entry := fmt.Sprintf("%s\naddress:  %s\nindex:    %d\nmnemonic: %s\n\n",
		time.Now().Format(time.RFC3339), m.address, m.index, m.mnemonic)
	if _, err := f.WriteString(entry); err != nil {
		return err
	}
	return f.Sync()
}

func report(start time.Time, checked uint64, found int64, cfg *config) {
	el := time.Since(start)
	rate := float64(checked) / el.Seconds()
	eta := "?"
	if rate > 0 {
		eta = dur(time.Duration(cfg.attempts / rate * float64(time.Second)))
	}
	fmt.Printf("[%s] checked %s | %s/s | found %d | avg time per match ~%s\n",
		dur(el.Truncate(time.Second)), human(float64(checked)), human(rate), found, eta)
}

func human(v float64) string {
	switch {
	case v >= 1e12:
		return fmt.Sprintf("%.2fT", v/1e12)
	case v >= 1e9:
		return fmt.Sprintf("%.2fG", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}

func dur(d time.Duration) string {
	if d > 1e6*time.Hour {
		return "forever"
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	switch {
	case days > 365:
		return fmt.Sprintf("%.1f years", float64(days)/365)
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
