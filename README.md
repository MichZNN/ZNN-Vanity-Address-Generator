# ZNN Vanity Address Generator

Fast, multi-core vanity address generator for the [Zenon Network](https://zenon.network).
Find a `z1q…` address with your own prefix and/or suffix, together with its
24-word mnemonic, ready to import into Syrius.

- **Pure Go, zero dependencies** – only the Go standard library.
- **Same derivation as go-zenon / Syrius** – BIP39 (24 words) → SLIP-0010 ed25519 on
  `m/44'/73404'/<index>'`. Verified at build time against the BIP39 and SLIP-0010
  test vectors and against go-zenon's own address fixtures.
- **Uses every core**, roughly 100× faster than the Dart-based generators.
- **Never loses a match** – results are appended and flushed to disk immediately.
- **Mnemonics stay out of the logs** – they are only written to the results file (mode `0600`).
- **Runs offline** – the container needs no network at all.

## Quick start (Docker)

```bash
git clone https://github.com/MichZNN/ZNN-Vanity-Address-Generator.git
cd ZNN-Vanity-Address-Generator
docker build -t znn-vanity .
mkdir -p results

# address ending in "aeth"
docker run --rm -it -v "$PWD/results":/data znn-vanity -s aeth
```

The match is in `results/results.txt`.

### Long search in the background

Runs detached, survives reboots and Docker updates, and keeps appending every match:

```bash
docker run -d --name vanity-aether --restart unless-stopped --network none \
  -v "$PWD/results":/data znn-vanity -s aether -n 0 -o aether.txt

docker logs -f vanity-aether     # progress (Ctrl+C only stops watching)
cat results/aether.txt           # matches
docker rm -f vanity-aether       # stop and remove
```

Because the file is opened in append mode, a restart never overwrites earlier matches.
And since every attempt is independent random luck, a restart doesn't cost you "progress" either.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `-s` | | suffix (end of the address) |
| `-p` | | prefix after `z1q` (a full `z1q…` is also accepted) |
| `-t` | all cores | worker threads |
| `-a` | `1` | addresses checked per mnemonic (index `0…a-1`); `1` = only the first address |
| `-n` | `1` | stop after this many matches; `0` = run forever |
| `-o` | `results.txt` | output file (appended, never overwritten) |
| `-i` | `30s` | progress report interval |

## Which characters can I use?

Zenon addresses are bech32: `qpzry9x8gf2tvdw0s3jn54khce6mua7l`.
The characters **`1`, `b`, `i`, `o`** never occur. Input is lowercased automatically.

Every user address starts with `z1q` followed by **`q`, `p`, `z` or `r`**, so a
prefix must start with one of those (`-p zen` → `z1qzen…`, but `-p ae` is impossible).

## How long will it take?

Each extra character makes the search 32× harder. On average:

| Pattern length | Attempts | ~1,000/s | ~10,000/s |
|---|---|---|---|
| 4 | 1 M | 17 min | 2 min |
| 5 | 34 M | 9 h | 1 h |
| 6 | 1.1 G | 12 days | 1.2 days |
| 7 | 34 G | 1 year | 40 days |

The progress line shows your real speed and the average time per match. It is luck,
not a countdown: a match can come much sooner or later than the average.

`-a` above 1 is faster (extra indexes of the same mnemonic are cheap), but the match
may be at e.g. index 37, so you'd have to add addresses in Syrius until it appears.

## After you find a match

1. Import the mnemonic in Syrius and check that the address matches.
2. Store the mnemonic safely (offline).
3. Delete the results file: `rm results/*.txt`.

Run this on your own machine, preferably offline – not on a VPS or shared server.

## Build without Docker

Requires Go 1.24+.

```bash
go test ./...
go build -o znn-vanity .
./znn-vanity -s aeth
```

## License

MIT. The BIP39 English wordlist comes from [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).
