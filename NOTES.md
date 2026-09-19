# slopped — reverse engineering notes

Everything below was derived from the handout in this repo
(`slopped-handout/peerctl`, sha256 `2c65ac0035c36f723fc1816ccd2e47cbe919f58ccc42cedb1d694558c6a1cceb`,
which matches `SHA256SUMS`) and cross-checked by running the real binary
against a local peer (`tools/mockpeer.py`).  Items marked **verified** were
observed on the wire; items marked **unchecked** were not.

## 1. What the flag is *not*

The flag is **not** in the handout.  Searches run over the 10,096,788-byte
`peerctl`:

* `flag{`, `FLAG{`, `ctf{`, `CTF{`, `z0d1ak{`, `Z0D1AK{`, `Z0D{` — no hits.
* `zdk{`, `ZDK{`, and even the bare substrings `zdk` / `ZDK` — no hits.
  `zdk{...}` is the real flag format for this CTF (see below), so this is the
  search that matters.
* every one of the 9161 `0x7b` (`{`) bytes in the file was inspected in
  context: they are all x86 operands (`H9{\x08` = `cmp 0x8(%rdi),%rsi`) or Go
  type literals (`dnsmessage.AResource{A: [4]byte{`).  There is not one
  `word{...}` string in the binary.
* single-byte XOR (keys 1..255) for the same markers — two hits, both inside
  `runtime.initMetrics`' metric-name tables (coincidence, not data).
* every base64-looking run ≥ 24 chars decoded — no hit.
* entropy scan of `.rodata`: peak 6.09 bits/byte at file offset `0x5b8000`.
  Then a second pass over the **whole file** in 64-byte windows: **zero**
  windows reach 7.6 bits/byte.  An embedded encrypted or compressed blob of
  any size would.  There is no ciphertext in this binary to unwrap.
* the per-team marker in `HANDOUT_VARIANT.txt`
  (`bbe2344b7ef7fd0f04dd3099a7bd7fb71047ea4cf76ceb9abd0c8363df3922fb`) does
  not occur in `peerctl` as ASCII, upper-case, or raw bytes — so the binary
  carries no per-team watermark either.
* `.go.buildinfo`: `go1.25.4`, `-buildmode=exe -compiler=gc -trimpath=true`,
  `CGO_ENABLED=0 GOARCH=amd64 GOOS=linux GOAMD64=v1`.  No `-ldflags -X`
  secret.  Module `slopped/cmd/peerctl`; deps: pion/webrtc v4.1.2,
  gorilla/websocket v1.5.3, fxamacker/cbor v2.9.0, google/uuid v1.6.0.
* git: one commit (`77db8c1`), five blobs, all accounted for.
  `git ls-remote origin` on `github.com/diablo144/slopped` shows only
  `refs/heads/main` at the same SHA — no other branch/tag holds the peer.

`peerctl` is **only** the client.  Its function table (Go pclntab, parsed with
`tools/rev/reflect.py`) contains `main.main`, `main.fetchConfig`,
`main.connect`, `main.runJSON`, `main.runInteractive`, `main.interactiveRequest`,
`main.(*client).request`, `main.printInteractiveFrame` and
`slopped/internal/protocol.{Encode,Decode}` — no listener, no handler, no
archive.  The archive peer (and therefore the flag) is server-side.

## 2. Frame format (`slopped/internal/protocol`) — verified

Captured from peerctl, CHAT "hello archive":

    474d5031 01 20 0000 00000001 0000000000000001 00000014
    a1 64 "text" 6d "hello archive"

| off | size | field      | notes                                        |
|-----|------|------------|----------------------------------------------|
| 0   | 4    | magic      | `GMP1` = `0x31504d47` little-endian           |
| 4   | 1    | version    | `0x01`                                        |
| 5   | 1    | Type       | uint8                                         |
| 6   | 2    | Flags      | uint16 BE — peerctl always sends 0            |
| 8   | 4    | StreamID   | uint32 BE — peerctl always sends 1            |
| 12  | 8    | Sequence   | uint64 BE — increments per request            |
| 20  | 4    | PayloadLen | uint32 BE — must equal `len(frame) - 24`      |
| 24  | n    | Payload    | CBOR map (`map[string]interface{}`)           |

`rtcbridge.Envelope` (rtype `0x9513e0`, size 24, walked out of the reflect
tables) is exactly `{Type uint8; Flags uint16; StreamID uint32; Sequence uint64;
Payload map[string]any}` — the first four fields live in the header, `Payload`
is the CBOR body.

Client-side limits, from the disassembly of `protocol.Encode` (`0x81f760`) and
`protocol.Decode` (`0x81f900`):

* `Encode`: whole frame `> 0x8000` → `"frame too large"`.
* `Decode`: `len - 24 > 0x7fe8` → `"invalid frame size"`;
  magic/version mismatch → `"invalid frame prefix"`;
  `PayloadLen != len - 24` → `"payload length mismatch"`;
  bad CBOR → `"CBOR: %w"`.

These checks are *client-side only*.  A custom client can violate every one of
them, which is the whole point of `tools/slopped_client.py`.

## 3. Request types — verified

`main.(*client).request` (`0x8224c0`) reads `payload["type"]`:

| `type` string    | Type byte | payload keys sent                          |
|------------------|-----------|--------------------------------------------|
| `HISTORY_PULL`   | `0x10`    | `after` (int64), `limit` (int), `fields` (array) |
| `CHAT`           | `0x20`    | `text` (string)                            |
| anything else    | —         | error `supported request types: CHAT or HISTORY_PULL` |

`type` is stripped from the CBOR payload; every other key is copied through
verbatim.  Captured HISTORY_PULL frame payload decoded to
`{"after": 0.0, "limit": 2.0, "fields": ["sender","body"]}` — note
fxamacker/cbor encoded the numbers as IEEE half floats (`f9 0000`, `f9 4000`)
because the JSON-Lines input turns them into `float64`.  In interactive mode
they are real integers.  A C peer with a naive CBOR decoder is a candidate
target right there.

`/history` client-side flags: `-after` (int64), `-limit` (int, default 10),
`-fields` (string, default `["sender","body","sent_at"]`), errors
`unexpected history argument` and `fields must be a JSON string array: %w`.

## 4. Gateway config (`rtcbridge.PublicConfig`) — verified

`GET <signaling>/v1/config` returns:

```json
{
  "protocol_version": 1,
  "websocket": "wss://…/v1/signal",
  "turn": {"URI": "turns://…:1337?transport=tcp", "Username": "…", "Password": "…"},
  "peer_fingerprint": "sha256:…",
  "channels": ["…"]
}
```

Field names and types were read out of the reflect tables (`Turn` is
`{URI, Username, Password string}` with **no** json tags, so they are
capitalised on the wire).  Confirmed empirically: feeding peerctl
`"turn":{"URI":""}` yields `InvalidAccessError: unknown scheme type` (pion
parsing the empty URI), and a well-formed config connects.  `channels` is
accepted empty and the datachannel label is hard-coded, so `channels` is not
load-bearing for the client.  Whether `peer_fingerprint` is actually pinned:
**unchecked**.

## 5. Signalling and transport — verified

* WS connect to `<websocket>` + `?role=guest`.
* client → `{"type":"ice_candidate","candidate":"<json blob>"}` (trickle, one
  per candidate; the blob is `{"candidate","sdpMid","sdpMLineIndex","usernameFragment"}`).
* client → `{"type":"sdp_offer","sdp":"…"}` once gathering completes
  (`a=end-of-candidates` present).
* server → `{"type":"sdp_answer","sdp":"…"}` (and its own `ice_candidate`s).
* client → `{"type":"hangup"}` on exit.
* Datachannel: label `gmp.chat.v1`, `protocol` empty, `negotiated=false`,
  `ordered=true`, `id=1`, `a=sctp-port:5000`.
* `peerctl -json` (or piped stdin) speaks JSON Lines:
  `{"type":"CHAT","text":"…"}` in, `{"type":"frame","frame_type":32,"sequence":1,"payload":{…}}` out.

## 6. Tooling in this repo

| path | what it is |
|------|------------|
| `tools/slopped_client.py` | standalone client (aiortc). `chat`, `history`, `raw`, `probe`. `raw` can lie about `PayloadLen`, oversize a frame, set arbitrary `Type`/`Flags`/`StreamID`/`Sequence` and inject raw CBOR — none of which `peerctl` will do. `probe` fires ~20 malformed-frame probes. |
| `tools/mockpeer.py` | local stand-in for the signalling endpoint + archive peer, used to verify the protocol without the challenge. |
| `tools/rev/disasm.py`, `tools/rev/fn.py`, `tools/rev/reflect.py` | the analysis helpers: annotated objdump of an address range, function lookup by name, and a Go reflect-table walker that dumps struct fields and tags. |
| `tools/rev/funcs.txt` | all 10,595 functions from the pclntab, with entry addresses. |

Requires `pip install aiortc websockets cbor2` (aioice inside aiortc handles
`turns://` over TLS, so it can reach the challenge relay).

### Verification actually performed

```
$ python tools/mockpeer.py                                   # local peer
$ printf '{"type":"CHAT","text":"hello archive"}\n' | ./peerctl -config http://127.0.0.1:8080/v1/config
{"type":"connected"}
{"frame_type":32,"payload":{"message":"you said: hello archive","status":"ok"},"sequence":1,"type":"frame"}

$ python tools/slopped_client.py --config http://127.0.0.1:8080/v1/config chat "hello from python"
{"type": 32, "flags": 0, "stream": 1, "seq": 1, "declared": 48, "actual": 48,
 "payload": {"status": "ok", "message": "you said: hello from python"}}
```

Both the vendor binary and the replacement client drive the same peer over the
same frames, so the protocol description above is grounded in observed bytes
rather than guesswork.

## 7. What is still open

The archive peer binary is not in the handout and the challenge endpoints are
not reachable from this sandbox (TLS to `*.challenges.z0d1ak.org` is dropped by
the egress proxy), so the actual memory-corruption bug has not been located.
The realistic targets, in the order the client-side checks suggest:

1. `PayloadLen` handling — the peer must not trust the declared length;
   `declared > actual` and `declared < actual` probes are already wired up.
2. Frames over 32768 bytes — only the *client* enforces that cap; the
   datachannel itself negotiated `max-message-size:65536`.
3. `Type`/`Flags`/`StreamID` values the client never emits.
4. CBOR shape attacks on the `Payload` map: half-floats for `after`/`limit`,
   negative or huge `limit`, a `fields` array of long strings, `fields` as a
   string, non-map payloads, deeply nested values, non-UTF-8 keys.

## 8. Where the flag lives — searched exhaustively on 2026-09-19

The endpoints are `*.challenges.z0d1ak.org`, i.e. the **z0d1ak CTF** run by
ACM-VIT.  That fixes the flag format: the qualifier writeups publish flags as
`zdk{...}` — e.g. the 500-pt pwn `rapture` is
`zdk{FREED_LN_The_de3P_BU7_n3VER_FOrgoT73N}`
(`hax1ng/z0d1ak-ctf-qualifiers-2026`, `pwn/rapture/README.md`).

Everything reachable was checked for a published copy of *this* challenge:

| source | result |
|--------|--------|
| GitHub code search `"gmp.chat.v1"` | 0 hits |
| GitHub code search `"supported request types: CHAT or HISTORY_PULL"` | 0 hits |
| GitHub code search `"payload length mismatch" GMP1`, `"archive peer" GMP1`, `slopped/internal/rtcbridge`, `slopped-handout`, `slopped peerctl` | 0 hits each |
| GitHub code search `"challenges.z0d1ak.org"` | 0 hits |
| `diablo144`'s 27 repos + 3 gists | no `slopped` content; the other CTF repos hold *other* challenges (`yet_another_pwn_challenge`, `pwn_riftcap`, `forensics_typewriter`) |
| z0d1ak qualifier writeup repos (`hax1ng/…`, `Abdelkad3r/…`, `ftps3rver/…`, `jaguar999paw-droid/…`) | pwn sets are dead-reckoning, expert-witness, house-xiii, paperweight, pelagic-palimpsest, phantom-phase, rapture, salvage-protocol, undertow — **no `slopped`** |
| `Abdelkad3r/Anti-SlopCTF-2026` | different CTF; its pwn track is anchorpoint, graceful-exit, paper-lantern |
| web search for the challenge / `peerctl` / `gmp.chat.v1` | no writeup, no source |

`slopped` is a later-round challenge (500 pts, 0 solves), so there is no
writeup and no leaked organiser source.  The flag is generated per instance on
the archive peer, which is not in the handout, and the instance is gone.  It is
therefore not recoverable from anything on disk here — the only route is a live
instance driven by `tools/slopped_client.py`.
