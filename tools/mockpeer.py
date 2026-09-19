#!/usr/bin/env python3
"""Local stand-in for the slopped signalling endpoint + "archive peer".

This is a test harness, not part of the challenge.  It speaks the protocol that
was reverse engineered out of peerctl:

  * HTTP  GET  /v1/config            -> rtcbridge.PublicConfig JSON
  * WS    GET  <websocket>?role=guest
        client -> {"type":"ice_candidate","candidate":"<json blob>"}
        client -> {"type":"sdp_offer","sdp":"..."}
        server -> {"type":"sdp_answer","sdp":"..."}
  * WebRTC datachannel, framed messages ("GMP1" header + CBOR map payload)

Run with the venv python:  /tmp/.venv/bin/python tools/mockpeer.py
"""
import asyncio
import json
import os
import struct

import cbor2
from aiortc import (RTCConfiguration, RTCCertificate, RTCPeerConnection,
                    RTCSessionDescription)
from websockets.asyncio.server import serve

WS_PORT = 8090
HTTP_PORT = 8080
LOGFILE = "/tmp/mock/mockpeer.log"
TURN_URI = "turn:127.0.0.1:9?transport=udp"

_logfh = open(LOGFILE, "a", buffering=1)


def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    _logfh.write(s + "\n")


# --------------------------------------------------------------------------
# frame codec (mirrors slopped/internal/protocol Encode/Decode)
# --------------------------------------------------------------------------
MAGIC = b"GMP1"
VERSION = 1
HDR = 24
MAX_FRAME = 32768          # peerctl: whole frame must be <= 0x8000
MAX_PAYLOAD = 0x7FE8       # peerctl: len-24 must be <= 0x7fe8

TYPE_HISTORY = 0x10
TYPE_CHAT = 0x20


def encode_frame(ftype, flags, stream, seq, payload):
    body = cbor2.dumps(payload) if payload is not None else b""
    return (MAGIC + bytes([VERSION, ftype])
            + struct.pack(">H", flags) + struct.pack(">I", stream)
            + struct.pack(">Q", seq) + struct.pack(">I", len(body)) + body)


def decode_frame(buf):
    if len(buf) < HDR:
        raise ValueError("short frame")
    if buf[:4] != MAGIC or buf[4] != VERSION:
        raise ValueError("invalid frame prefix")
    ftype = buf[5]
    flags, stream = struct.unpack(">HI", buf[6:12])
    seq, plen = struct.unpack(">QI", buf[12:24])
    body = buf[HDR:]
    if plen != len(body):
        raise ValueError("payload length mismatch")
    return dict(type=ftype, flags=flags, stream=stream, seq=seq,
                payload=cbor2.loads(body) if body else None)


# --------------------------------------------------------------------------
# HTTP: /v1/config
# --------------------------------------------------------------------------
class ConfigHandler:
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint or ""

    async def handle(self, reader, writer):
        try:
            req = await reader.readline()
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            log("HTTP", req.decode(errors="replace").strip())
            cfg = {
                "protocol_version": 1,
                "websocket": "ws://127.0.0.1:%d/v1/signal" % WS_PORT,
                "turn": {"URI": TURN_URI, "Username": "mock", "Password": "mock"},
                "peer_fingerprint": self.fingerprint,
                "channels": ["gmp.chat.v1?role=guest"],
            }
            body = json.dumps(cfg).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        finally:
            await writer.drain()
            writer.close()


# --------------------------------------------------------------------------
# archive peer simulator
# --------------------------------------------------------------------------
class ArchivePeer:
    def __init__(self):
        self.history = [
            {"sender": "archivist", "body": "history entry %d" % i,
             "sent_at": 1_700_000_000 + i}
            for i in range(5)
        ]

    def reply(self, req):
        t = req["type"]
        p = req["payload"] or {}
        if t == TYPE_CHAT:
            text = str(p.get("text") or p.get("body") or "")
            return TYPE_CHAT, {"status": "ok", "message": "you said: %s" % text[:200]}
        if t == TYPE_HISTORY:
            limit = int(p.get("limit", 10))
            after = int(p.get("after", 0))
            fields = p.get("fields") or ["sender", "body", "sent_at"]
            rows = [r for r in self.history if r["sent_at"] > after][:limit]
            rows = [{k: r.get(k) for k in fields if k in r} for r in rows]
            return TYPE_HISTORY, {"status": "ok", "rows": rows, "number": len(rows)}
        return 0xFF, {"status": "error", "message": "unknown request type %d" % t}


async def ws_handler(ws, peer):
    log("=== WS connect %s" % ws.request.path)
    pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
    seen = set()

    @pc.on("datachannel")
    def on_datachannel(ch):
        log("DATACHANNEL-OPEN readyState=%s" % ch.readyState)
        log("DATACHANNEL label=%r protocol=%r id=%r negotiated=%r ordered=%r "
            "maxRetransmits=%r maxPacketLifeTime=%r"
            % (ch.label, ch.protocol, ch.id, ch.negotiated, ch.ordered,
               getattr(ch, "maxRetransmits", None),
               getattr(ch, "maxPacketLifeTime", None)))

        @ch.on("message")
        def on_message(raw):
            if isinstance(raw, str):
                log("<<< TEXT %r" % raw[:300])
                return
            log("<<< RAW %d bytes: %s" % (len(raw), raw[:64].hex()))
            try:
                req = decode_frame(raw)
            except Exception as e:
                log("    decode error: %r" % (e,))
                return
            log("    frame type=%#x flags=%#x stream=%d seq=%d payload=%r"
                % (req["type"], req["flags"], req["stream"], req["seq"], req["payload"]))
            rtype, payload = peer.reply(req)
            out = encode_frame(rtype, 0, req["stream"], req["seq"], payload)
            log(">>> %d bytes type=%#x seq=%d payload=%r"
                % (len(out), rtype, req["seq"], payload))
            ch.send(out)

    try:
        async for msg in ws:
            if isinstance(msg, bytes):
                log("<<< WS BINARY %r" % msg[:200])
                continue
            obj = json.loads(msg)
            log("<<< WS %s" % json.dumps(obj)[:800])
            mtype = obj.get("type")
            if mtype == "ice_candidate":
                # the offer already carries every candidate; trickle adds nothing
                seen.add(obj.get("candidate"))
            elif mtype == "sdp_offer":
                await pc.setRemoteDescription(
                    RTCSessionDescription(sdp=obj["sdp"], type="offer"))
                await pc.setLocalDescription(await pc.createAnswer())
                out = {"type": "sdp_answer", "sdp": pc.localDescription.sdp}
                log(">>> WS %s" % json.dumps(out)[:400])
                await ws.send(json.dumps(out))
            elif mtype == "hangup":
                log("client hangup")
                break
            else:
                log("unhandled ws type %r" % mtype)
    except Exception as e:
        log("ws loop error %r" % (e,))
    finally:
        await pc.close()


async def main():
    # aiortc mints a fresh self-signed certificate per RTCPeerConnection, which
    # would defeat peerctl's peer_fingerprint pin: reuse one fixed certificate.
    fixed = RTCCertificate.generateCertificate()
    RTCCertificate.generateCertificate = staticmethod(lambda: fixed)
    fp = fixed.getFingerprints()[0]
    fingerprint = "%s:%s" % (fp.algorithm.replace("-", ""), fp.value)
    if os.environ.get("MOCK_BAD_FP"):      # test whether peerctl pins the peer cert
        fingerprint = "sha256:" + ":".join(["00"] * 32)
    open("/tmp/mock/fingerprint.txt", "w").write(fingerprint)
    log("mock fingerprint: %s" % fingerprint)

    peer = ArchivePeer()
    await asyncio.start_server(ConfigHandler(fingerprint).handle, "0.0.0.0", HTTP_PORT)
    log("HTTP /v1/config on %d" % HTTP_PORT)
    async with serve(lambda ws: ws_handler(ws, peer), "0.0.0.0", WS_PORT):
        log("WS on %d" % WS_PORT)
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
