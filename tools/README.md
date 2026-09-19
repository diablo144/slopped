# tools

| file | purpose |
|------|---------|
| `slopped_client.py` | standalone archive-peer client; can emit frames `peerctl` refuses to (bad lengths, oversize, odd Type/Flags/StreamID, raw CBOR). Needs `pip install aiortc websockets cbor2`. |
| `mockpeer.py` | local signalling endpoint + archive peer used to verify the protocol offline. |
| `rev/disasm.py <start> <end>` | objdump of an address range with string/call-target annotations. |
| `rev/fn.py <substring>` | disassemble every function whose name matches. |
| `rev/reflect.py` | walker for Go reflect tables: dumps struct fields, offsets, kinds and tags. |
| `rev/funcs.txt` | all 10595 functions recovered from the pclntab, with entry addresses. |

See `../NOTES.md` for the protocol write-up these were used to produce.
