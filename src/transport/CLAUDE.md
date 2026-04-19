# Transport -- send/receive abstraction

Split transport traits for SMB2 message I/O. Two implementations: TCP and mock.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `TransportSend`, `TransportReceive`, `Transport` traits |
| `tcp.rs` | `TcpTransport` -- direct TCP to port 445, handles framing |
| `mock.rs` | `MockTransport` -- FIFO response queue for testing |

## Split traits

`TransportSend` and `TransportReceive` are separate traits. This avoids deadlock in the pipeline's `tokio::select!` loop where one task sends requests while another concurrently reads responses on the same connection. A single `Transport` trait would require `&mut self` for both directions, making concurrent send+receive impossible without `Arc<Mutex>`.

The blanket impl `Transport` combines both halves. `Connection` stores `Box<dyn TransportSend>` and `Box<dyn TransportReceive>` separately.

## TCP framing

```
[0x00] [length: 3 bytes, big-endian] [SMB2 message(s)]
```

- First byte must be `0x00`
- Next 3 bytes: message length in big-endian (network byte order)
- Maximum frame size: 16 MB
- This is the ONLY big-endian value in SMB2

`TcpTransport::send` prepends the 4-byte header. `TcpTransport::receive` reads the header, then `read_exact` for the payload.

## Who reads the transport

`TransportReceive::receive()` is called by exactly one owner: the background receiver task spawned by `Connection::from_transport` (Phase 2 actor refactor). No other code path calls `receive()` in production. This is the invariant that makes per-`MessageId` routing sound — there's a single serialized read of the wire, then demux to per-request `oneshot::Sender`s. See `src/client/CLAUDE.md` § "Connection internals: receiver task + `oneshot` routing".

`TransportSend::send()` is called from the caller thread (the one holding `&mut Connection`). `TcpTransport`'s internal Mutex on the write half serializes sends — relevant for Phase 3 once `Connection` becomes `Clone`.

## MockTransport

Used by all unit tests. Stores sent messages for inspection and returns queued responses in FIFO order. Thread-safe via `std::sync::Mutex`.

Phase 2 changed `receive()` from "return `Err(Disconnected)` immediately when the queue is empty" to "block on `tokio::sync::Notify` until data is queued or `close()` is called". Required because the Connection's receiver task calls `receive()` in a loop — a premature `Disconnected` would kill the task while a test was still setting up responses.

- `queue_response(data)` / `queue_responses(vec)` push to the queue and call `notify_one()`. `notify_one` stores a permit if no receiver is parked, so the next `.notified().await` returns immediately.
- `close()` sets an atomic `closed` flag and calls BOTH `notify_one()` (covers the wake-loss race where `receive()` is between `closed.load()` and `.notified().await`) and `notify_waiters()` (wakes already-parked waiters).
- External consumers using `MockTransport` in their own tests must call `close()` to get an explicit end-of-stream; the implicit "empty queue = disconnected" behavior is gone.

## Gotchas

- **Partial TCP reads**: Always use `read_exact` to read the full frame. TCP can deliver partial data in any `read()` call.
- **16 MB max frame**: Reject frames larger than 16 MB to prevent OOM from malicious servers.
- **Frame may contain multiple messages**: Compound responses arrive in a single frame. The Connection's receiver task splits them by `NextCommand` offsets and routes each sub-response by `MessageId` independently.
- **`MockTransport::close()` wake-loss**: `notify_waiters()` alone only wakes already-parked waiters; if `close()` fires between `receive()`'s `closed.load()` check and its `notified().await`, the signal is lost. `close()` therefore also calls `notify_one()` to store a permit — next `.notified().await` returns immediately and the loop re-observes `closed=true`. Noticed via code review after Phase 2.
