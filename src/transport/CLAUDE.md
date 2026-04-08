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

## MockTransport

Used by all unit tests. Stores sent messages for inspection and returns queued responses in FIFO order. Thread-safe via `Mutex`.

## Gotchas

- **Partial TCP reads**: Always use `read_exact` to read the full frame. TCP can deliver partial data in any `read()` call.
- **16 MB max frame**: Reject frames larger than 16 MB to prevent OOM from malicious servers.
- **Frame may contain multiple messages**: Compound responses arrive in a single frame. The caller (`Connection::receive_compound`) splits them by `NextCommand` offsets.
