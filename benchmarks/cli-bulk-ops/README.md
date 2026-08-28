# CLI bulk-operation benchmark

`bulk-bench.sh` compares three ways of doing many small metadata operations
against one server: through a mounted SMB share, over SSH, and with `smb2-cli`
speaking SMB directly at several `-j` concurrency levels. It's what the
`-j` numbers in the CLI's README come from.

Each arm gets a disjoint slice of the input list, so no path is touched twice.

Build the binary first (`cargo build --release -p smb2-cli`), then run the
script with no arguments for usage.
