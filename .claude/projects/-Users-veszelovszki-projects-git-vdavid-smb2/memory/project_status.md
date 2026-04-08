---
name: Project status and next steps
description: Current state of smb2-rs development, pending work items, and quality standards
type: project
---

smb2-rs is in late Phase 9 (polish and ship). The core library works end-to-end against two real servers (QNAP NAS + Raspberry Pi).

**Current stats:** 531 unit tests + 17 integration tests, ~24K LOC, zero clippy warnings.

**Benchmark results:** smb2 beats native macOS SMB (with F_NOCACHE) on all operations at all file sizes. Compound reads give 5x download speedup for small files.

**Pending work items (in order):**
1. Auto-choose compound vs pipelined in `read_file` (try compound first, fall back if file > MaxReadSize)
2. Compound writes (CREATE+WRITE+FLUSH+CLOSE in 4-way compound — spec allows it, need to test on real servers)
3. Streaming download/upload with compound support (FileDownload and new FileUpload)
4. Test compound on Raspberry Pi (currently only tested on QNAP)
5. Fix 2 cargo doc warnings
6. Update README with final benchmark numbers

**Quality bar (from David):** Each change must be solid AND elegant, well-tested, and safe for family photos and company docs. No data loss scenarios.

**Key credentials (in cmdr benchmark config, NOT to be committed):**
- QNAP: 192.168.1.111, share "naspi", user "david"
- Pi: 192.168.1.150, share "PiHDD", guest access
