# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-09

### Added

- **Kerberos authentication** — full AS + TGS + AP-REQ flow, tested end-to-end against Windows Server 2022 with Active Directory Domain Services
- **Credential cache (ccache) support** — read MIT Kerberos ccache files (v3 and v4) for password-less authentication from `kinit` tickets
- `Session::setup_kerberos()` and `Session::setup_kerberos_from_ccache()` public API
- AP-REP mutual authentication with server sub-session key extraction
- Five Kerberos modules: `authenticator`, `messages`, `crypto`, `kdc`, `ccache`
- Support for AES-256, AES-128, and RC4-HMAC encryption types
- Integration tests against real Windows AD (AWS EC2)

### Key implementation details

These are documented in `src/auth/CLAUDE.md` but worth calling out because they're hard-won and not obvious from specs alone:

- MS Kerberos OID (`1.2.840.48018.1.2.2`) required as primary SPNEGO mechanism for Windows
- Key usage 11 (not 7) for AP-REQ Authenticator encryption in SPNEGO exchanges
- GSS-API wrapping of AP-REQ inside SPNEGO mechToken
- Raw ticket byte pass-through (re-encoding corrupts the encrypted ticket)
- Session key etype detection from TGS-REP (may differ from ticket encryption type)

## [0.1.0] - 2026-03-15

### Added

- Initial release
- SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 dialect support
- NTLM authentication (NTLMv2 with MIC)
- Compound requests (3-way read, 4-way write)
- Pipelined I/O with sliding window and credit management
- SMB 3.x signing (HMAC-SHA256, AES-CMAC, AES-GMAC)
- SMB 3.x encryption (AES-128/256-CCM/GCM)
- Streaming download/upload with progress callbacks
- File watching via CHANGE_NOTIFY
- Share enumeration via IPC$ + srvsvc RPC
- Reconnection support
- 733+ unit tests, 12 Docker integration containers
