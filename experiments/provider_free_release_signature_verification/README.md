# Provider-free release signature verification P0

This experiment builds the separate verification-only binary in locked offline
Ubuntu 24.04 WSL, creates one policy and detached envelope with a fixed public
synthetic seed, verifies the exact current Windows portable bundle and evidence
twice, requires byte-identical receipts, and removes the fixture root before
publishing checked artifacts.

Retained policy, envelope, receipt, Linux verifier binary, and sanitized report
contain public fixture material only. The independent PowerShell verifier binds
their exact identities and nonclaims without invoking the Rust verifier or
signing anything.

This proves mechanics, not policy governance, publisher identity, trust
provisioning, supported delivery, installation, production secret lifecycle,
operator acceptance, or production readiness.
