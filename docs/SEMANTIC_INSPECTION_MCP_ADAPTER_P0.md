# Semantic inspection MCP adapter P0

This native adapter exposes one read-only `inspect_sop_semantics` tool through
installed official rmcp 3.0.1. It inspects supplied SOP project bytes; it does
not host an LLM, install a service, open project paths, or perform agent work.

Build from the pinned source with `cargo build --locked --offline -p
cantor_sop_inspect_mcp --bin cantor-sop-inspect-mcp`. Development here uses
only the existing D:/CantorBuilds/target. The native executable accepts no
arguments. An independent client owns trusted launch and executable identity.

Tool arguments are exactly `{"wire_request_json":"<original wire JSON>"}`.
The string is bounded and passed to the unchanged strict SOP wire parser.
The authoritative `structuredContent` reply retains `wire_response_json`
as an exact string, not a semantically equivalent reserialization. It includes
a fixed version profile, typed outcome, byte counts, raw SHA256 values,
optional fixed fault and explicit non-authority. Request SHA256 is omitted
when an oversized direct-call argument is refused before hashing. These
coordinates are correspondence evidence, not an executable or model receipt.
Generic Serde decoding checks the reply's field/type shape only; it is not an
independent profile, transcript, executable, or semantic acceptance verifier.
Application acceptance must check the fixed profile, non-authority, identities
and retained exact wire bytes under its separately owned policy. This adapter
does not provide a new MCP receipt-validation protocol.

The outcomes are `inspection_succeeded`, `semantic_refused`, and
`adapter_refused`. Semantic refusal retains the complete original wire
response. Malformed outer wire or argument shape is an adapter refusal, not
the older EOF host's public fault. MCP `is_error` is true for either refusal.
Unknown tools are official SDK method faults. A fixed text summary never
contains supplied secrets. No ConsumerReceipt is emitted for this different
transport. Unknown, duplicate and trailing fields in the nested wire JSON
remain strict; duplicate keys already normalized by the SDK in the outer MCP
argument object cannot be detected here and are not claimed rejected.

## Fixed session ceilings

| Surface | P0 limit |
| --- | ---: |
| Decoded wire request | 262,144 UTF-8 bytes |
| Complete wire response | 1,048,576 bytes |
| Input MCP frame, including optional newline | 2,097,152 bytes |
| Encoded output frame, including newline | 4,194,304 bytes |
| Aggregate actual input | 8,388,608 bytes plus one refusal witness |
| Aggregate reserved output | 8,388,608 bytes |
| Admitted decoded messages, including handshake | 32 |
| Active semantic calls | 1, otherwise busy refusal |
| Native session / runtime shutdown wait | 60 seconds / 250 milliseconds |
| Async / blocking stdio workers | 2 / at most 2 |

The official decoder's payload ceiling reserves one byte for its delimiter;
an EOF-only payload uses that same conservative payload limit. The SDK
retains BOM and compatibility behavior and can decode a complete value at
EOF. Closing input can end the SDK worker before pending asynchronous replies
flush: await replies before closing. This is not the older one-shot EOF host.

Reservation counts are not delivered-byte measurements. A decoder, budget,
write, handshake or deadline fault ends the session. Native faults or extra
arguments produce exit 2 with only `cantor_semantic_inspection_mcp_refused\n`
on stderr; initialized normal disconnect exits 0. Output carries only the
SDK protocol, never debug logs. Generic `run_io` operates caller-supplied
streams and does not kill the caller's runtime. Only standalone main owns the
runtime and its bounded shutdown/process termination.

Native main safely duplicates inherited stdin/stdout handles or descriptors
into File wrappers without acquiring any pathname or arbitrary user handle.
Tokio's noncancelable blocking stdio work can remain until process termination;
explicit shutdown avoids default runtime Drop waiting indefinitely. Real
native withheld-input/unread-output tests are required in both profiles.
These are separate signed transport effects, not authority imported from the
pure consumer library. The returned semantic response can be constructed up
to the inherited producer ceiling before the smaller export limit refuses it;
this adapter does not claim a streaming producer or a total allocation quota.

## Ownership and evidence

P0 is an ephemeral bounded SDK session, not an indefinitely registered
resident agent server. The application owns launch, restart, longer-lived
integration and acceptance. Windows native gates do not establish a Linux
runtime claim merely because safe Unix descriptor conversion is included.
No Eclipse/Scribe app files, remote hosts, providers or model state are changed.

Frozen formation is replayed by
`scripts/verify_cantor_semantic_inspection_mcp_adapter_p0_formation.ps1`.
The original eight consumer fixtures supply five exact wire outcomes and
three adapter refusals; tests cover SDK initialization/calls/recovery,
mutation/budget/concurrency limits, fresh native sessions and real shutdown.
Actual measured gate identities belong in the completion proof and reentry,
not a speculative installed-agent claim.

The independent metadata verifier is also exercised against eight isolated
copied-tree mutations: focused/native counts, model-scope promotion, session
limit, component/outer artifact membership, formation profile and pinned wire
bytes. Six cases refresh the outer manifest hash before refusal, so a stale
hash alone cannot stand in for those semantic checks. Copies are retained in
a fresh small D-drive test directory; source, foreign narrative and runtimes
are not mutated. This verifies metadata refusal, not an executable trust or
model receipt. Completion signature replay is separately required on the
unchanged real tree after these pre-signature mutation tests.
