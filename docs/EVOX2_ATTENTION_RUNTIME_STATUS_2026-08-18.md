# EVO-X2 Needle attention runtime status — 2026-08-18

This status anchor consolidates the bounded Cantor attention-runtime campaign
from Git checkpoint `b0e27bb` through `d9bd690`. It is a navigation surface,
not new implementation authority; the cited specifications and proofs remain
canonical.

## Outcome

Cantor now has an isolated, deployed, fail-closed Needle 2 route controller and
a separate Codex-compatible STDIO MCP adapter. The controller selects only from
a content-addressed three-procedure catalogue, validates caller grounding and
explicit declared fields, exports a value-private admission account, archives
the run, and semantically verifies that evidence. The adapter independently
pins those dependencies, exposes only `route_attention`, serializes execution
within one server process, and returns either a verified learned proposal or a
structured verified refusal.

Positive routes now include `cantor-attention-frame/0.1`, an ordered
`FOCUS → BOUND → ADMIT → RETURN` projection. Caller-derived arguments are typed
as data, `ADMIT` is route-proposal evidence only, and `RETURN` carries the run
and manifest identities. Faults never carry a positive frame.

The optional `response_mode: "frame"` performs the same complete inference,
hash, admission, evidence, and single-flight work but omits duplicated runtime
and verifier records from the success response. Full remains the default.

## Measured result

All three current procedure families passed paired full/frame calls on EVO-X2:

| Procedure | Full bytes | Frame bytes | Reduction |
| --- | ---: | ---: | ---: |
| resolve subject | 3,052 | 1,005 | 3.0368× |
| inspect identity boundary | 3,226 | 1,047 | 3.0812× |
| review attention transition | 3,482 | 1,096 | 3.1770× |

This is a bounded result for the present catalogue and argument sizes, not a
universal guarantee for future procedures.

Reproduce the paired measurement against the reviewed deployment with:

```powershell
.\scripts\measure_attention_frame_response_modes.ps1
```

The script first runs the fail-closed deployment/readiness check, then requires
every current procedure family to meet the configured ratio. It launches
ephemeral MCP jobs and therefore creates normal remote run evidence, but it
does not change Codex configuration or start a persistent service.

## Current deployed identity

- host: `EVO-X2`
- root: `C:\AI\services\cantor-attention-mcp`
- adapter bytes: `2,951,680`
- adapter SHA-256: `37860b031a97b58de08cb669cf6b09b3bbac3db12c3fba3f198674231255deef`
- adapter deployment manifest SHA-256: `3ffa3003ac9b9711d3c075c5ea48524359943e6d9f2bfc99869d1640a3d8f405`
- adapter config SHA-256: `818a43df51b8bbfe4a7d8abe38458efbe4ad9c946dc0504d78f28e09f9ebf45c`
- catalogue digest: `057bb872686a2d6497670d255d4ae323844eeada4fdd5e620e5767f70850a466`
- existing llama.cpp process: PID `12780`, unchanged
- shared SOP-agent SHA-256: `18ddea8f40cb3c4a75bb879379ea57ec85a60f6dd76fa75af9ca048117db4df8`, unchanged
- persistent attention-adapter process count after probes: `0`

## Verification state

- full Rust workspace tests pass, with the existing governed physical fixture
  remaining ignored;
- workspace all-target/all-feature clippy passes with warnings denied;
- focused adapter suite passes five protocol and fault tests;
- current evidence reconciliation covers 23 manifests and 1,030 artifact
  references with zero stale entries;
- official RMCP clients pass local, SSH, selected, refused, recovery,
  single-flight, AttentionFrame, compact-mode, and closed-schema paths; and
- local Codex MCP inventory remains unchanged and collision-free for the
  proposed `cantor-attention` name.

The campaign spans 28 published commits and, relative to `b0e27bb`, 262 changed
paths. Git `HEAD` and `origin/codex/self-hosted-corpus` both resolve to
`d9bd690f1b8bce558f148b8fd67e4e5d28fb187a` at this anchor.

### Post-anchor verification closure

The immutable campaign anchor above remains the historical consolidation point.
Subsequent reproducibility work culminates in boundary-proof checkpoint
`071cc9ef3c4ce975afe72df2631bb0f6db748b7d` without changing the deployed
binary. A live `response_mode: "frame"` concurrency probe over SSH STDIO
returned exactly one verified compact frame (run
`b546a092-1396-4c65-8b33-b8f8a40c77c2`) and one immediate `runtime_busy`
fault without a frame. Full workspace tests and all-target/all-feature Clippy
were rerun at this head; the current evidence set remains 23 manifests and
1,030 references with zero stale entries.

## Preserved boundaries

- learned routing is not signed SOP meaning, truth, authorization, or safety;
- literal and declared-field identity checks establish representation
  consistency, not factual accuracy;
- process-local single-flight is not a distributed token ring or cluster lock;
- compact mode reduces returned context, not inference compute;
- the adapter never invokes llama.cpp or `query_sop`;
- no Codex MCP registration was silently performed; and
- the existing llama.cpp and shared SOP-agent services were not restarted or
  changed.

## Reentry

The exact operator preflight, add, restart, verification, and removal sequence
is in [`CODEX_ROUTE_ATTENTION_REGISTRATION.md`](CODEX_ROUTE_ATTENTION_REGISTRATION.md).
Run the read-only preflight first:

```powershell
.\scripts\test_codex_attention_mcp_registration_readiness.ps1
```

The next authorized decision is explicit registration. After registration, the
next experiment should compare real Codex task outcomes across no tool, full
mode, and frame mode. Learned paraphrase coverage, exterior production signing,
and distributed scheduling remain separate work.
