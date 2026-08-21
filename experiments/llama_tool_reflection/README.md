# llama.cpp tool-reflection probe

This is an isolated falsification experiment, not the Cantor engine. It asks an
unmodified `llama-server` to:

1. call one `cantor_reflect` tool with exact parameters;
2. receive a deterministic expression from the Rust host;
3. import that expression in a second inference checkpoint; and
4. return the same normalized meaning for verbose, condensed, and directive
   expressions.

The governing contract is
`specifications/Cantor_Llama_CPP_Tool_Reflection_Probe.sop`.

## Run

From the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_llama_cpp_probe.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_llama_cpp_probe.ps1
```

Leave the server running, then use a second terminal:

```powershell
cargo run --manifest-path .\experiments\llama_tool_reflection\Cargo.toml
```

The probe exits with `0` only if all three tool calls and all three imported
results satisfy the exact contract. Its sanitized evidence is written to
`experiments/llama_tool_reflection/artifacts/latest.json`. Provider-private
reasoning fields are recursively removed before writing.

The experiment deliberately does not implement SOP parsing, semantic search,
learned routing, faculty deliberation, distributed agents, or model-internal
intervention.

## Governed lifecycle A/B tool loop

The same package also contains the Slice 11 `cantor-lifecycle-tool-loop`
binary. It compares two host-side MCP routes while presenting the model with
one identical closed command:

- the stateless arm sends the complete governed lifecycle request to Slice 8
  on every validation;
- the volatile-custody arm registers once outside measured steady state and
  sends only the exact Slice 10 handle thereafter.

Both routes must equal the direct Slice 7 response byte-for-byte before the
result is projected into checkpoint two. The model can name only a governed
fixture and `validate`; it cannot author a body, signature, receipt, handle, or
effect. The output retains trial-level byte, token, latency, call-validity, and
import-validity observations while recursively omitting provider-private
reasoning fields.

The provider-free bridge probe is followed by a separate fail-closed evidence
verifier. It decodes a strict report schema, reconstructs every expected trial
coordinate and transport argument, checks exact lifecycle responses and
restart loss, and recomputes the published byte comparison from raw trials.
The producer's own summary is therefore not accepted as proof of itself.
The verifier also has a distinct provider-unavailable mode that binds the
pinned loopback and release identity, requires null preflight and zero
registrations or trials, and rejects remote endpoint substitution.

Run all provider-independent gates from the repository root:

```powershell
powershell.exe -NoProfile -File .\scripts\test_lifecycle_tool_loop_measurement.ps1
```

After the pinned local llama.cpp server is healthy, run bounded live trials:

```powershell
powershell.exe -NoProfile -File .\scripts\run_lifecycle_tool_loop_measurement.ps1
```

An unavailable or mismatched provider produces an explicit evidence file and
no synthetic trial. The harness accepts only an HTTP loopback endpoint, the
pinned `gpt-oss-20b` alias and model path, and completions reporting the pinned
`b10181-caa596ab3` system fingerprint.
