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
