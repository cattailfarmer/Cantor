# Cantor compact procedure reflection loop P0

This executable binds one exact compact coordination session to an ordinary
loopback OpenAI-compatible chat-completions endpoint. The model sees only one
run-scoped `advance_attention_procedure` tool with a closed `maximum_steps`
argument. The host retains the full context and compare-and-set handle, reads
the exact terminal record, and supplies it to a separate reflection pass.

Run `cantor-compact-reflection-loop --help` for the live command. The P0
requires one advancement to reach terminal state. It does not modify
llama.cpp, access hidden state, execute effects, contact a remote host, or
persist the volatile session.

`fixture-context --output PATH` emits one create-new, explicitly experimental
context for local proof. `--model ID` selects one exact identifier from a
multi-model advertisement; it never enables remote discovery or fallback.
