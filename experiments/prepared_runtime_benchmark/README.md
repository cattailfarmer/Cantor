# Cantor PreparedRuntime benchmark

This isolated crate measures the bounded `cantor-prepared-runtime/0.1`
candidate without adding a profiling dependency to production crates.

The latency command reports separately:

- direct request-scoped execution;
- one process's first generation-plus-scope preparation;
- generation construction (owned environment clone, environment digest, and generation identity);
- warm exact-scope preparation after generation construction;
- a cold runtime's first request (construction, admission, fabric construction, and operation);
- replacement to a different valid exact scope and back;
- prepared exact-scope hits.

Run one release process per corpus shape:

```text
cargo run --release --locked -- latency 1 40
cargo run --release --locked -- latency 32 40
cargo run --release --locked -- latency 256 40
```

The memory command uses `dhat` 0.3.3 as the process-wide allocation tracker.
Baseline and prepared measurements must run in separate release processes so
their current and peak counters cannot contaminate one another:

```text
cargo run --release --locked --features dhat-heap -- memory baseline 256
cargo run --release --locked --features dhat-heap -- memory prepared 256
```

`current_bytes` is the live allocation count at the measurement point.
`peak_bytes` includes fixture compilation and, for the prepared mode,
preparation. Absolute values include the benchmark request and fixture
bookkeeping; the baseline-versus-prepared delta is the bounded candidate cost.
The fixtures are synthetic signed packages with one term and source per package.
They represent the measured Phase6 shapes, not a production corpus, operating
system RSS, allocator fragmentation, or a distributed service workload.
