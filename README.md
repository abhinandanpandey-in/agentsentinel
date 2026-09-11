# AgentSentinel

A syscall-level firewall for agentic AI code execution, written in C++.

Most "AI sandboxing" projects trust the LLM/tool call description of what it's
about to do and wrap it in a Docker container. AgentSentinel doesn't trust the
description — it intercepts the actual Linux syscalls the process makes
(`openat`, `connect`, `execve`) via `seccomp-bpf` + `ptrace`, evaluates them
against a policy, and correlates sequences of events into known agentic
attack patterns (prompt-injection-driven exfiltration, scope escape via shell
spawn) using a deterministic, auditable state machine — not a black box.

## Threat model

See [`docs/architecture.md`](docs/architecture.md) for the full writeup. In
short: LLM agents and agentic frameworks (code-interpreter tools, MCP servers
executing generated code, autonomous coding agents) execute model-generated
code with little enforcement beyond "the model said this tool call is safe."
AgentSentinel enforces a behavioral contract at the OS level instead.

## Status

MVP (Phase 1–3 of the roadmap) is implemented and demoed below. Phase 4
(fuzzing harness) is the next milestone — see [Roadmap](#roadmap).

**Linux x86_64 only.** This project intentionally does not attempt to be
cross-platform — syscall interception is platform-specific by nature.

## Build

Dependencies: CMake ≥ 3.16, a C++20 compiler, `libseccomp-dev`, `nlohmann-json3-dev`.

```bash
sudo apt-get install -y cmake libseccomp-dev nlohmann-json3-dev
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

## Usage

```bash
./agentsentinel run --policy <policy.json> [--log audit.jsonl] -- <cmd> [args...]
```

## Demo: three scenarios

**1. Benign tool — runs clean:**

```bash
cd build && mkdir -p workdir && cd workdir
../agentsentinel run --policy ../../policies/web-tool-default.json \
    -- /usr/bin/python3 ../../samples/benign_data_analysis.py
```

**2. Simulated prompt-injection → SSH key exfiltration — blocked and correlated:**

```bash
../agentsentinel run --policy ../../policies/web-tool-default.json \
    -- /usr/bin/python3 ../../samples/malicious_ssh_exfil.py
```

Resulting audit trail (this is the core artifact — file read immediately
followed by a blocked outbound connection, automatically correlated):

```json
{"syscall":"openat","args":{"path":"/root/.ssh/id_rsa"},
 "policy_rule":"filesystem.deny:~/.ssh/**","verdict":"deny"}
{"syscall":"connect","args":{"dest_ip":"93.184.216.34","dest_port":443},
 "policy_rule":"network.default_deny","signature_match":"exfiltration_pattern",
 "verdict":"deny","preceding_event":{"syscall":"openat",
 "detail":"/root/.ssh/id_rsa","delta_ms":0}}
```

**3. Scope escape — a "read-only" tool spawning a shell — blocked:**

```bash
../agentsentinel run --policy ../../policies/web-tool-default.json \
    -- /usr/bin/python3 ../../samples/malicious_scope_escape.py
```

```json
{"syscall":"execve","args":{"binary":"/bin/sh"},
 "policy_rule":"exec.default_deny","signature_match":"scope_escape_pattern",
 "verdict":"deny"}
```

Note the correct pid attribution: the shell spawn is attributed to a *child*
pid distinct from the Python interpreter's pid, because AgentSentinel traces
`fork`/`vfork`/`clone` explicitly rather than only the top-level process —
without this, subprocess syscalls are invisible to the tracer and get
silently rejected by the kernel (`ENOSYS`) with zero audit trail, which
defeats the entire purpose of the tool.

## How it works

- **Fast path**: a `seccomp-bpf` filter defaults to `ALLOW` for all syscalls
  except a short list (`openat`, `connect`, `execve`, `clone`/`fork`,
  `socket`) that route to `SECCOMP_RET_TRACE`. Syscalls we don't care about
  never leave the kernel fast path.
- **Slow path**: traced syscalls trap into a `ptrace` supervisor, which reads
  the real arguments (paths, destination IP/port, exec argv) out of the
  traced process's memory via `process_vm_readv` and evaluates them against
  a JSON policy.
- **Policy engine**: path/network/exec allow-deny rules, deny-list or
  allow-list mode, plus per-syscall-class rate limiting.
- **Signature matcher**: a small deterministic state machine that correlates
  *sequences* of events (sensitive file read → network connect within a time
  window) rather than only single-syscall triggers.
- **Audit logger**: structured JSON Lines, one record per flagged/denied
  event, including the correlated preceding event where relevant.

Full component breakdown, syscall filter design, and rationale in
[`docs/architecture.md`](docs/architecture.md).

## Repo structure

```
agentsentinel/
├── src/                # interceptor, policy engine, signature matcher, audit logger, CLI
├── policies/           # example policy files
├── samples/            # benign + simulated-attack scripts used in the demo above
├── docs/architecture.md
└── CMakeLists.txt
```

## Roadmap

- [x] Phase 1 — ptrace tracer (syscall visibility)
- [x] Phase 2 — seccomp enforcement + policy engine
- [x] Phase 3 — behavioral signature correlation (exfil, scope escape)
- [ ] Phase 4 — fuzzing harness: adversarial prompt-injection corpus fed
      through a real tool-calling agent loop, using AgentSentinel's audit
      log as the detection oracle
- [ ] AF_INET6 support in the `connect()` inspector (currently IPv4 only)
- [ ] `clone()`/rate-limit enforcement wired into the policy engine (state
      machine hooks exist; not yet enforced)

## Disclaimer

This is a research/portfolio project demonstrating syscall-level sandboxing
techniques for agentic AI security. It is not a hardened production security
boundary — `ptrace`-based enforcement has known TOCTOU limitations (a
sufficiently adversarial traced process can race the supervisor between
argument inspection and syscall execution). For production use, this
approach should be combined with kernel-level mandatory access control
(SELinux/AppArmor) and namespace/cgroup isolation, not relied on alone.
