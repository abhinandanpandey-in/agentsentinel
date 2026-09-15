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

Complete. All phases (1-4) plus the three follow-up hardening items
(IPv6 support, rate-limit enforcement, obfuscated corpus) are implemented,
tested, and demoed below.

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

**3. Scope escape — a "read-only" tool spawning a shell  blocked:**

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
├── src/                # interceptor, policy engine, signature matcher, audit logger, CLI, fuzz harness
├── policies/           # example policy files
├── samples/            # benign + simulated-attack scripts used in the demo above
├── fuzz/
│   ├── agent_target.py # deliberately naive mock agent (the fuzzing target)
│   └── corpus/         # benign_*.txt and injected_*.txt adversarial documents
├── tests/
│   └── test_ipv6_cidr.cpp  # standalone unit test for IPv6 CIDR matching
├── docs/architecture.md
└── CMakeLists.txt
```

## Fuzzing harness

`fuzz_harness` drives an adversarial corpus through a deliberately naive
mock agent (`fuzz/agent_target.py`) — one that simulates the realistic
prompt-injection vulnerability: it's asked to "summarize" an untrusted
document, and if that document contains certain marker lines, it blindly
executes them as if they were legitimate instructions. This is a stand-in
for how a real LLM agent can be manipulated by injected text hidden inside
content it's processing (a document, a scraped page, an email).

AgentSentinel's own audit log is the detection oracle — the harness doesn't
need a separate "did this attack succeed" heuristic, it just checks whether
a `deny` or `signature_match` shows up for each case.

```bash
cd build && mkdir -p workdir && cd workdir
../fuzz_harness
```

```
=== AgentSentinel Fuzzing Harness — Results ===

Corpus file                       Expected    Detected    Denies    Sig.match Result
------------------------------------------------------------------------------------------
benign_base64_config.txt          benign      no          0         0         PASS
benign_meeting_notes.txt          benign      no          0         0         PASS
benign_report.txt                 benign      no          0         0         PASS
injected_aws_creds.txt            attack      yes         1         0         PASS
injected_multi_stage.txt          attack      yes         3         2         PASS
injected_obfuscated_base64.txt    attack      yes         2         1         PASS
injected_obfuscated_shell.txt     attack      yes         1         1         PASS
injected_shell_scope_escape.txt   attack      yes         1         1         PASS
injected_ssh_exfil.txt            attack      yes         2         1         PASS

9/9 cases passed.
```

The corpus includes both plaintext and base64-encoded injection attempts
(`injected_obfuscated_*.txt`), plus a benign document containing
base64-looking text that is *not* an injection
(`benign_base64_config.txt`), to check the decoding step itself doesn't
introduce false positives. The obfuscated attacks trigger the exact same
signatures as their plaintext equivalents — detection happens on the
resulting syscalls, not on parsing the instruction text, so encoding the
injection doesn't help the attacker.

Corpus naming convention (see `fuzz/corpus/`): files prefixed `benign_`
must produce zero deny/signature_match events; files prefixed `injected_`
must produce at least one. The harness exits non-zero if any case
mismatches, so it can be wired into CI as a regression check against
detection gaps — a case that used to be caught and silently stops being
caught is exactly the kind of regression this is meant to surface.

Add new corpus files freely — plain `.txt` documents containing any of the
`INJECT:*` directives documented at the top of `fuzz/agent_target.py`, or
combinations of them, following the `benign_`/`injected_` naming rule.

## Roadmap

- [x] Phase 1 — ptrace tracer (syscall visibility)
- [x] Phase 2 — seccomp enforcement + policy engine
- [x] Phase 3 — behavioral signature correlation (exfil, scope escape)
- [x] Phase 4 — fuzzing harness with adversarial corpus + detection oracle
- [x] AF_INET6 support in the `connect()` inspector — CIDR matching verified
      via a standalone unit test (`test_ipv6_cidr`), since this project's
      dev sandbox has IPv6 sockets disabled at the OS level and couldn't
      run a live end-to-end IPv6 syscall test; the interceptor's IPv6
      branch mirrors the already-verified IPv4 code path structurally.
- [x] `clone()`/rate-limit enforcement wired into the policy engine for
      `openat`, `connect`, and `clone`/`fork`/`vfork`. Tuning note: the
      default `openat_per_sec` had to be raised from an untested initial
      guess of 50 to 300 after measurement showed legitimate Python
      interpreter startup (ELF dynamic linking + import machinery
      scanning multiple candidate paths per module) makes ~30-60 `openat`
      calls in the same wall-clock second — a good example of why a rate
      limit needs to be measured against real baselines before shipping,
      not just guessed.
- [x] Obfuscated corpus (`fuzz/corpus/injected_obfuscated_*.txt`): base64
      encoded `INJECT:` directives. Key finding — the same
      `exfiltration_pattern`/`scope_escape_pattern` signatures fire
      identically whether the injection is plaintext or base64'd, because
      detection happens on the resulting syscalls, not on parsing the
      instruction. This is the core argument for syscall-level enforcement
      over text/regex-based prompt-injection filters: obfuscation defeats
      the latter far more easily than the former.

All items from the original roadmap are now complete. Possible future
directions: filesystem namespace/cgroup isolation layered on top of the
current ptrace/seccomp enforcement, and expanding the corpus with
multi-stage/chained obfuscation (nested encoding, encoding split across
multiple lines).

## Disclaimer

This is a research/portfolio project demonstrating syscall-level sandboxing
techniques for agentic AI security. It is not a hardened production security
boundary — `ptrace`-based enforcement has known TOCTOU limitations (a
sufficiently adversarial traced process can race the supervisor between
argument inspection and syscall execution). For production use, this
approach should be combined with kernel-level mandatory access control
(SELinux/AppArmor) and namespace/cgroup isolation, not relied on alone.
