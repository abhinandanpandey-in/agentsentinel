# AgentSentinel — Syscall-Level Firewall for Agentic AI Code Execution

## 1. Problem Statement / Threat Model

LLM agents and agentic frameworks (code-interpreter tools, MCP servers that execute
generated code, autonomous coding agents) frequently execute model-generated code or
shell commands with little enforcement beyond "the model said this tool call is safe."

Attack surface this project targets:

- **Prompt-injection → code execution**: injected instructions hidden in documents,
  web pages, or tool outputs cause the agent to run code that exceeds its declared
  intent (e.g., a "summarize this PDF" tool suddenly reading `~/.ssh/id_rsa`).
- **Tool-hijacking via unexpected syscalls**: a tool call that claims to do local
  data analysis instead opens outbound network sockets (exfiltration).
- **Privilege/scope creep**: agent-generated scripts spawning subprocesses,
  modifying files outside their working directory, or escalating beyond declared
  permissions.

AgentSentinel enforces a **behavioral contract** at the OS syscall level — not by
trusting what the LLM/tool *says* it will do, but by intercepting what the resulting
process *actually does*.

---

## 2. High-Level Components

```
                ┌────────────────────┐
                │   Launcher/CLI      │  agentsentinel run --policy web.json -- python3 tool.py
                └─────────┬───────────┘
                          │ fork+exec (under seccomp+ptrace)
                          ▼
                ┌────────────────────┐
                │  Target Process     │  (LLM-generated / agent tool code)
                └─────────┬───────────┘
                          │ syscalls
                          ▼
                ┌────────────────────┐
                │ Syscall Interceptor │  seccomp-bpf filter + ptrace supervisor
                └─────────┬───────────┘
                          │ flagged/traced syscalls
                          ▼
                ┌────────────────────┐
                │   Policy Engine     │  rule matching (paths, sockets, exec args)
                └─────────┬───────────┘
              allow │           │ deny/flag
                    ▼           ▼
             continue      ┌────────────────────┐
                            │ Behavioral Signature│  matches known agentic-attack
                            │      Matcher         │  patterns (exfil, priv-esc, etc.)
                            └─────────┬───────────┘
                                      ▼
                            ┌────────────────────┐
                            │   Audit Logger      │  structured JSON trace
                            └────────────────────┘
```

Optional 6th component (Phase 4): **Fuzzing Harness** — feeds adversarial/injected
prompts into a target agent framework and uses AgentSentinel as the observation layer
to detect when injected instructions cause out-of-scope syscalls.

---

## 3. Component Breakdown

### 3.1 Launcher
- Spawns the target process via `fork()` + `PTRACE_TRACEME` + `execve()`.
- Applies a `seccomp-bpf` filter to the child **before** `execve()` via
  `prctl(PR_SET_SECCOMP, ...)` or `seccomp_load()` (libseccomp).
- Sets up Linux namespaces (`unshare(CLONE_NEWNET|CLONE_NEWPID|CLONE_NEWNS)`) and an
  optional `chroot`/`pivot_root` for filesystem isolation, plus cgroups for
  CPU/memory/PID limits.

### 3.2 Syscall Interceptor
- **Fast path**: `seccomp-bpf` allowlist for syscalls always considered safe
  (e.g., `read`, `write` on already-opened fds, `mmap` for heap growth) — these run
  with zero tracer overhead.
- **Slow path**: syscalls that need argument inspection (`openat`, `connect`,
  `execve`, `socket`, `clone`) are set to `SECCOMP_RET_TRACE`, which traps into the
  `ptrace` supervisor so you can inspect actual arguments (file paths, IP/port,
  exec argv) before allowing/denying.
- Use `PTRACE_PEEKDATA`/`process_vm_readv` to read string arguments (paths, argv)
  out of the traced process's memory.

### 3.3 Policy Engine
- Rules loaded from a JSON/YAML policy file, compiled into an in-memory matcher at
  startup (avoid re-parsing per syscall — this is the "systems" part of the systems
  project).
- Rule types:
  - **Path rules**: allow/deny prefixes (`/etc/*`, `~/.ssh/*`, working-dir-only).
  - **Network rules**: allowed destination IP/CIDR + port allowlist; deny-by-default.
  - **Exec rules**: allowed subprocess binaries/argv patterns.
  - **Rate rules**: max syscalls of a given class per second (crude DoS/loop guard).
- Matching should be O(1)/O(log n) where possible (e.g., a trie for path prefixes)
  rather than linear regex scanning per syscall — this is the detail that separates
  "research-grade" from "script."

### 3.4 Behavioral Signature Matcher
- Sits above raw policy rules; correlates *sequences* of flagged events into known
  attack patterns rather than single-syscall triggers. Examples:
  - `openat(~/.ssh/*)` followed within N syscalls by `connect()` to a non-allowlisted
    IP → **exfiltration pattern**.
  - Declared "read-only data analysis" tool spawning `execve("/bin/sh", ...)` →
    **scope-escape pattern**.
  - Repeated `clone()`/`fork()` bursts → **fork-bomb / persistence attempt**.
- Implement as a small state machine per process (not a full ML model — a
  deterministic, auditable state machine is more defensible in a security context
  and easier to explain in a writeup).

### 3.5 Audit Logger
- Structured JSON, one record per flagged/denied event: timestamp, syscall,
  resolved arguments, policy rule matched, verdict (allow/deny/flag).
- This log is the actual "proof of work" artifact for a portfolio/demo — show a
  side-by-side of an injected prompt and the resulting syscall trace it produced.

### 3.6 (Phase 4) Fuzzing Harness
- Generates adversarial tool-call payloads / injected instructions, feeds them
  through a target agent (e.g., a small LangChain/MCP tool-calling loop you stand
  up as the test subject), and uses AgentSentinel's audit log as the oracle for
  "did this injection cause an out-of-scope syscall."

---

## 4. Tech Stack

- **Language**: C++17/20
- **Core OS APIs**: `ptrace(2)`, `seccomp-bpf` via `libseccomp`, `unshare(2)`,
  `cgroups` (v2, via `/sys/fs/cgroup`)
- **JSON**: `nlohmann::json` for policy files + audit logs
- **Build**: CMake
- **Target OS**: Linux only (state this explicitly — syscall interception is
  platform-specific; don't try to fake cross-platform support)
- **Testing**: a small corpus of benign and malicious sample scripts to validate
  policy enforcement (this doubles as your demo material)

---

## 5. Suggested Repo Structure

```
agentsentinel/
├── src/
│   ├── launcher.cpp / launcher.hpp
│   ├── interceptor.cpp / interceptor.hpp    # seccomp+ptrace core
│   ├── policy_engine.cpp / policy_engine.hpp
│   ├── signature_matcher.cpp / signature_matcher.hpp
│   ├── audit_logger.cpp / audit_logger.hpp
│   └── main.cpp
├── policies/
│   ├── strict-readonly.json
│   └── web-tool-default.json
├── samples/                # benign + malicious test scripts for the demo
│   ├── benign_data_analysis.py
│   ├── malicious_ssh_exfil.py
│   └── malicious_scope_escape.py
├── fuzz/                   # Phase 4
│   └── prompt_injection_corpus/
├── tests/
├── CMakeLists.txt
└── README.md               # threat model + architecture diagram + demo GIF
```

---

## 6. MVP Roadmap

1. **Phase 1 — Tracer only**: `ptrace`-based tracer that logs every syscall a child
   process makes (no blocking yet). Validates your interception pipeline works.
2. **Phase 2 — Enforcement**: add `seccomp-bpf` filter + policy engine; start
   denying/allowing based on a simple path/network policy file.
3. **Phase 3 — Behavioral signatures**: add the state-machine matcher for
   multi-syscall attack patterns (exfil, scope-escape).
4. **Phase 4 — Fuzzing harness**: wire up a small target agent + adversarial prompt
   corpus, use AgentSentinel as the detection oracle.

Each phase is independently demo-able, which matters for a portfolio repo — you get
working commits/tags at each stage rather than one big unreviewable dump.

---

## 7. Example Policy File

```json
{
  "name": "web-tool-default",
  "filesystem": {
    "allow": ["./workdir/**"],
    "deny": ["~/.ssh/**", "/etc/**", "~/.aws/**"]
  },
  "network": {
    "default": "deny",
    "allow": [{ "cidr": "127.0.0.1/32", "ports": [11434] }]
  },
  "exec": {
    "allow": ["/usr/bin/python3"]
  },
  "rate_limits": {
    "openat_per_sec": 50,
    "connect_per_sec": 5
  }
}
```

## 8. Example Audit Log Entry

```json
{
  "timestamp": "2026-09-11T10:22:31Z",
  "pid": 48213,
  "syscall": "connect",
  "args": { "dest_ip": "185.23.14.9", "dest_port": 443 },
  "policy_rule": "network.default_deny",
  "signature_match": "exfiltration_pattern",
  "verdict": "deny",
  "preceding_event": {
    "syscall": "openat",
    "path": "/home/user/.ssh/id_rsa",
    "delta_ms": 340
  }
}
```

This kind of paired trace (file read → immediate outbound connection, denied) is
exactly the artifact that makes the repo read as research rather than a toy.

---

## 9. Why This Reads as Expert-Level

- Real kernel-interface work (`seccomp`, `ptrace`, namespaces) — not a library
  wrapper.
- Directly tied to a named, current problem in agentic AI security (prompt
  injection → downstream execution) rather than generic sandboxing.
- Deterministic, auditable detection logic (state machine) instead of a black-box
  classifier — defensible in a security writeup.
- Phased roadmap produces real, demoable commits instead of one opaque final push.
