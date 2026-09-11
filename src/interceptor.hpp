#pragma once
#include <string>
#include <vector>
#include <sys/types.h>
#include "policy_engine.hpp"
#include "signature_matcher.hpp"
#include "audit_logger.hpp"

namespace agentsentinel {

// Owns the traced child process, installs the seccomp-bpf filter that routes
// sensitive syscalls to PTRACE, and runs the ptrace supervisor loop that
// inspects arguments and applies the policy/signature engines.
class Interceptor {
public:
    Interceptor(PolicyEngine policy, const std::string& audit_log_path,
                const std::vector<std::string>& sensitive_path_globs);

    // Forks, execs argv[0..] as the traced child, applies the seccomp filter
    // in the child before execve, then runs the supervisor loop in the
    // parent until the child exits. Returns the child's exit code.
    int run(const std::vector<std::string>& argv);

private:
    PolicyEngine policy_;
    AuditLogger audit_;
    SignatureMatcher sig_matcher_;
    std::vector<std::string> sensitive_globs_;

    // Applies PR_SET_NO_NEW_PRIVS + the seccomp-bpf filter. Must run in the
    // child, after PTRACE_TRACEME and before execve.
    static void install_seccomp_filter();

    // Reads a NUL-terminated string out of the traced child's address space
    // at `addr`, using process_vm_readv (falls back to PTRACE_PEEKDATA).
    std::string read_child_string(pid_t pid, unsigned long long addr, size_t max_len = 4096);

    void handle_traced_syscall(pid_t pid, long syscall_nr);
    bool is_sensitive_path(const std::string& path) const;
};

} // namespace agentsentinel
