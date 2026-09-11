#include "interceptor.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <seccomp.h>

namespace agentsentinel {

Interceptor::Interceptor(PolicyEngine policy, const std::string& audit_log_path,
                          const std::vector<std::string>& sensitive_path_globs)
    : policy_(std::move(policy)), audit_(audit_log_path), sensitive_globs_(sensitive_path_globs) {}

// This installs the syscall filter as SCMP_ACT_ALLOW by default and routes
// only the syscalls we actually need to inspect to PTRACE_EVENT_SECCOMP.
// This keeps overhead low: syscalls we don't care about (read/write/mmap/
// etc.) never leave the fast path.
void Interceptor::install_seccomp_filter() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        std::cerr << "agentsentinel: seccomp_init failed\n";
        _exit(1);
    }

    const int traced_syscalls[] = {
        SCMP_SYS(openat), SCMP_SYS(open), SCMP_SYS(connect),
        SCMP_SYS(execve), SCMP_SYS(execveat), SCMP_SYS(clone), SCMP_SYS(fork),
        SCMP_SYS(vfork), SCMP_SYS(socket)
    };
    for (int sys : traced_syscalls) {
        // SCMP_ACT_TRACE(0): trap into ptrace supervisor via
        // PTRACE_EVENT_SECCOMP with data=0; we don't use the seccomp data
        // value, we re-read args from registers in the tracer instead.
        if (seccomp_rule_add(ctx, SCMP_ACT_TRACE(0), sys, 0) < 0) {
            std::cerr << "agentsentinel: failed to add seccomp rule for syscall " << sys << "\n";
        }
    }

    if (seccomp_load(ctx) < 0) {
        std::cerr << "agentsentinel: seccomp_load failed\n";
        _exit(1);
    }
    seccomp_release(ctx);
}

std::string Interceptor::read_child_string(pid_t pid, unsigned long long addr, size_t max_len) {
    if (addr == 0) return "";
    std::string result;
    char buf[512];
    struct iovec local{buf, sizeof(buf)};
    unsigned long long remote_addr = addr;

    while (result.size() < max_len) {
        struct iovec remote{reinterpret_cast<void*>(remote_addr), sizeof(buf)};
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n <= 0) {
            // Fall back to PTRACE_PEEKDATA word-by-word if process_vm_readv
            // is unavailable (e.g. restricted by yama ptrace_scope).
            for (int i = 0; i < 64; i++) {
                errno = 0;
                long word = ptrace(PTRACE_PEEKDATA, pid, remote_addr + i * sizeof(long), nullptr);
                if (word == -1 && errno != 0) return result;
                char* bytes = reinterpret_cast<char*>(&word);
                for (size_t b = 0; b < sizeof(long); b++) {
                    if (bytes[b] == '\0') return result;
                    result += bytes[b];
                }
            }
            return result;
        }
        bool found_null = false;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\0') { found_null = true; break; }
            result += buf[i];
        }
        if (found_null || static_cast<size_t>(n) < sizeof(buf)) break;
        remote_addr += n;
    }
    return result;
}

bool Interceptor::is_sensitive_path(const std::string& path) const {
    for (auto& glob : sensitive_globs_) {
        // Reuse the same simple prefix-matching semantics as PolicyEngine
        // for "**"-suffixed globs.
        auto pos = glob.find("/**");
        std::string prefix = pos != std::string::npos ? glob.substr(0, pos) : glob;
        if (!prefix.empty() && prefix[0] == '~') {
            const char* home = getenv("HOME");
            if (home) prefix = std::string(home) + prefix.substr(1);
        }
        if (path.compare(0, prefix.size(), prefix) == 0) return true;
    }
    return false;
}

void Interceptor::handle_traced_syscall(pid_t pid, long syscall_nr) {
    struct user_regs_struct regs{};
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) < 0) return;

    if (syscall_nr == SYS_openat || syscall_nr == SYS_open) {
        unsigned long long path_addr = (syscall_nr == SYS_openat) ? regs.rsi : regs.rdi;
        std::string path = read_child_string(pid, path_addr);

        auto result = policy_.check_path(path);
        std::string args_json = "{\"path\":\"" + path + "\"}";

        if (is_sensitive_path(path)) sig_matcher_.record_sensitive_open(pid, path);

        AuditEvent ev{pid, "openat", args_json, result.rule_matched, std::nullopt,
                      result.verdict == Verdict::Deny ? "deny" : "allow", std::nullopt};
        if (result.verdict == Verdict::Deny) {
            audit_.log(ev);
            // Force the syscall to fail rather than execute: redirect to an
            // invalid syscall number so the kernel returns -ENOSYS, then
            // restore before the tracee notices (simplified: we just block
            // by setting orig_rax to -1, a common ptrace-based deny pattern).
            regs.orig_rax = static_cast<unsigned long long>(-1);
            ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
        } else if (result.rule_matched.find("default_allow") == std::string::npos) {
            // Only log allowed events when an explicit rule matched, to
            // keep the audit log focused on decisions rather than noise.
            audit_.log(ev);
        }
    } else if (syscall_nr == SYS_connect) {
        // regs.rsi points to a struct sockaddr; read the first bytes to get
        // family/IP/port for AF_INET. (AF_INET6 handling omitted for MVP.)
        struct sockaddr_in sa{};
        struct iovec local{&sa, sizeof(sa)};
        struct iovec remote{reinterpret_cast<void*>(regs.rsi), sizeof(sa)};
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n > 0 && sa.sin_family == AF_INET) {
            char ip_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sa.sin_addr, ip_buf, sizeof(ip_buf));
            int port = ntohs(sa.sin_port);
            std::string ip(ip_buf);

            auto result = policy_.check_connect(ip, port);
            std::string args_json = "{\"dest_ip\":\"" + ip + "\",\"dest_port\":" + std::to_string(port) + "}";

            std::optional<std::string> sig;
            std::optional<PrecedingEvent> preceding;
            auto exfil = sig_matcher_.check_connect_correlation(pid);
            if (exfil) {
                sig = "exfiltration_pattern";
                preceding = PrecedingEvent{"openat", exfil->preceding_path, exfil->delta_ms};
            }

            std::string verdict = result.verdict == Verdict::Deny || sig ? "deny" : "allow";
            AuditEvent ev{pid, "connect", args_json, result.rule_matched, sig, verdict, preceding};
            audit_.log(ev);

            if (verdict == "deny") {
                regs.orig_rax = static_cast<unsigned long long>(-1);
                ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
            }
        }
    } else if (syscall_nr == SYS_execve) {
        std::string binary = read_child_string(pid, regs.rdi);
        auto result = policy_.check_exec(binary);
        std::optional<std::string> sig;
        if (sig_matcher_.is_shell_binary(binary)) sig = "scope_escape_pattern";

        std::string verdict = (result.verdict == Verdict::Deny) ? "deny" : "flag";
        if (!sig && result.verdict != Verdict::Deny) verdict = "allow";

        AuditEvent ev{pid, "execve", "{\"binary\":\"" + binary + "\"}", result.rule_matched, sig, verdict, std::nullopt};
        audit_.log(ev);

        if (result.verdict == Verdict::Deny) {
            regs.orig_rax = static_cast<unsigned long long>(-1);
            ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
        }
    }
    // clone/fork/vfork/socket: currently audit-only pass-through (Phase 3
    // extension point for rate limiting via policy_.rate_limit_exceeded).
}

int Interceptor::run(const std::vector<std::string>& argv) {
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "agentsentinel: fork failed\n";
        return 1;
    }

    if (pid == 0) {
        // Child: become traceable, install the seccomp filter, then exec.
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        install_seccomp_filter();
        raise(SIGSTOP); // sync point: wait for parent to set trace options

        std::vector<char*> c_argv;
        for (auto& a : argv) c_argv.push_back(const_cast<char*>(a.c_str()));
        c_argv.push_back(nullptr);
        execv(c_argv[0], c_argv.data());
        std::cerr << "agentsentinel: execv failed: " << strerror(errno) << "\n";
        _exit(127);
    }

    // Parent: supervisor loop.
    int status;
    waitpid(pid, &status, 0); // wait for the initial SIGSTOP
    ptrace(PTRACE_SETOPTIONS, pid, nullptr,
           (void*)(PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL |
                   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE));
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    while (true) {
        pid_t w = waitpid(-1, &status, 0);
        if (w < 0) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (w == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            continue; // a traced grandchild exited; keep supervising
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            int event = status >> 16;

            if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
                struct user_regs_struct regs{};
                ptrace(PTRACE_GETREGS, w, nullptr, &regs);
                handle_traced_syscall(w, regs.orig_rax);
                ptrace(PTRACE_CONT, w, nullptr, nullptr);
            } else if (sig == SIGTRAP && (event == PTRACE_EVENT_FORK ||
                                          event == PTRACE_EVENT_VFORK ||
                                          event == PTRACE_EVENT_CLONE)) {
                // A new child/thread was created. It is auto-attached and
                // currently group-stopped; propagate our trace options to
                // it (options are NOT inherited automatically) so its own
                // seccomp-trapped syscalls reach this same supervisor loop.
                unsigned long new_pid = 0;
                ptrace(PTRACE_GETEVENTMSG, w, nullptr, &new_pid);
                ptrace(PTRACE_SETOPTIONS, static_cast<pid_t>(new_pid), nullptr,
                       (void*)(PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL |
                               PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE));
                ptrace(PTRACE_CONT, static_cast<pid_t>(new_pid), nullptr, nullptr);
                ptrace(PTRACE_CONT, w, nullptr, nullptr);
            } else {
                // Forward any other signal (or none) and continue.
                ptrace(PTRACE_CONT, w, nullptr, (sig == SIGTRAP || sig == SIGSTOP) ? nullptr : (void*)(long)sig);
            }
        }
    }
    return 1;
}

} // namespace agentsentinel
