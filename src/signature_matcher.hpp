#pragma once
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <sys/types.h>

namespace agentsentinel {

// Tracks a short rolling window of recent sensitive events per traced process
// and flags known agentic-attack sequences. Deterministic state machine —
// no ML, fully auditable.
class SignatureMatcher {
public:
    struct SensitiveOpen {
        pid_t pid;
        std::string path;
        std::chrono::steady_clock::time_point at;
    };

    // Call when a path matching a "sensitive" pattern (e.g. ~/.ssh/**,
    // ~/.aws/**) is opened, whether or not the policy engine allowed it.
    void record_sensitive_open(pid_t pid, const std::string& path);

    // Call on every connect() attempt. Returns "exfiltration_pattern" if a
    // sensitive file was opened by the same pid within the correlation
    // window, along with the preceding path + delta in ms. Returns
    // std::nullopt if no match.
    struct ExfilMatch { std::string preceding_path; long delta_ms; };
    std::optional<ExfilMatch> check_connect_correlation(pid_t pid);

    // Call on every execve(). Returns "scope_escape_pattern" if the target
    // binary is a shell/interpreter not in the process's original exec
    // lineage (simplified here to: any exec of a shell after startup).
    bool is_shell_binary(const std::string& binary_path) const;

private:
    static constexpr int kCorrelationWindowMs = 2000;
    std::vector<SensitiveOpen> recent_opens_;
};

} // namespace agentsentinel
