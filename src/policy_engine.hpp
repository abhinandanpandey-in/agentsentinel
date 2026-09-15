#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace agentsentinel {

enum class Verdict { Allow, Deny };

struct MatchResult {
    Verdict verdict;
    std::string rule_matched;   // human-readable rule id, e.g. "filesystem.deny"
};

// A single glob-style path rule, e.g. "~/.ssh/**" or "./workdir/**"
struct PathRule {
    std::string pattern;
    bool is_deny; // true = deny, false = allow
};

struct NetRule {
    std::string cidr;      // e.g. "127.0.0.1/32"
    std::vector<int> ports;
};

struct ExecRule {
    std::string binary_path; // allowed exec target
};

class PolicyEngine {
public:
    // Loads a policy from a JSON file. Throws std::runtime_error on parse failure.
    static PolicyEngine load_from_file(const std::string& path);

    // Filesystem check: resolves ~ and relative components before matching.
    MatchResult check_path(const std::string& raw_path) const;

    // Network check: dest IP (dotted quad) + port.
    MatchResult check_connect(const std::string& dest_ip, int dest_port) const;

    // Exec check: absolute path to the binary being exec'd.
    MatchResult check_exec(const std::string& binary_path) const;

    // Rate limiting: returns true if this syscall class has exceeded its
    // configured per-second budget for the given pid. Call once per event.
    bool rate_limit_exceeded(const std::string& syscall_class, pid_t pid);

    const std::string& name() const { return name_; }

private:
    std::string name_;
    std::vector<PathRule> path_rules_;      // evaluated in order, first match wins
    std::string net_default_ = "deny";
    std::vector<NetRule> net_allow_;
    std::vector<ExecRule> exec_allow_;
    // syscall_class -> max events/sec
    std::vector<std::pair<std::string, int>> rate_limits_;

    // pid -> (syscall_class -> (window_start_epoch_sec, count))
    struct RateWindow { long window_start = 0; int count = 0; };
    mutable std::vector<std::tuple<pid_t, std::string, RateWindow>> rate_state_;

    static bool glob_match(const std::string& pattern, const std::string& path);
    static bool cidr_match(const std::string& cidr, const std::string& ip);
    static bool cidr_match_v4(const std::string& cidr, const std::string& ip);
    static bool cidr_match_v6(const std::string& cidr, const std::string& ip);
    static std::string expand_home(const std::string& path);
};

} // namespace agentsentinel
