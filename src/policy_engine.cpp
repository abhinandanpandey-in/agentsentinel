#include "policy_engine.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <arpa/inet.h>
#include <cstdlib>
#include <ctime>
#include <algorithm>

namespace agentsentinel {

using json = nlohmann::json;

std::string PolicyEngine::expand_home(const std::string& path) {
    if (!path.empty() && path[0] == '~') {
        const char* home = std::getenv("HOME");
        if (home) return std::string(home) + path.substr(1);
    }
    return path;
}

// Minimal glob supporting '**' (any depth) and '*' (single segment) as the
// last path components. Good enough for policy files like "~/.ssh/**".
bool PolicyEngine::glob_match(const std::string& pattern_in, const std::string& path_in) {
    std::string pattern = expand_home(pattern_in);
    std::string path = path_in;

    // Handle trailing "/**" -> prefix match
    auto pos = pattern.find("/**");
    if (pos != std::string::npos && pos == pattern.size() - 3) {
        std::string prefix = pattern.substr(0, pos);
        return path.compare(0, prefix.size(), prefix) == 0;
    }
    // Handle trailing "/*" -> single-segment match under prefix
    pos = pattern.find("/*");
    if (pos != std::string::npos && pos == pattern.size() - 2) {
        std::string prefix = pattern.substr(0, pos);
        if (path.compare(0, prefix.size(), prefix) != 0) return false;
        std::string rest = path.substr(prefix.size());
        if (rest.empty() || rest[0] != '/') return false;
        return rest.find('/', 1) == std::string::npos;
    }
    // Exact match fallback
    return pattern == path;
}

bool PolicyEngine::cidr_match(const std::string& cidr, const std::string& ip) {
    auto slash = cidr.find('/');
    std::string net_str = cidr.substr(0, slash);
    int prefix_len = slash == std::string::npos ? 32 : std::stoi(cidr.substr(slash + 1));

    in_addr net_addr{}, ip_addr{};
    if (inet_pton(AF_INET, net_str.c_str(), &net_addr) != 1) return false;
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) return false;

    uint32_t mask = prefix_len == 0 ? 0 : htonl(~((1u << (32 - prefix_len)) - 1));
    return (net_addr.s_addr & mask) == (ip_addr.s_addr & mask);
}

PolicyEngine PolicyEngine::load_from_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open policy file: " + path);

    json j;
    f >> j;

    PolicyEngine pe;
    pe.name_ = j.value("name", "unnamed-policy");

    if (j.contains("filesystem")) {
        auto& fs = j["filesystem"];
        for (auto& p : fs.value("deny", json::array()))
            pe.path_rules_.push_back({p.get<std::string>(), true});
        for (auto& p : fs.value("allow", json::array()))
            pe.path_rules_.push_back({p.get<std::string>(), false});
    }

    if (j.contains("network")) {
        auto& net = j["network"];
        pe.net_default_ = net.value("default", "deny");
        for (auto& rule : net.value("allow", json::array())) {
            NetRule nr;
            nr.cidr = rule.value("cidr", "0.0.0.0/0");
            for (auto& port : rule.value("ports", json::array()))
                nr.ports.push_back(port.get<int>());
            pe.net_allow_.push_back(nr);
        }
    }

    if (j.contains("exec")) {
        for (auto& b : j["exec"].value("allow", json::array()))
            pe.exec_allow_.push_back({b.get<std::string>()});
    }

    if (j.contains("rate_limits")) {
        for (auto& [key, val] : j["rate_limits"].items())
            pe.rate_limits_.push_back({key, val.get<int>()});
    }

    return pe;
}

MatchResult PolicyEngine::check_path(const std::string& raw_path) const {
    // Deny rules take priority over allow rules regardless of order, since
    // an explicit deny (e.g. ~/.ssh) should never be shadowed by a broad
    // allow (e.g. ~/**).
    for (auto& rule : path_rules_) {
        if (rule.is_deny && glob_match(rule.pattern, raw_path))
            return {Verdict::Deny, "filesystem.deny:" + rule.pattern};
    }
    bool has_allow_rules = false;
    for (auto& rule : path_rules_) {
        if (!rule.is_deny) {
            has_allow_rules = true;
            if (glob_match(rule.pattern, raw_path))
                return {Verdict::Allow, "filesystem.allow:" + rule.pattern};
        }
    }
    // If allow rules exist and none matched, default deny. If no allow
    // rules were configured at all, default allow (deny-list-only mode).
    if (has_allow_rules)
        return {Verdict::Deny, "filesystem.default_deny"};
    return {Verdict::Allow, "filesystem.default_allow"};
}

MatchResult PolicyEngine::check_connect(const std::string& dest_ip, int dest_port) const {
    for (auto& rule : net_allow_) {
        if (cidr_match(rule.cidr, dest_ip)) {
            if (rule.ports.empty() ||
                std::find(rule.ports.begin(), rule.ports.end(), dest_port) != rule.ports.end()) {
                return {Verdict::Allow, "network.allow:" + rule.cidr};
            }
        }
    }
    if (net_default_ == "allow")
        return {Verdict::Allow, "network.default_allow"};
    return {Verdict::Deny, "network.default_deny"};
}

MatchResult PolicyEngine::check_exec(const std::string& binary_path) const {
    if (exec_allow_.empty())
        return {Verdict::Allow, "exec.default_allow"};
    for (auto& rule : exec_allow_) {
        if (rule.binary_path == binary_path)
            return {Verdict::Allow, "exec.allow:" + rule.binary_path};
    }
    return {Verdict::Deny, "exec.default_deny"};
}

bool PolicyEngine::rate_limit_exceeded(const std::string& syscall_class, pid_t pid) {
    int limit = -1;
    for (auto& [cls, lim] : rate_limits_) {
        if (cls == syscall_class + "_per_sec") { limit = lim; break; }
    }
    if (limit < 0) return false; // no limit configured for this class

    long now = static_cast<long>(time(nullptr));
    for (auto& [p, cls, window] : rate_state_) {
        if (p == pid && cls == syscall_class) {
            if (now != window.window_start) {
                window.window_start = now;
                window.count = 1;
                return false;
            }
            window.count++;
            return window.count > limit;
        }
    }
    rate_state_.push_back({pid, syscall_class, RateWindow{now, 1}});
    return false;
}

} // namespace agentsentinel
