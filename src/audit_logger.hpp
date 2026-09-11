#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <optional>

namespace agentsentinel {

struct PrecedingEvent {
    std::string syscall;
    std::string detail; // e.g. path or "ip:port"
    long delta_ms;
};

struct AuditEvent {
    pid_t pid;
    std::string syscall;
    std::string args_json;      // pre-formatted JSON fragment for the args object
    std::string policy_rule;
    std::optional<std::string> signature_match;
    std::string verdict;        // "allow" | "deny" | "flag"
    std::optional<PrecedingEvent> preceding;
};

class AuditLogger {
public:
    explicit AuditLogger(const std::string& out_path);
    void log(const AuditEvent& ev);

private:
    std::ofstream out_;
    std::mutex mtx_;
    static std::string iso8601_now();
};

} // namespace agentsentinel
