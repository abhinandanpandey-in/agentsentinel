#include "signature_matcher.hpp"
#include <algorithm>

namespace agentsentinel {

void SignatureMatcher::record_sensitive_open(pid_t pid, const std::string& path) {
    recent_opens_.push_back({pid, path, std::chrono::steady_clock::now()});
    // Prune anything older than the correlation window to keep this bounded.
    auto now = std::chrono::steady_clock::now();
    recent_opens_.erase(
        std::remove_if(recent_opens_.begin(), recent_opens_.end(),
            [&](const SensitiveOpen& e) {
                auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - e.at).count();
                return age_ms > kCorrelationWindowMs;
            }),
        recent_opens_.end());
}

std::optional<SignatureMatcher::ExfilMatch> SignatureMatcher::check_connect_correlation(pid_t pid) {
    auto now = std::chrono::steady_clock::now();
    for (auto it = recent_opens_.rbegin(); it != recent_opens_.rend(); ++it) {
        if (it->pid == pid) {
            auto delta_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->at).count();
            if (delta_ms <= kCorrelationWindowMs) {
                return ExfilMatch{it->path, delta_ms};
            }
        }
    }
    return std::nullopt;
}

bool SignatureMatcher::is_shell_binary(const std::string& binary_path) const {
    static const std::vector<std::string> shells = {
        "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/usr/bin/sh", "/usr/bin/bash"
    };
    return std::find(shells.begin(), shells.end(), binary_path) != shells.end();
}

} // namespace agentsentinel
