#include "audit_logger.hpp"
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace agentsentinel {

AuditLogger::AuditLogger(const std::string& out_path) {
    out_.open(out_path, std::ios::app);
    if (!out_) throw std::runtime_error("cannot open audit log: " + out_path);
}

std::string AuditLogger::iso8601_now() {
    std::time_t t = std::time(nullptr);
    std::tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

void AuditLogger::log(const AuditEvent& ev) {
    std::lock_guard<std::mutex> lock(mtx_);
    out_ << "{"
         << "\"timestamp\":\"" << iso8601_now() << "\","
         << "\"pid\":" << ev.pid << ","
         << "\"syscall\":\"" << ev.syscall << "\","
         << "\"args\":" << ev.args_json << ","
         << "\"policy_rule\":\"" << ev.policy_rule << "\",";
    if (ev.signature_match)
        out_ << "\"signature_match\":\"" << *ev.signature_match << "\",";
    out_ << "\"verdict\":\"" << ev.verdict << "\"";
    if (ev.preceding) {
        out_ << ",\"preceding_event\":{"
             << "\"syscall\":\"" << ev.preceding->syscall << "\","
             << "\"detail\":\"" << ev.preceding->detail << "\","
             << "\"delta_ms\":" << ev.preceding->delta_ms
             << "}";
    }
    out_ << "}\n";
    out_.flush();
}

} // namespace agentsentinel
