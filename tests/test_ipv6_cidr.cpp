// test_ipv6_cidr.cpp — standalone unit test for PolicyEngine's IPv6 CIDR
// matching. This sandbox environment has IPv6 sockets disabled at the OS
// level (AF_INET6 socket() fails with EAFNOSUPPORT), so the live syscall
// interception path for IPv6 connect() couldn't be exercised end-to-end
// here. This test isolates and verifies the actual new logic (byte/bit
// boundary matching across a 128-bit address) independent of sockets.
#include "policy_engine.hpp"
#include <fstream>
#include <iostream>
#include <cstdio>

using namespace agentsentinel;

static int failures = 0;

static void expect(bool condition, const std::string& description) {
    if (!condition) {
        std::cerr << "FAIL: " << description << "\n";
        failures++;
    } else {
        std::cout << "PASS: " << description << "\n";
    }
}

int main() {
    const char* policy_path = "/tmp/ipv6_unit_test_policy.json";
    std::ofstream f(policy_path);
    f << R"({
        "name": "ipv6-unit-test",
        "network": {
            "default": "deny",
            "allow": [
                { "cidr": "2001:db8::/32", "ports": [443] },
                { "cidr": "::1/128", "ports": [8080] }
            ]
        }
    })";
    f.close();

    PolicyEngine pe = PolicyEngine::load_from_file(policy_path);

    // In-prefix address on an exact /32 boundary should match.
    expect(pe.check_connect("2001:db8::1", 443).verdict == Verdict::Allow,
           "address within 2001:db8::/32 on allowed port is allowed");

    // Same prefix, wrong port should be denied.
    expect(pe.check_connect("2001:db8::1", 22).verdict == Verdict::Deny,
           "address within allowed prefix but wrong port is denied");

    // Address just outside the /32 prefix should be denied — this is the
    // critical boundary case for the byte+bit masking logic.
    expect(pe.check_connect("2001:db9::1", 443).verdict == Verdict::Deny,
           "address one prefix-group outside 2001:db8::/32 is denied");

    // Exact /128 (single host) match.
    expect(pe.check_connect("::1", 8080).verdict == Verdict::Allow,
           "exact /128 loopback match is allowed");
    expect(pe.check_connect("::2", 8080).verdict == Verdict::Deny,
           "address differing by 1 bit from a /128 rule is denied");

    // A completely unrelated IPv6 address should hit default_deny.
    expect(pe.check_connect("2606:2800:220:1:248:1893:25c8:1946", 443).verdict == Verdict::Deny,
           "unrelated IPv6 destination hits default_deny");

    // IPv4 and IPv6 must never cross-match even if one could be
    // (mis)interpreted as bytes of the other.
    expect(pe.check_connect("93.184.216.34", 443).verdict == Verdict::Deny,
           "IPv4 destination does not match an IPv6-only allow rule");

    std::remove(policy_path);

    if (failures == 0) {
        std::cout << "\nAll IPv6 CIDR matching tests passed.\n";
        return 0;
    } else {
        std::cout << "\n" << failures << " test(s) failed.\n";
        return 1;
    }
}
