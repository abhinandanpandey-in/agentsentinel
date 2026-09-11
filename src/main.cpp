#include <iostream>
#include <vector>
#include <string>
#include "policy_engine.hpp"
#include "interceptor.hpp"

using namespace agentsentinel;

static void print_usage(const char* prog) {
    std::cerr << "AgentSentinel — syscall-level firewall for agentic AI code execution\n\n"
              << "Usage:\n"
              << "  " << prog << " run --policy <policy.json> [--log <audit.jsonl>] -- <cmd> [args...]\n\n"
              << "Example:\n"
              << "  " << prog << " run --policy policies/web-tool-default.json -- python3 samples/benign_data_analysis.py\n";
}

int main(int argc, char** argv) {
    if (argc < 2 || std::string(argv[1]) != "run") {
        print_usage(argv[0]);
        return 1;
    }

    std::string policy_path, log_path = "audit.jsonl";
    int i = 2;
    for (; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--policy" && i + 1 < argc) {
            policy_path = argv[++i];
        } else if (arg == "--log" && i + 1 < argc) {
            log_path = argv[++i];
        } else if (arg == "--") {
            i++;
            break;
        } else {
            std::cerr << "agentsentinel: unrecognized argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (policy_path.empty() || i >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    std::vector<std::string> target_argv(argv + i, argv + argc);

    try {
        PolicyEngine policy = PolicyEngine::load_from_file(policy_path);
        std::vector<std::string> sensitive_globs = {
            "~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "/etc/shadow", "/etc/passwd"
        };
        Interceptor interceptor(std::move(policy), log_path, sensitive_globs);

        std::cerr << "agentsentinel: launching '" << target_argv[0]
                  << "' under policy '" << policy_path << "' (audit log: " << log_path << ")\n";
        return interceptor.run(target_argv);
    } catch (const std::exception& e) {
        std::cerr << "agentsentinel: fatal: " << e.what() << "\n";
        return 1;
    }
}
