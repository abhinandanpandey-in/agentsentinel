// fuzz_harness.cpp — Phase 4 of the AgentSentinel roadmap.
//
// Drives a corpus of adversarial/benign documents through the vulnerable
// mock agent (agent_target.py) under AgentSentinel's enforcement, then
// grades whether each expected attack was actually caught by inspecting
// the resulting audit log. AgentSentinel's own audit trail is the
// detection oracle — no separate "did it work" heuristic is needed beyond
// "did a deny/signature_match event appear in the log."
//
// Naming convention for the corpus (see fuzz/corpus/):
//   benign_*.txt    -> expected to produce ZERO deny/signature_match events
//   injected_*.txt  -> expected to produce AT LEAST ONE deny/signature_match

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

struct GradeResult {
    std::string corpus_file;
    bool expected_attack;
    bool detected;      // any deny or signature_match in the audit log
    int denies = 0;
    int signature_matches = 0;
    bool pass() const { return expected_attack == detected; }
};

static bool run_agentsentinel(const std::string& agentsentinel_bin,
                               const std::string& policy_path,
                               const std::string& agent_script,
                               const std::string& corpus_file,
                               const std::string& log_path) {
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "fuzz_harness: fork failed\n";
        return false;
    }
    if (pid == 0) {
        // Redirect the target's stdout/stderr to /dev/null — we only care
        // about the audit log, not the agent's own chatter.
        if (!freopen("/dev/null", "w", stdout)) { /* best-effort; continue regardless */ }
        if (!freopen("/dev/null", "w", stderr)) { /* best-effort; continue regardless */ }
        execl(agentsentinel_bin.c_str(), agentsentinel_bin.c_str(),
              "run", "--policy", policy_path.c_str(), "--log", log_path.c_str(),
              "--", "/usr/bin/python3", agent_script.c_str(), corpus_file.c_str(),
              (char*)nullptr);
        _exit(127); // execl failed
    }
    int status;
    waitpid(pid, &status, 0);
    return true;
}

static GradeResult grade(const std::string& corpus_file, const std::string& log_path) {
    GradeResult r;
    r.corpus_file = fs::path(corpus_file).filename().string();
    r.expected_attack = r.corpus_file.rfind("injected_", 0) == 0;

    std::ifstream log(log_path);
    std::string line;
    while (std::getline(log, line)) {
        if (line.empty()) continue;
        try {
            json j = json::parse(line);
            if (j.value("verdict", "") == "deny") r.denies++;
            if (j.contains("signature_match")) r.signature_matches++;
        } catch (...) {
            // Malformed line — ignore rather than crash the whole run.
        }
    }
    r.detected = (r.denies > 0) || (r.signature_matches > 0);
    return r;
}

int main(int argc, char** argv) {
    std::string agentsentinel_bin = "../agentsentinel";
    std::string policy_path = "../../policies/web-tool-default.json";
    std::string corpus_dir = "../../fuzz/corpus";
    std::string agent_script = "../../fuzz/agent_target.py";

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--bin" && i + 1 < argc) agentsentinel_bin = argv[++i];
        else if (arg == "--policy" && i + 1 < argc) policy_path = argv[++i];
        else if (arg == "--corpus" && i + 1 < argc) corpus_dir = argv[++i];
        else if (arg == "--agent" && i + 1 < argc) agent_script = argv[++i];
        else {
            std::cerr << "usage: fuzz_harness [--bin path] [--policy path] "
                         "[--corpus dir] [--agent path]\n";
            return 1;
        }
    }

    if (!fs::exists(corpus_dir)) {
        std::cerr << "fuzz_harness: corpus directory not found: " << corpus_dir << "\n";
        return 1;
    }

    std::vector<std::string> corpus_files;
    for (auto& entry : fs::directory_iterator(corpus_dir)) {
        if (entry.path().extension() == ".txt") corpus_files.push_back(entry.path().string());
    }
    std::sort(corpus_files.begin(), corpus_files.end());

    if (corpus_files.empty()) {
        std::cerr << "fuzz_harness: no .txt files found in " << corpus_dir << "\n";
        return 1;
    }

    std::vector<GradeResult> results;
    int case_num = 0;
    for (auto& file : corpus_files) {
        std::string log_path = "fuzz_case_" + std::to_string(case_num++) + ".jsonl";
        fs::remove(log_path); // start clean in case of a rerun
        run_agentsentinel(agentsentinel_bin, policy_path, agent_script, file, log_path);
        results.push_back(grade(file, log_path));
    }

    std::cout << "\n=== AgentSentinel Fuzzing Harness — Results ===\n\n";
    std::cout.setf(std::ios::left);
    std::cout << std::setw(34) << "Corpus file"
              << std::setw(12) << "Expected"
              << std::setw(12) << "Detected"
              << std::setw(10) << "Denies"
              << std::setw(10) << "Sig.match"
              << "Result\n";
    std::cout << std::string(90, '-') << "\n";

    int passed = 0;
    for (auto& r : results) {
        std::cout << std::setw(34) << r.corpus_file
                  << std::setw(12) << (r.expected_attack ? "attack" : "benign")
                  << std::setw(12) << (r.detected ? "yes" : "no")
                  << std::setw(10) << r.denies
                  << std::setw(10) << r.signature_matches
                  << (r.pass() ? "PASS" : "FAIL") << "\n";
        if (r.pass()) passed++;
    }

    std::cout << "\n" << passed << "/" << results.size() << " cases passed.\n";

    bool all_passed = (passed == static_cast<int>(results.size()));
    if (!all_passed) {
        std::cout << "\nDetection gaps found — see FAIL rows above:\n"
                  << "  - An 'attack' row with 0 denies/sig.matches means AgentSentinel\n"
                  << "    missed a real attack (false negative).\n"
                  << "  - A 'benign' row with any denies/sig.matches means AgentSentinel\n"
                  << "    is over-blocking legitimate behavior (false positive).\n";
    }

    return all_passed ? 0 : 1;
}
