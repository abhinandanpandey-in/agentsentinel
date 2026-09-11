cmake_minimum_required(VERSION 3.16)
project(agentsentinel CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SECCOMP REQUIRED libseccomp)
find_package(nlohmann_json 3.2.0 REQUIRED)

add_executable(agentsentinel
    src/main.cpp
    src/interceptor.cpp
    src/policy_engine.cpp
    src/signature_matcher.cpp
    src/audit_logger.cpp
)

target_include_directories(agentsentinel PRIVATE ${SECCOMP_INCLUDE_DIRS})
target_link_libraries(agentsentinel PRIVATE ${SECCOMP_LIBRARIES} nlohmann_json::nlohmann_json)
target_compile_options(agentsentinel PRIVATE ${SECCOMP_CFLAGS_OTHER})

# This project depends on Linux-specific interfaces (ptrace, seccomp-bpf,
# process_vm_readv) and is not intended to be portable.
if(NOT UNIX OR APPLE)
    message(FATAL_ERROR "AgentSentinel currently supports Linux only.")
endif()
