#include <iostream>
#include <fcntl.h>

#include <cxxopts.hpp>
#include <yaml-cpp/yaml.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include "Daemon.h"

using namespace SAIL;

struct ArgInfo {
    std::string targetPath;
    std::vector<std::string> targetArgs;
    std::string configPath;
    std::string targetlogPath;
};

ArgInfo parseArgs(int argc, char **argv) {
    cxxopts::Options options("secureme", "A wrapper for libseccomp");
    options.add_options()
        ("t, target", "the target binary to be executed, required", cxxopts::value<std::string>())
        ("args", "arguments of target binary, optional", cxxopts::value<std::vector<std::string>>())
        ("d, targetlog", "redirected output of target binary, optional, if omitted, print to stdout", cxxopts::value<std::string>())
        ("c, config", "configuration file containing rules, required", cxxopts::value<std::string>())
        ("o, logfile", "log file, optional, if omitted, print to stdout", cxxopts::value<std::string>())
        ("v, verbose", "whether to print info log, optional", cxxopts::value<bool>());

    ArgInfo argInfo;
    try
    {
        auto result = options.parse(argc, argv);

        // -t, required
        argInfo.targetPath = result["t"].as<std::string>();

        // --args, optional
        try {
            argInfo.targetArgs = result["args"].as<std::vector<std::string>>();
        }
        catch (std::exception &e) {}

        // -d, optional
        try {
            argInfo.targetlogPath = result["d"].as<std::string>();
        }
        catch (std::exception &e) {}

        // -c, required
        argInfo.configPath = result["c"].as<std::string>();

        // -o, optional
        try {
            std::string logfile = result["o"].as<std::string>();
            spdlog::set_default_logger(spdlog::basic_logger_mt("SecureMe", logfile));
        }
        catch (std::exception &e) {}

        // -v, optional
        try {
            bool verbose = result["v"].as<bool>();
            auto level = verbose ? spdlog::level::info : spdlog::level::critical;
            spdlog::set_level(level);
            spdlog::default_logger()->flush_on(level);
        }
        catch (std::exception &e) {
            assert(0);
        }
    }
    catch (std::exception &e) {
        std::cout << options.help() << std::endl;
        std::cout << e.what() << std::endl;
        exit(-1);
    }

    return argInfo;
}

void runTarget(const ArgInfo &argInfo, const std::shared_ptr<rule::RuleManager> &rulemgr) {
    // redirect
    if (!argInfo.targetlogPath.empty()) {
        int targetlogFd = open(argInfo.targetlogPath.c_str(), O_RDWR | O_CREAT | O_APPEND, 0666);
        assert(targetlogFd > 0);
        dup2(targetlogFd, 1);
        dup2(targetlogFd, 2);
    }

    // build args
    std::vector<char *> args;
    args.push_back(const_cast<char *>(argInfo.targetPath.c_str()));
    for (const std::string &arg : argInfo.targetArgs) {
        args.push_back(const_cast<char *>(arg.c_str()));
    }
    args.push_back(nullptr);

    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    char **command = &args[0];

    rulemgr->applyRules();

    // execv after TRACEME will trigger a SIGTRAP delivered automatically
    execv(argInfo.targetPath.c_str(), command);
    assert(0);
}

int main(int argc, char **argv)
{
    const ArgInfo argInfo = parseArgs(argc, argv);

    std::shared_ptr<util::Utils> up = std::make_shared<util::Utils>();
    // init rule manager
    const YAML::Node config = YAML::LoadFile(argInfo.configPath);
    std::shared_ptr<rule::RuleManager> rulemgr = std::make_unique<rule::RuleManager>(config, up);

    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        runTarget(argInfo, rulemgr);
    }
    std::unique_ptr<core::Daemon> daemon = std::make_unique<core::Daemon>(child, rulemgr, up);
    daemon->setOptions();
    daemon->run();

    return 0;
}