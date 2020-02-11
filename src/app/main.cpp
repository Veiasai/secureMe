#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cassert>
#include <memory>

#include <seccomp.h>
#include <cxxopts.hpp>
#include <yaml-cpp/yaml.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include "RuleManager.h"

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

int main(int argc, char **argv)
{
    const ArgInfo argInfo = parseArgs(argc, argv);

    std::unique_ptr<rule::RuleManager> rulemgr = std::make_unique<rule::RuleManager>(argInfo.configPath);

    // parse and apply rules
    // config

    // execve
    // target args 
}