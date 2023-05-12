#include <filesystem>
#include "G3LogCustomSink.h"

namespace fs = std::filesystem;

// global g3log pointer
std::unique_ptr<g3::LogWorker> logworker = nullptr;
std::unique_ptr<g3::SinkHandle<CustomSink>> sinkHandle = nullptr;
std::unique_ptr<FileSinkHandle> defaultHandler = nullptr;

// G3LOG initialization with custom sink
void InitializeLogger()
{
    if(logworker == nullptr)
    {
        logworker = {LogWorker::createLogWorker()};
    #if defined(linux) || defined(__linux__)
        defaultHandler = {logworker->addDefaultLogger("stelgic", "/tmp", "connectors")};
    #elif defined(_WIN32) || defined(_WIN64)
        char* user = getenv("username");
        fs::path WinTemp("C:/Users");
        WinTemp.append(user).append("AppData")
            .append("Local").append("Temp");

        std::cout << "TEmp DIR " << WinTemp.string() << "\n";
        defaultHandler = {logworker->addDefaultLogger("stelgic", WinTemp.string(), "connectors")};
    #endif
        // initialize the logger before it can receive G3LOG calls
        initializeLogging(logworker.get());

        // Customized log message
        defaultHandler->call(&g3::FileSink::overrideLogDetails, &CustomSink::CustomLogDetailsToString);

        sinkHandle = {logworker->addSink(std::make_unique<CustomSink>(),
                                                &CustomSink::ReceiveLogMessage)};
    }
}
