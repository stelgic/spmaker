#include <iostream>
#include <iomanip>
#include <g3log/g3log.hpp>
#include <g3log/logworker.hpp>

using namespace g3;

struct CustomSink {
    // Linux xterm color
    // http://stackoverflow.com/questions/2616906/how-do-i-output-coloured-text-to-a-linux-terminal
    enum FG_Color {RESET=30, YELLOW = 33, RED = 31, GREEN=32, WHITE = 97};

    FG_Color GetColor(const LEVELS level) const {
        if (level.value == ::WARNING.value) { return YELLOW; }
        if (level.value == ::DEBUG.value) { return GREEN; }
        if (::internal::wasFatal(level)) { return RED; }

        return RESET;
    }

    static std::string CustomLogDetailsToString(const LogMessage& msg) 
    {
        std::string out;
        out.append(msg.timestamp() + " "
                    + msg.level() 
                    + " [" 
                    + msg.file() 
                    + ":" + msg.line() + "]\t");
        return out;
    }

    void ReceiveLogMessage(::LogMessageMover logEntry) {
        auto level = logEntry.get()._level;
        auto color = GetColor(level);

        std::cout << std::setprecision(8) << "\033[" << color 
            << "m" << logEntry.get().toString(CustomLogDetailsToString) << "\033[m";
    }
};
