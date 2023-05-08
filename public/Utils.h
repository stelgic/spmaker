#include <cassert>
#include "third_party/stduuid/include/uuid.h"

#pragma once

#if defined(_WIN32) || defined(_WIN64)
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <stdio.h>
#include <bcrypt.h>
#include <sal.h>
#endif

#include <string>
#include <sstream>
#include <memory>
#include <ctime>
#include <cmath>
#include <unordered_map>
#include <set>
#include <tuple>
#include <vector>
#include <chrono>
#include <date.h>
#include <random>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <iterator>

namespace stelgic
{
class Utils
{
public:
    static inline std::string FormatTimestamp(const int64_t& timestamp)
    {
        std::ostringstream ssdate;
        std::chrono::system_clock::time_point tp(std::chrono::milliseconds{timestamp});
        ssdate << date::format("%Y%m%d %H:%M:%S", date::floor<std::chrono::seconds>(tp));
        return ssdate.str();
    }

    static inline int64_t FromFmtMilliseconds(const std::string& ts, const std::string& fmt)
    {
        std::istringstream iss{ts};
        iss.exceptions(std::ios::failbit);
        std::chrono::system_clock::time_point tp;
        iss >> date::parse(fmt, tp);
        return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
    }

    static inline int64_t FromFmtSeconds(const std::string& ts, const std::string& fmt)
    {
        std::istringstream iss{ts};
        iss.exceptions(std::ios::failbit);
        std::chrono::system_clock::time_point tp;
        iss >> date::parse(fmt, tp);
        return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
    }

    static inline int64_t FromFmtNanoseconds(const std::string& ts, const std::string& fmt)
    {
        std::istringstream iss{ts};
        iss.exceptions(std::ios::failbit);
        std::chrono::system_clock::time_point tp;
        iss >> date::parse(fmt, tp);
        return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
    }

    static inline std::string FormatTime(const int64_t& timestamp, std::string fmt="%H%M%S")
    {
        std::ostringstream ssdate;
        std::chrono::system_clock::time_point tp(std::chrono::milliseconds{timestamp});
        ssdate << date::format(fmt, date::floor<std::chrono::seconds>(tp));
        return ssdate.str();
    }

    static inline std::string FormatDate(const int64_t& timestamp, std::string fmt="%Y%m%d")
    {
        std::ostringstream ssdate;
        std::chrono::system_clock::time_point tp(std::chrono::milliseconds{timestamp});
        ssdate << date::format(fmt, date::floor<std::chrono::seconds>(tp));
        return ssdate.str();
    }

    static inline std::string FormatDatetime(const int64_t& timestamp)
    {
        std::ostringstream ssdate;
        std::chrono::system_clock::time_point tp(std::chrono::milliseconds{timestamp});
        ssdate << date::format("%Y%m%d %H%M%S", date::floor<std::chrono::seconds>(tp));
        return ssdate.str();
    }

    static inline bool ParseTimestamp(const std::string& timestamp, std::tm& otm, int& mils)
    {
        int y,M,d,h,m;
        float value;
        int sec = 0;
        mils = 0;
        otm.tm_hour = -1;
        otm.tm_isdst = 0;

        if (sscanf(timestamp.c_str(), "%d-%d-%dT%d:%d:%fZ", &y, &M, &d, &h, &m, &value) != 0)
        {
            std::string token;
            std::stringstream ss, secss, milss;
            ss << value;

            std::getline(ss, token, '.');
            secss << token;
            secss >> sec;

            std::getline(ss, token, '.');
            milss << token;
            milss >> mils;

            otm.tm_year = y - 1900;
            otm.tm_mon = M - 1;
            otm.tm_mday = d;
            otm.tm_hour = h;
            otm.tm_min = m;
            otm.tm_sec = sec;
            otm.tm_isdst = 0;

            if (otm.tm_hour >= 0)
                return true;
        }
        return false;
    }

    static inline int64_t GetSeconds(int64_t offset=0)
    {
        double epoch = std::chrono::duration_cast<std::chrono::duration<double>>(
        std::chrono::system_clock::now().time_since_epoch()).count();

        return(std::round(epoch + offset));
    }

    static inline int64_t GetMilliseconds(int64_t offset=0)
    {
        auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

        return(epoch + offset);
    }

    static inline std::string GetRandomUUID()
    {
        std::random_device rd;
        auto seed_data = std::array<int, std::mt19937::state_size> {};
        std::generate(std::begin(seed_data), std::end(seed_data), std::ref(rd));
        std::seed_seq seq(std::begin(seed_data), std::end(seed_data));
        std::mt19937 generator(seq);
        uuids::uuid_random_generator gen{ generator };
        
        uuids::uuid const id = gen();
        assert(!id.is_nil());
        assert(id.as_bytes().size() == 16);

        return uuids::to_string(id);
    }

    static inline std::string GetUUIDFromString(const std::string& str)
    {
        uuids::uuid id = uuids::uuid::from_string(str).value();
        return uuids::to_string(id);
    }

    static inline std::string GetUrandom(int count)
    {
        std::string urandom;

    #if defined(_WIN32) || defined(_WIN64)
        do
        {
            errno_t err;
            NTSTATUS Status;
            HCRYPTPROV hCryptProv = 0;
            const size_t size = 128;
            char memblock[size];

            memset(memblock, 0, size);
            Status = BCryptGenRandom (NULL, (unsigned char*)memblock, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG); // Flags   
            if(NT_SUCCESS(Status))
            {
                std::string temp(memblock);
                temp.erase(remove_if(temp.begin(), temp.end(), 
                        [](char c) { return !isalnum(c) || isupper(c); } ), temp.end());
                urandom.append(temp);
            }
            else
            {
                std::cout << "CryptGenRandom failed!\n";
                return urandom;
            }
        } while (urandom.length() < 8);

        urandom = urandom.substr(0, count);
    #elif defined(__linux__)
        std::ifstream istream("/dev/urandom", std::ios::in|std::ios::binary); //Open stream
        if(istream.is_open()) //Check if stream is open
        {
            do
            {
                const size_t size = 2048;
                char memblock[size];
                istream.read(reinterpret_cast<char*>(memblock), size);
                std::string temp(memblock);

                temp.erase(remove_if(temp.begin(), temp.end(), 
                        [](char c) { return !isalnum(c) || isupper(c); } ), temp.end());
                urandom.append(temp);
            }
            while(urandom.length() < 8);

            urandom = urandom.substr(0,count);
            istream.close();
        }
        else
            std::cout << "Failed to read /dev/urandom\n";
    #endif
        return urandom;
    }
};
}
