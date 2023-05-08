#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <json/json.h>

namespace stelgic
{
class CandleData
{
public:
    CandleData() : strike(0), open(0), high(0), low(0), close(0), 
        volume(0), numTrades(0), timestamp(0), endtimestamp(0) {}

    virtual ~CandleData() {}

    CandleData(const CandleData& other)
    {
        strike = other.strike;
        open = other.open;
        high = other.high;
        low = other.low;
        close = other.close;
        volume = other.volume;
        numTrades = other.numTrades;
        timestamp = other.timestamp;
        endtimestamp = other.endtimestamp;

        exchange = other.exchange;
        assetClass = other.assetClass;
        instrum = other.instrum;
        date = other.date;
        time = other.time;
        expireDate = other.expireDate;
        optionType = other.optionType;
        
        if(!attrs.isNull())
            attrs.copy(other.attrs);
    }

    CandleData& operator=(const CandleData& other)
    {
        if(this == &other)
            return *this;

        strike = other.strike;
        open = other.open;
        high = other.high;
        low = other.low;
        close = other.close;
        volume = other.volume;
        numTrades = other.numTrades;
        timestamp = other.timestamp;
        endtimestamp = other.endtimestamp;

        exchange = other.exchange;
        assetClass = other.assetClass;
        instrum = other.instrum;
        date = other.date;
        time = other.time;
        expireDate = other.expireDate;
        optionType = other.optionType;

        if(!attrs.isNull())
            attrs.copy(other.attrs);

        return *this;
    }

    CandleData& operator=(const CandleData&& other)
    {
        if(this == &other)
            return *this;

        strike = other.strike;
        open = other.open;
        high = other.high;
        low = other.low;
        close = other.close;
        volume = other.volume;
        numTrades = other.numTrades;
        timestamp = other.timestamp;
        endtimestamp = other.endtimestamp;

        exchange = std::move(other.exchange);
        assetClass = std::move(other.assetClass);
        instrum = std::move(other.instrum);
        date = std::move(other.date);
        time = std::move(other.time);
        expireDate = std::move(other.expireDate);
        optionType = std::move(other.optionType);

        if(!attrs.isNull())
            attrs = std::move(other.attrs);

        return *this;
    }

    double strike;
    double open;
    double high;
    double low;
    double close;
    double volume;
    int numTrades;
    int64_t timestamp;
    int64_t endtimestamp;

    std::string exchange;
    std::string assetClass;
    std::string instrum;
    std::string date;
    std::string time;
    std::string expireDate;
    std::string optionType;
    Json::Value attrs;

    std::string toString() const;
    friend std::ostream & operator<<(std::ostream &out, const CandleData& candleData);
};


inline std::ostream & operator<<(std::ostream &out, const CandleData& candleData)
{
    return out << std::left 
        << std::setw(10) << candleData.instrum
        << std::setw(12) << candleData.date
        << std::setw(8) << candleData.time 
        << std::setw(12) << std::setprecision(8) << candleData.open
        << std::setw(12) << std::setprecision(8) << candleData.high
        << std::setw(12) << std::setprecision(8) << candleData.low
        << std::setw(12) << std::setprecision(8) << candleData.close
        << std::setw(12) << std::setprecision(8) << candleData.volume
        << std::setw(8) << candleData.assetClass
        << std::setw(8) << candleData.exchange;
}

inline std::string CandleData::toString() const
{
    std::ostringstream out;
    out << std::left 
        << std::setw(10) << instrum
        << std::setw(10) << date
        << std::setw(10) << time 
        << std::setw(16) << std::setprecision(8) << open
        << std::setw(16) << std::setprecision(8) << high
        << std::setw(16) << std::setprecision(8) << low
        << std::setw(16) << std::setprecision(8) << close
        << std::setw(16) << std::setprecision(8) << volume
        << std::setw(8) << assetClass
        << std::setw(8) << exchange;
    return std::move(out.str());
}
}
