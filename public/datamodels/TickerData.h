#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace stelgic
{
class TickerData
{
public:
    TickerData() : bid(0), ask(0), bidQty(0), 
                    askQty(0), timestamp(0){}
    
    virtual ~TickerData() {}

    TickerData(const TickerData& other)
    {
        bid = other.bid;
        ask = other.ask;
        bidQty = other.bidQty;
        askQty = other.askQty;
        timestamp = other.timestamp;
        exchange = other.exchange;
        assetClass = other.assetClass;
        instrum = other.instrum;
    }

    TickerData& operator=(const TickerData& other)
    {
        if (this == &other) 
            return *this;
            
        bid = other.bid;
        ask = other.ask;
        bidQty = other.bidQty;
        askQty = other.askQty;
        timestamp = other.timestamp;
        exchange = other.exchange;
        assetClass = other.assetClass;
        instrum = other.instrum;

        return *this;
    }

    TickerData& operator=(TickerData&& other)
    {
        if (this == &other) 
            return *this;
            
        bid = other.bid;
        ask = other.ask;
        bidQty = other.bidQty;
        askQty = other.askQty;
        timestamp = other.timestamp;
        exchange = std::move(other.exchange);
        assetClass = std::move(other.assetClass);
        instrum = std::move(other.instrum);

        return *this;
    }

    bool operator< (const TickerData& other) const
    {
        return instrum.compare(other.instrum) < 0;
    }

    double bid;
    double ask;
    double bidQty;
    double askQty;
    int64_t timestamp;
    std::string exchange;
    std::string assetClass;
    std::string instrum;

    friend std::ostream & operator<<(std::ostream &out, const TickerData& ticker);
};

inline std::ostream & operator<<(std::ostream &out, const TickerData& ticker)
{
    return out << std::left 
        << std::setw(12) << ticker.instrum
        << std::setw(10) << std::setprecision(8) << ticker.bid
        << std::setw(10) << std::setprecision(8) << ticker.bidQty
        << std::setw(10) << std::setprecision(8) << ticker.ask
        << std::setw(10) << std::setprecision(8) << ticker.askQty
        << std::setw(16) << ticker.timestamp
        << std::setw(8) << ticker.assetClass
        << std::setw(8) << ticker.exchange;
}
}

