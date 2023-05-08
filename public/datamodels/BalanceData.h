#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace stelgic
{
class BalanceData
{
public:
    BalanceData() : available(0), locked(0),
            marginBalance(0), unrealizedPNL(0) {}

    virtual ~BalanceData() {}

    BalanceData(const BalanceData& other)
    {
        available = other.available;
        locked = other.locked;
        marginBalance = other.marginBalance;
        unrealizedPNL = other.unrealizedPNL;

        exchange = other.exchange;
        asset = other.asset;
        underAsset = other.underAsset;
    }

    BalanceData& operator=(const BalanceData& other)
    {
        if(this == &other)
            return *this;

        available = other.available;
        locked = other.locked;
        marginBalance = other.marginBalance;
        unrealizedPNL = other.unrealizedPNL;

        exchange = other.exchange;
        asset = other.asset;
        underAsset = other.underAsset;

        return *this;
    }

    BalanceData& operator=(const BalanceData&& other)
    {
        if(this == &other)
            return *this;

        available = other.available;
        locked = other.locked;
        marginBalance = other.marginBalance;
        unrealizedPNL = other.unrealizedPNL;

        exchange = std::move(other.exchange);
        asset = std::move(other.asset);
        underAsset = std::move(other.underAsset);

        return *this;
    }

    bool operator< (const BalanceData& other) const
    {
        return asset.compare(other.asset) < 0;
    }

    double available;
    double locked;
    double marginBalance;
    double unrealizedPNL;

    std::string exchange;
    std::string asset;
    std::string underAsset;

    std::string toString() const;
    friend std::ostream & operator<<(std::ostream &out, const BalanceData& balanceData);
};

inline std::ostream & operator<<(std::ostream &out, const BalanceData& balanceData)
{
    return out << std::left 
        << std::setw(10) << balanceData.asset
        << std::setw(10) << balanceData.available
        << std::setw(10) << balanceData.locked 
        << std::setw(10) << balanceData.marginBalance
        << std::setw(10) << balanceData.unrealizedPNL
        << std::setw(10) << balanceData.underAsset;
}

inline std::string BalanceData::toString() const
{
    std::ostringstream out;
    out << std::left 
        << std::setw(10) << asset
        << std::setw(10) << available
        << std::setw(10) << locked 
        << std::setw(10) << marginBalance
        << std::setw(10) << unrealizedPNL
        << std::setw(10) << underAsset;
    return std::move(out.str());
}
}
