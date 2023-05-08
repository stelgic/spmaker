#pragma once

#include <string>
#include <set>
#include <iomanip>
#include <iostream>
#include "BalanceData.h"

namespace stelgic
{
class ExchangeData
{
public:
    ExchangeData() {}
    virtual ~ExchangeData() {}

    ExchangeData(const ExchangeData& other)
    {
        name = other.name;
        balances = balances;
    }

    ExchangeData& operator=(const ExchangeData& other)
    {
        if(this == &other)
            return *this;

        name = other.name;
        balances = balances;

        return *this;
    }

    ExchangeData& operator=(const ExchangeData&& other)
    {
        if(this == &other)
            return *this;

        name = std::move(other.name);
        balances = std::move(balances);

        return *this;
    }

    bool operator< (const ExchangeData& other) const
    {
        return name.compare(other.name) < 0;
    }

    std::string name;
    std::set<BalanceData> balances;
};
}
