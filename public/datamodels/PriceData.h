#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace stelgic
{
class PriceData
{
public:
    PriceData() : price(0), quantity(0), timestamp(0) {};

    virtual ~PriceData() {}

    PriceData(const PriceData& other)
    {
        price = other.price;
        quantity = other.quantity;
        timestamp = other.timestamp;
        exchange = other.exchange;
        assetClass = other.assetClass;
        instrum = other.instrum;
        date = other.date;
        time = other.time;
    }

    PriceData& operator=(const PriceData& other)
    {
        if (this == &other) 
            return *this;
            
        price = other.price;
        quantity = other.quantity;
        timestamp = other.timestamp;
        exchange = other.exchange;
        assetClass = other.assetClass;
        instrum = other.instrum;
        date = other.date;
        time = other.time;

        return *this;
    }

    PriceData& operator=(PriceData&& other)
    {
        if (this == &other) 
            return *this;
            
        price = other.price;
        quantity = other.quantity;
        timestamp = other.timestamp;
        exchange = std::move(other.exchange);
        assetClass = std::move(other.assetClass);
        instrum = std::move(other.instrum);
        date = std::move(other.date);
        time = std::move(other.time);

        return *this;
    }

    double price;
    double quantity;
    int64_t timestamp;
    std::string exchange;
    std::string assetClass;
    std::string instrum;
    std::string date;
    std::string time;

    friend std::ostream & operator<<(std::ostream &out, const PriceData& priceData);
};


inline std::ostream & operator<<(std::ostream &out, const PriceData& priceData)
{
    return out << std::left 
        << std::setw(12) << priceData.instrum
        << std::setw(10) << priceData.date
        << std::setw(10) << priceData.time
        << std::setw(10) << std::setprecision(8) << priceData.price
        << std::setw(10) << std::setprecision(8) << priceData.quantity
        << std::setw(16) << priceData.timestamp
        << std::setw(8) << priceData.assetClass
        << std::setw(8) << priceData.exchange;
}
}
