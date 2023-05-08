#pragma once

#include <iomanip>
#include <string>
#include <json/json.h>

namespace stelgic
{
struct Filter
{
    Filter() : pxPrecision(0), qtyPrecision(0), 
            basePrecision(0), quotePrecision(0),
            tickSize(0.0), maxPrice(0.0),
            stepSize(0.0), maxQty(0.0) {}

    Filter(const Filter& other)
    {
        pxPrecision = other.pxPrecision;
        qtyPrecision = other.qtyPrecision;
        basePrecision = other.basePrecision;
        quotePrecision = other.quotePrecision;
        tickSize = other.tickSize;
        maxPrice = other.maxPrice;
        stepSize = other.stepSize;
        maxQty = other.maxQty;
        instrum = other.instrum;
        status = other.status;

        if(!other.attrs.isNull())
            attrs = other.attrs;
    }

    Filter& operator=(const Filter& other)
    {
        if (this == &other)
            return *this;
        
        pxPrecision = other.pxPrecision;
        qtyPrecision = other.qtyPrecision;
        basePrecision = other.basePrecision;
        quotePrecision = other.quotePrecision;
        tickSize = other.tickSize;
        maxPrice = other.maxPrice;
        stepSize = other.stepSize;
        maxQty = other.maxQty;
        instrum = other.instrum;
        status = other.status;

        if(!other.attrs.isNull())
            attrs = std::move(other.attrs);
        
        return *this;
    }

    /*Filter& operator=(const Filter&& other)
    {
        if (this != &other) 
            return *this;
            
        pxPrecision = other.pxPrecision;
        qtyPrecision = other.qtyPrecision;
        basePrecision = other.basePrecision;
        quotePrecision = other.quotePrecision;
        tickSize = other.tickSize;
        maxPrice = other.maxPrice;
        stepSize = other.stepSize;
        maxQty = other.maxQty;
        instrum = std::move(other.instrum);
        status = std::move(other.status);

        if(!other.attrs.isNull())
            attrs = std::move(other.attrs);
        
        return *this;
    }*/

    bool operator< (const Filter& other) const
    {
        return instrum.compare(other.instrum) < 0;
    }

    bool operator== (const Filter& other) const
    {
        return instrum.compare(other.instrum) == 0;
    }
    
    std::string instrum;
    std::string status;
    int pxPrecision;
    int qtyPrecision;
    int basePrecision;
    int quotePrecision;
    double tickSize;
    double maxPrice;
    double stepSize;
    double maxQty;
    Json::Value attrs;

    friend std::ostream & operator<<(std::ostream &out, const Filter& filter);
};

inline std::ostream & operator<<(std::ostream &out, const Filter& filter)
{
    return out << std::left 
        << std::setw(16) << filter.instrum
        << std::setw(12) << filter.status
        << std::setw(8) << filter.tickSize
        << std::setw(8) << filter.stepSize
        << std::setw(8) << filter.maxPrice
        << std::setw(5) << filter.pxPrecision
        << std::setw(5) << filter.qtyPrecision
        << std::setw(5) << filter.basePrecision
        << std::setw(5) << filter.quotePrecision;
}
}

