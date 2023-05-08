#pragma once

#include <time.h>
#include <cmath>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <json/json.h>
#include "public/Utils.h"

namespace stelgic
{
class PositionData
{
public:
    PositionData() :
        local(false), closed(false), action(0), leverage(1.0), price(0), 
        closePrice(0), quantity(0), pnl(0), unrealizedPnl(0), maxPnl(0), 
        timestamp(0), ltimestamp(0), identifier("position"), closeDate("-")
    {
        
    }

    PositionData(const PositionData& other)
    {
        local = other.local;
        closed = other.closed;
        price = other.price;
        closePrice = other.closePrice;
        quantity = other.quantity;
        pnl = other.pnl;
        unrealizedPnl = other.unrealizedPnl;
        maxPnl = other.maxPnl;
        leverage = other.leverage;
        timestamp = other.timestamp;
        ltimestamp = other.ltimestamp;

        identifier = other.identifier;
        exchange = other.exchange;
        assetClass = other.assetClass;
        instrum = other.instrum;
        id = other.id;
        lid = other.lid;
        entryDate = other.entryDate;
        closeDate = other.closeDate;
        side = other.side;
        posSide = other.posSide;

        if(!attrs.isNull())
            attrs.copy(other.attrs);
    }

    virtual ~PositionData() {}

    PositionData& operator=(const PositionData& other)
    {
        if (this == &other) 
            return *this;

        local = other.local;
        closed = other.closed;
        price = other.price;
        closePrice = other.closePrice;
        quantity = other.quantity;
        pnl = other.pnl;
        unrealizedPnl = other.unrealizedPnl;
        maxPnl = other.maxPnl;
        leverage = other.leverage;
        timestamp = other.timestamp;
        ltimestamp = other.ltimestamp;

        identifier = other.identifier;
        exchange = other.exchange;
        assetClass = other.assetClass;
        instrum = other.instrum;
        id = other.id;
        lid = other.lid;
        entryDate = other.entryDate;
        closeDate = other.closeDate;
        side = other.side;
        posSide = other.posSide;

        if(!attrs.isNull())
            attrs.copy(other.attrs);

        return *this;
    }

    PositionData& operator=(const PositionData&& other)
    {
        if (this == &other) 
            return *this;

        local = other.local;
        closed = other.closed;
        price = other.price;
        closePrice = other.closePrice;
        quantity = other.quantity;
        pnl = other.pnl;
        unrealizedPnl = other.unrealizedPnl;
        maxPnl = other.maxPnl;
        leverage = other.leverage;
        timestamp = other.timestamp;
        ltimestamp = other.ltimestamp;

        identifier = std::move(other.identifier);
        exchange = std::move(other.exchange);
        assetClass = std::move(other.assetClass);
        instrum = std::move(other.instrum);
        id = std::move(other.id);
        lid = std::move(other.lid);
        entryDate = std::move(other.entryDate);
        closeDate = std::move(other.closeDate);
        side = std::move(other.side);
        posSide = std::move(other.posSide);
        
        if(!attrs.isNull())
            attrs = std::move(other.attrs);

        return *this;
    }

    void Update(const PositionData& other)
    {
        exchange = other.exchange;
        id = other.id;
        instrum = other.instrum;
        local = other.local;
        closed = other.closed;
        entryDate = other.entryDate;
        closeDate = other.closeDate;
        action = other.action;
        price = other.price;
        closePrice = other.closePrice;
        quantity = other.quantity;
        pnl = other.pnl;
        unrealizedPnl = other.unrealizedPnl;
        maxPnl = other.maxPnl;
        side = other.side;
        posSide = other.posSide;
        assetClass = other.assetClass;
        leverage = other.leverage;
        timestamp = other.timestamp;
        ltimestamp = (ltimestamp == 0) ? other.timestamp: ltimestamp;
        if(!attrs.isNull())
            attrs.copy(other.attrs);
    }

    bool operator< (const PositionData& other) const
    {
        return (lid.compare(other.lid) < 0);
    }

    bool operator== (const PositionData& other) const
    {
        return (lid.compare(other.lid) == 0);
    }

    void UpdateLocalId(bool isMany=false)
    {
        std::ostringstream oss;
        oss.setf(std::ios::fixed);
        oss.precision(8); 
        if(isMany)
        {
            oss << ltimestamp << exchange << assetClass 
                << instrum << side << posSide << price;  
        }
        else
        {
            oss << exchange << assetClass << instrum << side << posSide;
        }
        lid = std::to_string(std::hash<std::string>{}(oss.str()));
    }

    bool IsValid() const
    {
        return (!instrum.empty() && !lid.empty() && 
                price > 0.00000000 && std::abs(quantity) > 0.00000000);
    }

    double currentPnl(double currPrice) const
    {
        int factor = 1.0; //(leverage == 0) ? 1 : leverage;
        int direction = (side == "BUY") ? 1 : -1;
        return (currPrice - price) * std::abs(quantity) * direction * factor;
    }

    double currentPerc(double currPrice) const
    {
        int direction = (side == "BUY") ? 1 : -1;
        return ((currPrice - price) / price) * 100 * direction;
    }

    void setExit(double lastPrice, int64_t epoch, double takerFee=0.001)
    {
        double entryfee = quantity * price * takerFee;
        double exitfee = quantity * lastPrice * takerFee;
        pnl = currentPnl(lastPrice); //- entryfee - exitfee
        maxPnl = std::max(maxPnl, currentPerc(lastPrice));
        closePrice = lastPrice;
        closed = true;
        closeDate = Utils::FormatTimestamp(epoch);
    }

    std::string toJson() const;
    std::string toCsv() const;
    friend std::ostream & operator<<(std::ostream &out, const PositionData& posData);

public:
    bool local;
    bool closed;
    int action;
    int leverage;
    double price;
    double closePrice;
    double quantity;
    double pnl;
    double unrealizedPnl;
    double maxPnl; // max pnl perce to use for trailing stop loss
    int64_t timestamp;
    int64_t ltimestamp;

    std::string identifier;
    std::string exchange;
    std::string assetClass;
    std::string instrum;
    std::string lid; // local id
    std::string id;
    std::string entryDate;
    std::string closeDate;
    std::string side;
    std::string posSide;

    Json::Value attrs; // additional values    
};


inline std::ostream & operator<<(std::ostream &out, const PositionData& posData)
{
    return out << std::left 
        << std::setw(12) << posData.instrum
        << std::setw(19) << posData.entryDate
        << std::setw(18) << posData.closeDate
        << std::setw(6) << posData.side
        << std::setw(6) << posData.posSide
        << std::setw(10) << std::setprecision(8) << posData.price
        << std::setw(10) << std::setprecision(8) << posData.closePrice
        << std::setw(6) << std::setprecision(8) << posData.quantity
        << std::setw(8) << std::setprecision(8) << posData.pnl
        << std::setw(4) << posData.leverage
        << std::setw(16) << posData.timestamp
        << std::setw(8) << posData.assetClass
        << std::setw(8) << posData.exchange;
}

inline std::string PositionData::toJson() const
{
    std::ostringstream out;
    out.setf(std::ios::fixed);
    out << "{\"instrum\":\"" << instrum << "\","
        << "\"identifier\":\"" << identifier << "\","
        << "\"lid\":\"" << lid << "\","
        << "\"local\":" << local << ","
        << "\"entryDate\":\"" << entryDate << "\","
        << "\"side\":\"" << side << "\","
        << "\"posSide\":\"" << posSide << "\","
        << "\"pnl\":" << std::setprecision(2) << pnl << ","
        << "\"maxPerc\":" << std::setprecision(2) << maxPnl << ","
        << "\"price\":" << std::setprecision(8) << price << ","
        << "\"quantity\":" << std::setprecision(8) << quantity << ","
        << "\"closePrice\":" << std::setprecision(8) << closePrice << ","
        << "\"leverage\":" << leverage << ","
        << "\"timestamp\":" << timestamp << ","
        << "\"ltimestamp\":" << ltimestamp << ","
        << "\"exchange\":\"" << exchange << "\","
        << "\"assetClass\":\"" << assetClass << "\","
        << "\"closed\":" << closed << "}";
    return out.str();
}

inline std::string PositionData::toCsv() const
{
    std::string posSide = (action == 0) ? "None": side;
    
    std::ostringstream out;
    out.setf(std::ios::fixed);
    out << instrum
        << "\t" << entryDate
        << "\t" << closeDate
        << "\t" << std::setprecision(8) << price
        << "\t" << std::setprecision(8) << closePrice
        << "\t" << std::setprecision(8) << quantity
        << "\t" << std::setprecision(8) << pnl
        << "\t" << side
        << "\t" << timestamp
        << "\t" << ltimestamp
        << "\t" << assetClass
        << "\t" << exchange;

    return out.str();
}
}
