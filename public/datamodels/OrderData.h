#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <json/json.h>

namespace stelgic
{
class OrderData
{
public:
    OrderData() : local(false), special(false), 
        closePosition(false), price(0.0), stopPrice(0.0), 
        profitPrice(0.0), quantity(0.0), execQuantity(0.0), fees(0.0), 
        timestamp(0), ltimestamp(0),identifier("order"), assetClass("")
    {
        
    }

    virtual ~OrderData() {}

    OrderData(const OrderData& other)
    {
        local = other.local;
        special = other.special;
        closePosition = other.closePosition;
        position = other.position; // 0: open; 1: close long; -1: close short
        price = other.price;
        stopPrice = other.stopPrice;
        profitPrice = other.profitPrice;
        quantity = other.quantity;
        execQuantity = other.execQuantity;
        fees = other.fees;
        timestamp = other.timestamp;
        ltimestamp = other.ltimestamp; // local create timestamp

        identifier = other.identifier;
        exchange = other.exchange;
        assetClass = other.assetClass;
        id = other.id;
        lid = other.lid;
        instrum = other.instrum;
        date = other.date;
        side = other.side;
        posSide = other.posSide; // SHORT, LONG, BOTH
        orderType = other.orderType;
        state = other.state;
        timeInForce = other.timeInForce; 
        marginMode = other.marginMode;

        if(!attrs.isNull())
            attrs.copy(other.attrs);
    }

    OrderData& operator=(const OrderData& other)
    {
        if (this == &other) 
            return *this;

        local = other.local;
        special = other.special;
        closePosition = other.closePosition;
        position = other.position; // 0: open; 1: close long; -1: close short
        price = other.price;
        stopPrice = other.stopPrice;
        profitPrice = other.profitPrice;
        quantity = other.quantity;
        execQuantity = other.execQuantity;
        fees = other.fees;
        timestamp = other.timestamp;
        ltimestamp = other.ltimestamp; // local create timestamp

        identifier = other.identifier;
        exchange = other.exchange;
        assetClass = other.assetClass;
        id = other.id;
        lid = other.lid;
        instrum = other.instrum;
        date = other.date;
        side = other.side;
        posSide = other.posSide; // SHORT, LONG, BOTH
        orderType = other.orderType;
        state = other.state;
        timeInForce = other.timeInForce; 
        marginMode = other.marginMode;

        if(!attrs.isNull())
            attrs.copy(other.attrs);

        return *this;
    }

    OrderData& operator=(const OrderData&& other)
    {
        if (this == &other) 
            return *this;

        local = other.local;
        special = other.special;
        closePosition = other.closePosition;
        position = other.position; // 0: open; 1: close long; -1: close short
        price = other.price;
        stopPrice = other.stopPrice;
        profitPrice = other.profitPrice;
        quantity = other.quantity;
        execQuantity = other.execQuantity;
        fees = other.fees;
        timestamp = other.timestamp;
        ltimestamp = other.ltimestamp; // local create timestamp

        identifier = std::move(other.identifier);
        exchange = std::move(other.exchange);
        assetClass = std::move(other.assetClass);
        id = std::move(other.id);
        lid = std::move(other.lid);
        instrum = std::move(other.instrum);
        date = std::move(other.date);
        side = std::move(other.side);
        posSide = std::move(other.posSide); // SHORT, LONG, BOTH
        orderType = std::move(other.orderType);
        state = std::move(other.state);
        timeInForce = std::move(other.timeInForce); 
        marginMode = std::move(other.marginMode);

        if(!attrs.isNull())
            attrs = std::move(other.attrs);

        return *this;
    }

    void Update(const OrderData& other)
    {
        local = other.local;
        special = other.special;
        closePosition = other.closePosition;
        position = other.position; // 0: open; 1: close long; -1: close short
        price = other.price;
        stopPrice = other.stopPrice;
        profitPrice = other.profitPrice;
        quantity = other.quantity;
        execQuantity = other.execQuantity;
        fees = other.fees;
        timestamp = other.timestamp;
        ltimestamp = other.ltimestamp; // local create timestamp

        identifier = other.identifier;
        exchange = other.exchange;
        assetClass = other.assetClass;
        lid = other.lid;
        instrum = other.instrum;
        date = other.date;
        side = other.side;
        posSide = other.posSide; // SHORT, LONG, BOTH
        orderType = other.orderType;
        state = other.state;
        timeInForce = other.timeInForce; 
        marginMode = other.marginMode;

        if(!attrs.isNull())
            attrs.copy(other.attrs);
    }

    bool operator< (const OrderData& other) const
    {
        return (id.compare(other.id) < 0);
    }

    bool operator== (const OrderData& other) const
    {
        return (id.compare(other.id) == 0);
    }

    void UpdateLocalId()
    {
        std::ostringstream oss;
        oss.setf(std::ios::fixed);
        oss.precision(8); 

        std::string dir = side;
        if(closePosition)
            dir = (side == "BUY") ? "SELL": "BUY";
        oss << exchange << assetClass << instrum << dir << posSide;
        lid = std::to_string(std::hash<std::string>{}(oss.str()));
    }

    bool IsValid() const
    {
        return (!instrum.empty() && !orderType.empty() && 
                price > 0.0 && (timestamp > 0 || ltimestamp > 0));
    }
    
    bool local;
    bool special; // special order such as OCO
    bool closePosition;
    int position; // 0: none; 1: open long; -1: open short;
    double price;
    double stopPrice;
    double profitPrice;
    double quantity;
    double execQuantity;
    double fees;
    int64_t timestamp;
    int64_t ltimestamp; // local timestamp

    std::string identifier;
    std::string id;
    std::string lid; // local id
    std::string exchange;
    std::string assetClass;
    std::string instrum;
    std::string date;
    std::string side; // BUY, SELL
    std::string posSide; // SHORT, LONG
    std::string orderType;
    mutable std::string state;
    std::string timeInForce; // GTC, ICO, FOK, GTX
    std::string marginMode;
    Json::Value attrs; // additional values

    std::string toJson() const;
    friend std::ostream & operator<<(std::ostream &out, const OrderData& orderData);
    
};


inline std::ostream & operator<<(std::ostream &out, const OrderData& orderData)
{
    return out << std::left 
        << std::setw(12) << orderData.instrum
        << std::setw(16) << orderData.date
        << std::setw(11) << orderData.id
        << std::setw(5) << orderData.side
        << std::setw(5) << orderData.posSide
        << std::setw(6) << orderData.orderType 
        << std::setw(8) << std::setprecision(8) << orderData.price
        << std::setw(7) << std::setprecision(8) << orderData.quantity
        << std::setw(8) << std::setprecision(8) << orderData.execQuantity
        << std::setw(18) << orderData.state
        << std::setw(14) << orderData.timestamp
        << std::setw(7) << orderData.assetClass
        << std::setw(5) << orderData.exchange;
}

inline std::string OrderData::toJson() const
{
    std::ostringstream out;
    out << "{\"instrum\":\"" << instrum << "\","
        << "\"date\":\"" << date << "\","
        << "\"id\":\"" << id << "\","
        << "\"lid\":\"" << lid << "\","
        << "\"side\":\"" << side << "\","
        << "\"posSide\":\"" << posSide << "\","
        << "\"orderType\":\"" << orderType << "\","
        << "\"price\":" << price << ","
        << "\"quantity\":" << quantity << ","
        << "\"execQuantity\":" << execQuantity << ","
        << "\"state\":\"" << state << "\","
        << "\"timestamp\":" << timestamp << ","
        << "\"special\":" << (int)special << ","
        << "\"closePosition\":" << (int)closePosition << ","
        << "\"exchange\":\"" << exchange << "\","
        << "\"assetClass\":\"" << assetClass << "\","
        << "\"identifier\":\"" << identifier << "\"}";
    return std::move(out.str());
}
}
