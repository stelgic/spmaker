#include <g3log/g3log.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include "SpinLock.h"
#include "datamodels/OrderData.h"

using namespace g3;
using namespace boost::container;

namespace stelgic
{
class TradeStats
{
public:
    TradeStats()
    {
        // benchmarch statistics
        statistics["NEW"] = {0};
        statistics["FILLED"] = {0};
        statistics["PARTIALLY_FILLED"] = {0};
        statistics["CANCELED"] = {0};
        statistics["REJECTED"] = {0};
        statistics["EXPIRED"] = {0};
        statistics["NEW_ELAPSED"] = {0}; // time taken from local and order placed on exchange
        statistics["FILLED_ELAPSED"] = {0}; // time taken from local and order filled on exchange
    }

    virtual ~TradeStats() {}

    void UpdateNewOrderStats(const OrderData& order,  
        std::chrono::system_clock::time_point starttime)
    {
        if(!order.id.empty())
        {
            // compute the request time to place new order
            auto endtime = std::chrono::system_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(endtime - starttime);
            // update statistics map
            statsLock.Lock();
            std::string ordState = "NEW";
            ++statistics.at(ordState);
            ordState.append("_ELAPSED");
            statistics.at(ordState) += elapsed.count();

            int64_t crttime = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                endtime.time_since_epoch()).count();
            newOrdersTimeMap.insert_or_assign(order.id, crttime);

            statsLock.Unlock();
        }
    }

    void UpdateOrderStats(const OrderData& order, std::string ordState)
    {
        auto now = std::chrono::system_clock::now();
        int64_t currtime = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                    now.time_since_epoch()).count();
        statsLock.Lock();
        if((ordState == "NEW") && newOrdersTimeMap.count(order.id) == 0)
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::milliseconds(currtime) - std::chrono::milliseconds(order.timestamp));

            ++statistics.at(ordState);
            ordState.append("_ELAPSED");
            statistics.at(ordState) += elapsed.count();
            newOrdersTimeMap.insert_or_assign(order.id, order.timestamp);
        }
        else if(ordState == "PARTIALLY_FILLED" && partialFilledOrders.count(order.id) == 0)
        {
            ++statistics.at(ordState);
            partialFilledOrders.insert(order.id);
        }
        else if(ordState == "FILLED" && newOrdersTimeMap.count(order.id))
        {
            auto crttime = newOrdersTimeMap.at(order.id);
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::milliseconds(currtime) - std::chrono::milliseconds(crttime));

            ++statistics.at(ordState);
            ordState.append("_ELAPSED");
            statistics.at(ordState) += elapsed.count();
            newOrdersTimeMap.erase(order.id);
            partialFilledOrders.erase(order.id);
        }
        else if(ordState == "CANCELED" || ordState == "EXPIRED" || ordState == "REJECTED")
        {
            ++statistics.at(ordState);
            newOrdersTimeMap.erase(order.id);
            partialFilledOrders.erase(order.id);
        }
        statsLock.Unlock();
    }

    std::unordered_map<std::string,std::atomic<int64_t>>& GetStatistics()
    {
        return statistics;
    }

    void LogBenchmarks()
    {
        long newCount = statistics.at("NEW");
        long filledCount = statistics.at("FILLED");
        long newElapsed = newCount > 0 ? statistics.at("NEW_ELAPSED") / newCount : 0;
        long filledElapsed = filledCount > 0 ? statistics.at("FILLED_ELAPSED") / filledCount : 0;

        LOG(INFO) << "NEW=" << statistics.at("NEW")
            << "\tFILLED=" << statistics.at("FILLED")
            << "\tPARTIAL_FILLED=" << statistics.at("PARTIALLY_FILLED")
            << "\tCANCELED=" << statistics.at("CANCELED")
            << "\tREJECTED=" << statistics.at("REJECTED")
            << "\tEXPIRED=" << statistics.at("EXPIRED");

        LOG(INFO) << "NEW_ELAPSED=" << newElapsed << "ms"
            << "\tFILLED_ELAPSED=" << filledElapsed << "ms\n\n";
    }

public:
    flat_set<std::string> partialFilledOrders;
    flat_map<std::string, int64_t> newOrdersTimeMap;
    std::unordered_map<std::string,std::atomic<int64_t>> statistics;

protected:
    SpinLock statsLock;
};
}
