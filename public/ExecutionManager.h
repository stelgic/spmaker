#include "IExchange.h"
#include "SpinLock.h"
#include <atomic>
#include <g3log/g3log.hpp>

using namespace g3;

namespace stelgic
{
class ExecutionManager
{
public:
    ExecutionManager(const ExecutionManager &other) = default;
    ExecutionManager &operator=(const ExecutionManager &other) = default;
public:
    ExecutionManager(double maxCapital, double riskPercentage, int verbosity) 
        : capital(maxCapital), riskLimit(riskPercentage), usedCapital(0.0), verbose(verbosity)
    {
        // map order state to method
        dispatcherMap["NEW0"] = (pfunct)&ExecutionManager::UpdateOpeningPosition;
        dispatcherMap["FILLED0"] = (pfunct)&ExecutionManager::UpdateOpenedPosition;
        dispatcherMap["PARTIALLY_FILLED0"] = (pfunct)&ExecutionManager::UpdateOpenedPosition;
        dispatcherMap["NEW1"] = (pfunct)&ExecutionManager::UpdateClosingPosition;
        dispatcherMap["PARTIALLY_FILLED1"] = (pfunct)&ExecutionManager::UpdateClosingPosition;
        dispatcherMap["FILLED1"] = (pfunct)&ExecutionManager::UpdateClosedPosition;
        dispatcherMap["CANCELED0"] = (pfunct)&ExecutionManager::UpdateCancelOpening;
        dispatcherMap["CANCELED1"] = (pfunct)&ExecutionManager::UpdateCancelClosing;
        dispatcherMap["EXPIRED0"] = (pfunct)&ExecutionManager::UpdateCancelOpening;
        dispatcherMap["EXPIRED1"] = (pfunct)&ExecutionManager::UpdateCancelClosing;

        // bybit order status
        orderStatusMap.emplace("New","NEW");
        orderStatusMap.emplace("Created","NEW");
        orderStatusMap.emplace("Rejected","REJECTED");
        orderStatusMap.emplace("Filled","FILLED");
        orderStatusMap.emplace("PartiallyFilled","PARTIALLY_FILLED");
        orderStatusMap.emplace("Deactivated","EXPIRED");
        orderStatusMap.emplace("Cancelled","CANCELED");
    }

    virtual ~ExecutionManager() {}

    void Update(const OrderData& primary, const OrderData& secondary)
    {
        std::string event = primary.state;
        // try to map order state
        if(orderStatusMap.count(primary.state))
            event = orderStatusMap.at(primary.state);
        event.append(std::to_string((int)primary.closePosition));

        if(dispatcherMap.count(event))
        {
            pfunct caller = dispatcherMap[event];
            (this->*caller)(primary, secondary);
        }
    }

    void UpdateOpenOrders(const flat_set<OrderData>& orders)
    {
        execLock.Lock();
        openOrders.insert(orders.begin(), orders.end());
        execLock.Unlock();
    }

    void UpdateOpenPositions(
        const std::string& instrum, const flat_set<PositionData>& positions)
    {
        execLock.Lock();
        if (openPositions.count(instrum) == 0)
            openPositions.emplace(instrum, flat_set<PositionData>());
        openPositions[instrum].insert(positions.begin(), positions.end());
        execLock.Unlock();
    }

    void ClosingRequest(const OrderData& order)
    {
        execLock.Lock();
        closingRequests.insert(order.id);
        execLock.Unlock();
    }

    void ClearClosingRequest(const OrderData& order)
    {
        execLock.Lock();
        closingRequests.erase(order.id);
        execLock.Unlock();
    }

    void CancelRequest(const OrderData& order)
    {
        execLock.Lock();
        cancelingRequests.insert(order.id);
        execLock.Unlock();
    }

    void ClearCancelRequest(const OrderData& order)
    {
        execLock.Lock();
        cancelingRequests.erase(order.id);
        execLock.Unlock();
    }

    void CopyPositionOrders(const std::string& instrum, flat_set<OrderData>& orders)
    {
        if (positionsOrderIds.count(instrum))
        {
            execLock.Lock();
            for(const std::string& id: positionsOrderIds.at(instrum))
            {
                OrderData order;
                order.id = id;
                auto it = postOders.find(order);
                if(it != postOders.end())
                    orders.insert(*it);
            }
            execLock.Unlock();
        }
    }

    void CopyOpenOrders(flat_set<OrderData>& orders)
    {
        execLock.Lock();
        orders.insert(openOrders.begin(), openOrders.end());
        execLock.Unlock();
    }

    void CopyOpenPositions(const std::string& instrum, flat_set<PositionData>& positions)
    {
        execLock.Lock();
        auto it = openPositions.find(instrum);
        if(it != openPositions.end())
            positions.insert(it->second.begin(), it->second.end());
        execLock.Unlock();
    }

    bool HasPosition(const std::string& instrum)
    {
        bool success = false;
        execLock.Lock();
        if(positionsOrderIds.count(instrum))
            success = positionsOrderIds.at(instrum).size() > 0;
        execLock.Unlock();
        return success;
    }

    bool IsClosingRequested(const OrderData& order)
    {
        execLock.Lock();
        bool success = closingRequests.count(order.id);
        execLock.Unlock();
        return success;
    }

    bool IsCancelRequested(const OrderData& order)
    {
        execLock.Lock();
        bool success = cancelingRequests.count(order.id);
        execLock.Unlock();
        return success;
    }

    double GetRiskCapital()
    {
        execLock.Lock();
        usedCapital = (usedCapital < 0) ? 0.0: usedCapital;
        double riskCapital = capital * riskLimit;
        if((capital - usedCapital) < riskCapital)
            riskCapital = 0.0;
        execLock.Unlock();

        return riskCapital;
    }

    void UpdateUsedCapital(double value)
    {
        execLock.Lock();
        usedCapital += value;
        double usedCap = usedCapital;
        execLock.Unlock();

        LOG_IF(INFO, verbose > 1) << "CAPITAL=" << capital << " " << "USED_CAPITAL=" << usedCap;
    }

    std::string GetMappedState(const std::string& state)
    {
        if(orderStatusMap.count(state))
            return orderStatusMap.at(state);
        return state;
    }

protected:
    void UpdateOpeningPosition(const OrderData& order, const OrderData& dummy)
    {
        execLock.Lock();
        openOrders.insert(order);
        execLock.Unlock();        
    }

    void UpdateOpenedPosition(const OrderData& order, const OrderData& dummy)
    {
        execLock.Lock();
        postOders.insert(order);
        if(positionsOrderIds.count(order.instrum) == 0)
            positionsOrderIds.emplace(order.instrum, flat_set<std::string>());
        positionsOrderIds.at(order.instrum).insert(order.id);
        
        if(order.state == "FILLED")
            openOrders.erase(order);
        
        execLock.Unlock();
    }

    void UpdateClosingPosition(const OrderData& order, const OrderData& postOrder)
    {
        execLock.Lock();
        openOrders.insert(order);
        reduceOrders.insert(order);
        //closingRequests.erase(order.lid);
        usedCapital -= (order.execQuantity * order.price);
        execLock.Unlock();
    }

    void UpdateClosedPosition(const OrderData& order, const OrderData& postOrder)
    {
        execLock.Lock();
        closingRequests.erase(order.lid);

        if(positionsOrderIds.count(order.instrum))
        {
            positionsOrderIds.at(order.instrum).erase(order.id);
            positionsOrderIds.at(order.instrum).erase(order.lid);
        }

        openOrders.erase(order);
        reduceOrders.erase(order);

        OrderData openigOrder;
        openigOrder.id = order.lid;
        postOders.erase(openigOrder);
        postOders.erase(postOrder);

        usedCapital -= (order.execQuantity * order.price);
        double usedCap = usedCapital;
        execLock.Unlock();

        LOG_IF(INFO, verbose > 0) << "CAPITAL=" << capital << " " << "USED_CAPITAL=" << usedCap;
    }

    void UpdateCancelOpening(const OrderData& order, const OrderData& dummy)
    {
        execLock.Lock();
        openOrders.erase(order);
        cancelingRequests.erase(order.id);
        
        usedCapital -= ((order.quantity - order.execQuantity) * order.price);
        double usedCap = usedCapital;
        execLock.Unlock();

        LOG_IF(INFO, verbose > 0) << "CAPITAL=" << capital << " " << "USED_CAPITAL=" << usedCap;
    }

    void UpdateCancelClosing(const OrderData& order, const OrderData& dummy)
    {
        execLock.Lock();
        cancelingRequests.erase(order.id);
        closingRequests.erase(order.lid);
        openOrders.erase(order);
        execLock.Unlock();
    }
    
private:
    int verbose;
    double riskLimit;
    double capital;
    double usedCapital;

    SpinLock execLock;
    flat_set<OrderData> openOrders;
    flat_set<OrderData> postOders;
    flat_set<OrderData> reduceOrders;
    flat_set<std::string> closingRequests;
    flat_set<std::string> cancelingRequests;
    flat_map<std::string, flat_set<PositionData>> openPositions;
    flat_map<std::string, flat_set<std::string>> positionsOrderIds;

    flat_map<std::string,std::string> orderStatusMap;

    // add function to map for each event type to avoid if else
    typedef void (ExecutionManager::*pfunct)(const OrderData& primary, const OrderData& secondary);
    flat_map<std::string, pfunct> dispatcherMap;
};
}
