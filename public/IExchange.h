#pragma once

#define _WEBSOCKETPP_CPP11_STL_
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include <ctime>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <random>
#include <functional>
#include <unordered_map>
#include <json/json.h>
#include <concurrentqueue.h>
#include <cpr/cpr.h>
#include <g3log/g3log.hpp>
#include <websocketpp/endpoint.hpp>
#include <websocketpp/connection.hpp>
#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include "datamodels/InstrumentFilter.h"
#include "datamodels/PriceData.h"
#include "datamodels/CandleData.h"
#include "datamodels/OrderData.h"
#include "datamodels/PositionData.h"
#include "datamodels/BalanceData.h"
#include "datamodels/TickerData.h"

using namespace moodycamel;
using namespace boost::container;

namespace stelgic
{
using WebClient=websocketpp::client<websocketpp::config::asio_tls_client>;
using ContextPtr=websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context>;
using ThreadPtr = websocketpp::lib::shared_ptr<websocketpp::lib::thread>;
using StrMap = std::unordered_map<std::string, std::string>;
using StrPair = std::pair<std::string, std::string>;
using IntStrPair = std::pair<int, std::string>;
using MessageQueue = ConcurrentQueue<std::pair<std::string, std::string>>;

enum class ConnState 
{
    Opening=0, Opened, Closed, Failed, Invalid, Abnormal
};

enum class LiveState 
{
    Started=0, Running, Paused, Stopped
};

class IExchange
{
protected:
    /**
     * @brief Construct a new IExchange object
     * 
     */
    IExchange() {};

    /**
     * @brief Construct a new IExchange object from existent one
     * 
     * @param other 
     */
    IExchange(const IExchange& other) = default;

    /**
     * @brief Make a copy IExchange to new one
     * 
     * @param other 
     * @return IExchange& 
     */
    IExchange& operator=(const IExchange& other) = default;

public:
    /**
     * @brief Destroy the IExchange object
     * 
     */
    virtual ~IExchange() = default;

    /**
     * @brief this method should be called before connect.
     * It does required websocket initializations
     * 
     * @param params 
     * @param logLevel 
     * @param logWorker
     * 
     */
    virtual void Init(const Json::Value& params, int logLevel, g3::LogWorker* logWorker) = 0;

    /**
     * @brief close websocket connection
     * 
     */
    virtual void Close() = 0;

    /**
     * @brief 
     * 
     */
    virtual void Stop() = 0;

    /**
     * @brief - modify to reconnect to specific connection
     * 
     */
    virtual void Reconnect() = 0;

    /**
     * @brief 
     * 
     * @return true 
     * @return false 
     */
    virtual bool IsInitialized() = 0;

    /**
     * @brief - if true realtime connection has been established with this exchange
     * 
     * @return true 
     * @return false 
     */
    virtual bool IsOnline() = 0;

    /**
     * @brief check where the http request limit is hit
     * 
     * @return true 
     * @return false 
     */
    virtual bool IsRequestLimitHit() = 0;

    /**
     * @brief start a time to reset the limit after n period
     * 
     * @param millis 
     * @return true 
     * @return false 
     */
    virtual bool ResetRequestLimitTimer(int millis) = 0;

    /**
     * @brief compute average time on ping send and pong received
     * 
     */
    virtual void TestConnectivity() = 0;

    /**
     * @brief Get the instrum Filters
     * 
     * @return flat_set<Filter>& 
     */
    virtual flat_set<Filter>& GetFilters() = 0;
    
    /**
     * @brief Get the Configuration object
     * 
     * @return Json::Value& 
     */
    virtual Json::Value& GetConfiguration() = 0;

    /**
     * @brief Get the Message Queue object
     * 
     * @param tag 
     * @return void* - must cast to MessageQueue type
     */
    virtual void* GetMessageQueue(const std::string& tag) = 0;

    /**
     * @brief - connect to websocket server using credentials
     * 
     * @param params - key and websocket endpoint url to subscribe for live data
     */
    virtual ConnState Connect(const Json::Value& params) = 0;

    /**
     * @brief - subscribe to websocket stream by channel
     * 
     * @param key 
     * @param market 
     * @param symbols 
     * @param channels 
     * @param privacy public or private endpoint 
     * @return true 
     * @return false 
     */
    virtual bool Subscribe(const std::string& key,
                            const std::string& market,
                            const Json::Value& symbols, 
                            const Json::Value& channels,
                            std::string privacy="public") = 0;

    /**
     * @brief 
     * 
     * @param params 
     * @return true 
     * @return false 
     */
    virtual bool Subscribe(const Json::Value& params) = 0;

    /**
     * @brief send message to server via websocket
     * 
     * @param key - given key name to endpoint [public or private]
     * @param message 
     * @return true 
     * @return false 
     */
    virtual bool Send(const std::string& key, const std::string& message) = 0;
    
    /**
     * @brief - send ping or keep alive command to server to keep connected
     *          some server disconnect client at certain period
     * 
     * @param key - given key name to cached endpoint [public or private]
     * @return true - server return success 
     * @return false - command might or not reach server
     */
    virtual bool SendKeepAlive(const std::string& key) = 0;

    /**
     * @brief Get Spot, Future or Option Market Info object
     * 
     * @param market 
     * @return Json::Value 
     */
    virtual Json::Value GetMarketInfo(const std::string& market) = 0;

    /**
     * @brief Get the Spot Account Balances object
     * 
     * @param currencies 
     * @return flat_set<BalanceData> 
     */
    virtual flat_set<BalanceData> GetSpotAccountBalances(
        const std::set<std::string>& currencies) = 0;
    
    /**
     * @brief Get the Future Account Balances object
     * 
     * @param currencies 
     * @return flat_set<BalanceData> 
     */
    virtual flat_set<BalanceData> GetPerpetualAccountBalances(
        const std::set<std::string>& currencies) = 0;
    
    /**
     * @brief Get the Option Account Balances object
     * 
     * @param currencies 
     * @return flat_set<BalanceData> 
     */
    virtual flat_set<BalanceData> GetOptionAccountBalances( 
                    const std::set<std::string>& currencies) = 0;

    /**
     * @brief 
     * 
     * @param params 
     * @param payload 
     * @return true 
     * @return false 
     */
    virtual bool BuildNewOrder(const Json::Value &params, cpr::Payload& payload) = 0;
    virtual bool BuildNewOrder(const Json::Value &params, Json::Value& payload) = 0;

    /**
     * @brief build and send new spot order to exchange
     * 
     * @param params
     * @param isdummy - send test order
     * @return OrderData 
     */
    virtual OrderData NewSpotOrder(const Json::Value& params, bool isdummy=false) = 0;

    /**
     * @brief build and send new Perpetual/perpectual order to exchange
     * 
     * @param params 
     * @param isdummy - send test order
     * @return OrderData
     */
    virtual OrderData NewPerpetualOrder(const Json::Value& params, bool isdummy=false) = 0;

    /**
     * @brief build and send new option order to exchange
     * 
     * @param params 
     * @param isdummy - send test order
     * @return OrderData
     */
    virtual OrderData NewOptionOrder(const Json::Value& params, bool isdummy=false) = 0;

    /**
     * @brief place batch orders
     * 
     * @param params 
     * @return flat_set<OrderData> 
     */
    virtual flat_set<OrderData> NewSpotBatchOrders(const Json::Value& params) = 0;

    /**
     * @brief place batch orders
     * 
     * @param params 
     * @return flat_set<OrderData> 
     */
    virtual flat_set<OrderData> NewPerpetualBatchOrders(const Json::Value& params) = 0;

    /**
     * @brief Query Order from exchange
     * 
     * @param instrum 
     * @param id order Id
     * @param lid client Order Id
     * @return OrderData
     */
    virtual OrderData GetSpotOrder(const std::string& instrum, std::string id="", std::string lid="") = 0;
    virtual OrderData GetPerpetualOrder(const std::string& instrum, std::string id="", std::string lid="") = 0;
    virtual OrderData GetOptionOrder(const std::string& instrum, std::string id="", std::string lid="") = 0;

    /**
     * @brief Get all open orders
     * 
     * @return flat_set<OrderData> 
     */
    virtual flat_set<OrderData> GetPerpetualOpenOrders() = 0;

    /**
     * @brief 
     * 
     * @param instrum 
     * @param id order Id
     * @param lid client Order Id
     * @return true 
     * @return false 
     */
    virtual bool CancelSpotOrder(const std::string& instrum, std::string id="", std::string lid="") = 0;
    virtual bool CancelPerpetualOrder(const std::string& instrum, std::string id="", std::string lid="") = 0;
    virtual bool CancelOptionOrder(const std::string& instrum, std::string id="", std::string lid="") = 0;

    /**
     * @brief cancel open orders
     * 
     * @param params 
     * @return std::vector<StrPair> pair of instrum/orderId or empty to cancel all
     */
    virtual std::vector<StrPair> CancelSpotOrders(const std::vector<StrPair>& params) = 0;
    virtual std::vector<StrPair> CancelPerpetualOrders(const std::vector<StrPair>& params) = 0;
    virtual std::vector<StrPair> CancelOptionOrders(const std::vector<StrPair>& params) = 0;

    /**
     * @brief Get the Last Perpetual Trade object
     * 
     * @param instrum 
     * @param limit 
     * @return Json::Value 
     */
    virtual Json::Value GetLastPerpetualTrade(const std::string& instrum, int limit=1) = 0;

    /**
     * @brief Query Position from exchange
     * 
     * @param instrum 
     * @param lid client Order Id
     * @return flat_set<PositionData> 
     */
    virtual flat_set<PositionData> GetPerpetualPositions(const std::string& instrum, std::string lid="") = 0;
    
    /**
     * @brief Get the Option Position object
     * 
     * @param instrum 
     * @param lid client Order Id
     * @return flat_set<PositionData>  
     */
    virtual flat_set<PositionData> GetOptionPositions(const std::string& instrum, std::string lid="") = 0;

    /**
     * @brief thread to parse all incomming data using parser methods
     * 
     * @param messageQueue 
     * @param numThreads 
     * @return std::thread 
     */
    virtual std::thread StreamParser(MessageQueue& messageQueue, size_t numThreads=4) = 0;

    /**
     * @brief - send keep alive message to server at specified interval
     * 
     * @return std::thread 
     */
    virtual std::thread KeepAlive() = 0;

    /**
     * @brief 
     * 
     * @param queue 
     */
    virtual void BindTradesQueue(ConcurrentQueue<PriceData>* queue) = 0;
    virtual void BindCandlesQueue(ConcurrentQueue<CandleData>* queue) = 0;
    virtual void BindDepthQueue(ConcurrentQueue<Json::Value>* queue) = 0;
    virtual void BindTickerQueue(ConcurrentQueue<TickerData>* queue) = 0;
    virtual void BindOrderQueue(ConcurrentQueue<OrderData>* queue) = 0;
    virtual void BindPositionQueue(ConcurrentQueue<PositionData>* queue) = 0;

protected:
    /**
     * @brief parse incomming market data to unique format
     * 
     * @param data trades, candles, order book, positions, orders
     * @param tag the connection tag based on asset class [spot, swap, future, option]
     * @param timestamp current timespace in utc
     */
    virtual void TradesParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) = 0;
    virtual void CandlesParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) = 0;
    virtual void DepthParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) = 0;
    virtual void TickersParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) = 0;
    virtual void OrdersParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) = 0;
    virtual void PositionsParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) = 0;
};
}

#if defined(WIN32) || defined(_WIN32)
#define CONNECTOR_MODULE(classType, name, version)           \
    extern "C"                                               \
    {                                                        \
        __declspec(dllexport) stelgic::IExchange* Create()   \
        {                                                    \
            return new classType();                          \
        }                                                    \
                                                             \
        __declspec(dllexport) const char *Name()             \
        {                                                    \
            return name;                                     \
        }                                                    \
                                                             \
        __declspec(dllexport) const char *Version()          \
        {                                                    \
            return version;                                  \
        }                                                    \
    }

#else
#define CONNECTOR_MODULE(classType, name, version)           \
    extern "C"                                               \
    {                                                        \
        stelgic::IExchange* Create()                         \
        {                                                    \
            return new classType();                          \
        }                                                    \
                                                             \
        const char *Name()                                   \
        {                                                    \
            return name;                                     \
        }                                                    \
                                                             \
        const char *Version()                                \
        {                                                    \
            return version;                                  \
        }                                                    \
    }
#endif
