#pragma once

#include "public/IExchange.h"
#include "public/ConnHandler.h"
#include "public/AuthUtils.h"

namespace stelgic
{
class Bybit : public IExchange
{
public:
    Bybit(const Bybit &other) = default;
    Bybit &operator=(const Bybit &other) = default;

public:
    Bybit();
    virtual ~Bybit();

    void Init(const Json::Value& params, int logLevel, g3::LogWorker* logWorker) override;
    void Close() override;
    void Stop() override;
    void Reconnect() override;
    bool IsInitialized() override;
    bool IsOnline() override;
    bool IsRequestLimitHit() override;
    bool ResetRequestLimitTimer(int millis) override;
    void TestConnectivity() override;

    flat_set<Filter>& GetFilters() override;
    Json::Value& GetConfiguration() override;
    void* GetMessageQueue(const std::string& tag) override;

    ConnState Connect(const Json::Value &params) override;

    bool Subscribe(const std::string &key,
                   const std::string& market,
                   const Json::Value &symbols,
                   const Json::Value &channels,
                   std::string privacy="public") override;

    bool Subscribe(const Json::Value& params) override;
    bool Send(const std::string &key, const std::string &message) override;
    bool SendKeepAlive(const std::string &key) override;

    // get account details
    Json::Value GetMarketInfo(const std::string& assetClass) override;
    flat_set<BalanceData> GetSpotAccountBalances(const std::set<std::string>& currencies) override;
    flat_set<BalanceData> GetPerpetualAccountBalances(const std::set<std::string>& currencies) override;
    flat_set<BalanceData> GetOptionAccountBalances(const std::set<std::string>& currencies) override;

    // new orders
    bool BuildNewOrder(const Json::Value &params, cpr::Payload& payload) override;
    bool BuildNewOrder(const Json::Value &params, Json::Value& payload) override;
    OrderData NewSpotOrder(const Json::Value &params, bool isdummy=false) override;
    OrderData NewPerpetualOrder(const Json::Value &params, bool isdummy=false) override;
    OrderData NewOptionOrder(const Json::Value &params, bool isdummy=false) override;

    // place multiple orders
    flat_set<OrderData> NewSpotBatchOrders(const Json::Value& params) override;
    flat_set<OrderData> NewPerpetualBatchOrders(const Json::Value& params) override;

    OrderData GetSpotOrder(const std::string &instrum, std::string id="", std::string lid="") override;
    OrderData GetPerpetualOrder(const std::string& instrum, std::string id="", std::string lid="") override;
    OrderData GetOptionOrder(const std::string& instrum, std::string id="", std::string lid="") override;

    flat_set<OrderData> GetPerpetualOpenOrders() override;

    bool CancelSpotOrder(const std::string &instrum, std::string id="", std::string lid="") override;
    bool CancelPerpetualOrder(const std::string &instrum, std::string id="", std::string lid="") override;
    bool CancelOptionOrder(const std::string &instrum, std::string id="", std::string lid="") override;

    std::vector<StrPair> CancelSpotOrders(const std::vector<StrPair> &params) override;
    std::vector<StrPair> CancelPerpetualOrders(const std::vector<StrPair> &params) override;
    std::vector<StrPair> CancelOptionOrders(const std::vector<StrPair> &params) override;

    Json::Value GetLastPerpetualTrade(const std::string& instrum, int limit=1) override;

    // positions
    flat_set<PositionData> GetPerpetualPositions(const std::string &instrum, std::string lid="") override;
    flat_set<PositionData> GetOptionPositions(const std::string& instrum, std::string lid="") override;

    // live parsing thread
    std::thread StreamParser(MessageQueue& messageQueue, size_t numThreads=4) override;
    std::thread KeepAlive() override;

    // callbacks
    void BindTradesQueue(ConcurrentQueue<PriceData>* queue) override;
    void BindCandlesQueue(ConcurrentQueue<CandleData>* queue) override;
    void BindDepthQueue(ConcurrentQueue<Json::Value>* queue) override;
    void BindTickerQueue(ConcurrentQueue<TickerData>* queue) override;
    void BindOrderQueue(ConcurrentQueue<OrderData>* queue) override;
    void BindPositionQueue(ConcurrentQueue<PositionData>* queue) override;

protected:
    void InfoParser(const Json::Value &info);
    void TradesParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) override;
    void CandlesParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) override;
    void DepthParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) override;
    void TickersParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) override;
    void OrdersParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) override;
    void PositionsParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) override;
    void AuthenticationParser(const Json::Value& data, const std::string& tag, const std::time_t& ts);

    OrderData OrdersParserGet(const std::string& msg, const std::string& tag);
    flat_set<OrderData> BatchOrdersParserGet(const std::string& msg, const std::string& tag);
    flat_set<PositionData> PerpetualPositionParserGet(const std::string& msg, const std::string& tag);
    flat_set<PositionData> OptionPositionParserGet(const std::string& msg, const std::string& tag);
    
    bool CancelBatchOrders(const std::string& assetClass, const std::string& privacy, 
                        const std::string& querypath, cpr::Payload& payload);
    bool Authentication(const std::string& connKey, 
                        const std::string& assetClass, 
                        const std::string& privacy);

    // http actions
    void HttpCommon(const std::string &baseurl, const Json::Value& configs, 
                const std::string& function, cpr::Payload& payload, 
                const std::string& postData, cpr::Header& headers, bool signing=true);
    IntStrPair HttpPost(const Json::Value& configs, const std::string& tag, 
                    const std::string& function, cpr::Payload& payload, 
                    const std::string& postData, cpr::Header headers=cpr::Header{}, 
                    bool signing=true, std::string privacy="public");
    IntStrPair HttpGet(const Json::Value& configs, const std::string& tag, 
                    const std::string& function, cpr::Payload& payload, 
                    const std::string& postData, cpr::Header headers=cpr::Header{}, 
                    bool signing=true, std::string privacy="public");
    IntStrPair HttpPut(const Json::Value& configs, const std::string& tag, 
                    const std::string& function, cpr::Payload& payload, 
                    const std::string& postData, cpr::Header headers=cpr::Header{}, 
                    bool signing=true, std::string privacy="public");
    IntStrPair HttpDelete(const Json::Value& configs, const std::string& tag, 
                    const std::string& function, cpr::Payload& payload, 
                    const std::string& postData, cpr::Header headers=cpr::Header{}, 
                    bool signing=true, std::string privacy="public");
protected:
    long pingInterval;
    long recvWindow;
    long ORDERS_LIMIT;
    LiveState liveMode;
    time_t timestamp;
    
    Json::Value connParams;
    flat_set<Filter> filters;
    Json::Value paramMapping;
    
    size_t MAX_BATCH_ORDERS;
    std::atomic<long> REQUEST_LIMIT = {100};
    std::atomic<long> IP_LIMIT_COUNT = ATOMIC_FLAG_INIT;
    std::atomic<long> ORDER_LIMIT_COUNT = ATOMIC_FLAG_INIT;
    std::atomic_bool limitResetOn = ATOMIC_FLAG_INIT;

    std::atomic_bool exitThread = ATOMIC_FLAG_INIT;
    std::atomic<int> verbose = ATOMIC_FLAG_INIT;
    std::atomic_flag connFlag = ATOMIC_FLAG_INIT;

    // mapping position edge mode to LONG, SHORT, BOTH
    flat_map<int, std::string> edgeModesMap;

    // caching connection info
    flat_map<std::string, ConnHandler::ptr> connHdlPtrsMap;
    flat_map<std::string, std::vector<WebClient::connection_ptr>> connPtrsMap;

    // cache auth and subscrition channels
    flat_map<std::string, std::string> channelsMap;
    std::unordered_map<std::string, std::atomic_bool> authenticationMap;

    // cpr Session pool
    ConcurrentQueue<std::shared_ptr<cpr::Session>> sessionPool;

    // websocket
    WebClient endpoint;
    WebClient::timer_ptr resetTimer;
    websocketpp::lib::shared_ptr<websocketpp::lib::thread> wthread;
    std::vector<std::thread> workers;

    // add function to map for each event type to avoid if else
    typedef void (Bybit::*pfunct)(const Json::Value& data, const std::string& tag, const std::time_t& ts);
    flat_map<std::string, pfunct> dispatcherMap;

    // calbacks
    ConcurrentQueue<PriceData>* priceQueue;
    ConcurrentQueue<CandleData>* candleQueue;
    ConcurrentQueue<Json::Value>* depthQueue;
    ConcurrentQueue<TickerData>* tickerQueue;
    ConcurrentQueue<OrderData>* orderQueue;
    ConcurrentQueue<PositionData>* positionQueue;
};
}

