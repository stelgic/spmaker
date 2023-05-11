#include "Binance.h"
#include <g3log/g3log.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>

namespace stelgic
{
Binance::Binance() : recvWindow(60000), pingInterval(60000), 
    ORDERS_LIMIT(300), REQUEST_LIMIT(300)
{
    dispatcherMap["trade"] = (pfunct)&Binance::TradesParser;
    dispatcherMap["kline"] = (pfunct)&Binance::CandlesParser;
    dispatcherMap["depthUpdate"] = (pfunct)&Binance::DepthParser;
    dispatcherMap["bookTicker"] = (pfunct)&Binance::TickersParser;
    dispatcherMap["ORDER_TRADE_UPDATE"] = (pfunct)&Binance::OrdersParser;
    dispatcherMap["ACCOUNT_UPDATE"] = (pfunct)&Binance::PositionsParser;
    dispatcherMap["listenKeyExpired"] = (pfunct)&Binance::ListenKeyParser;

    timestamp = 0;
    MAX_BATCH_ORDERS = 5;
    liveMode = LiveState::Stopped;
}

Binance::~Binance() 
{
    Close();

    for(auto& worker: workers)
        worker.join();
}

void Binance::Init(const Json::Value& params, int logLevel)
{
    connParams = params;
    verbose = logLevel;
        
    liveMode = LiveState::Started;
    pingInterval = connParams.get("pingInterval", 1800000).asInt64();

    endpoint.clear_access_channels(websocketpp::log::alevel::all);
    endpoint.clear_error_channels(websocketpp::log::elevel::all);
    endpoint.get_elog().set_channels(websocketpp::log::elevel::rerror);
    endpoint.get_elog().set_channels(websocketpp::log::elevel::fatal);

    endpoint.init_asio();
    endpoint.start_perpetual();    
    wthread = websocketpp::lib::make_shared<websocketpp::lib::thread>(&WebClient::run, &endpoint);

    int numSession = connParams.get("numSessions", 4).asInt();
    for(int i=0; i < numSession; ++i)
        sessionPool.enqueue(std::make_shared<cpr::Session>());

    for(const Json::Value& item: connParams["websocket"]["private"]["subscribe"])
    {
        Json::Value info = GetMarketInfo(item.asString());
        if(!info.isNull())
            InfoParser(info);
    }
}

void Binance::Close()
{    
    if(liveMode == LiveState::Stopped)
        return;

    endpoint.stop_perpetual();
    for(auto& item: connPtrsMap)
    {
        for(auto& conPtr: item.second)
        {
            endpoint.close(
                conPtr->get_handle(), 
                websocketpp::close::status::normal,  
                "connection closed");
        }
    }

    connHdlPtrsMap.clear();
    connPtrsMap.clear();

    liveMode = LiveState::Stopped;
}

bool Binance::IsInitialized()
{
    return liveMode == LiveState::Started || liveMode == LiveState::Running;
}

void Binance::Stop()
{ 
    exitThread = {1};
}

void Binance::Reconnect()
{
    connFlag.test_and_set(std::memory_order_release);

    for(auto& entry: connHdlPtrsMap)
    {
        if(entry.second->GetStatus() != ConnState::Opening &&
            entry.second->GetStatus() != ConnState::Opened)
        {
            LOG_IF(WARNING, verbose > 0) << "Reconnecting ...";
            endpoint.connect(entry.second->GetConnection());
        }
    }
    connFlag.clear(std::memory_order_acquire); // release
}

bool Binance::IsOnline()
{
    return liveMode == LiveState::Running;
}

bool Binance::IsRequestLimitHit()
{
    return (ORDERS_LIMIT - ORDER_LIMIT_COUNT ) <= 50 || (REQUEST_LIMIT - IP_LIMIT_COUNT) <= 1;
}

bool Binance::ResetRequestLimitTimer(int millis)
{
    if(!limitResetOn)
    {
        limitResetOn = {1};
        resetTimer = endpoint.set_timer(millis, websocketpp::lib::bind(
                        [this](websocketpp::lib::error_code const & ec)
                        {
                            ORDER_LIMIT_COUNT = {0};
                            IP_LIMIT_COUNT = {0};
                            limitResetOn = {0};
                            LOG_IF(INFO, verbose > 0) << "Request limit lifted!";
                        },
                        websocketpp::lib::placeholders::_1));
    }

    return limitResetOn;
}

void Binance::TestConnectivity()
{
    ConnHandler::ptr connHdlPtr = nullptr;
    for(auto& item: connHdlPtrsMap)
    {
        if(item.first == "public")
            connHdlPtr = item.second;
    }

    if(connHdlPtr == nullptr)
        connHdlPtr = connHdlPtrsMap.begin()->second;

    size_t i = 0;
    size_t pingCount = 100;
    std::vector<std::pair<int64_t,int64_t>> timeTracker;
    timeTracker.reserve(pingCount);

    while(!exitThread && connHdlPtr && i < pingCount)
    {
        int64_t pingSendTime = Utils::GetMilliseconds();
        endpoint.ping(connHdlPtr->GetHandler(), "0x9");

        while(connHdlPtr->GetPongRecvTime() < pingSendTime);
        timeTracker.emplace_back(pingSendTime, connHdlPtr->GetPongRecvTime().load());   
        ++i;
    }

    double avg = 0.0;
    int64_t maxDelay = 0;
    pingCount = timeTracker.size();
    for(const auto& item: timeTracker)
    {
        int64_t diff = (item.second - item.first);
        avg += diff;
        maxDelay = std::max(maxDelay, diff);
    }

    avg /= pingCount;

    std::stringstream oss;
    oss << "averageDealy=" << avg << " ms"
        << "\tmaxDealy=" << maxDelay << " ms"
        << "\tpingCount=" << pingCount;

    LOG(INFO) << "***Client Server Ping/Pong***";
    LOG(INFO) << oss.str();
}

Json::Value& Binance::GetConfiguration()
{
    return connParams;
}

void* Binance::GetMessageQueue(const std::string& tag)
{
    return nullptr;
}

ConnState Binance::Connect(const Json::Value& params)
{
    ConnState conState;
    if(!params.isMember("websocket"))
    {
        LOG_IF(WARNING, verbose > 0) << "Missing websocket params in binance!";
        return ConnState::Failed;
    }

    // set secure connection
    endpoint.set_tls_init_handler(&ConnHandler::onInitTLS);

    for(const std::string& privacy: params["websocket"].getMemberNames())
    {
        // TODO: connect to spot, future or option
        const auto& data = params["websocket"][privacy];
        for(const auto& item: data["subscribe"])
        {
            std::string assetClass = item.asString();
            std::string url = data[assetClass].asString();

            std::string connKey(privacy);
            connKey.append("_").append(assetClass);
            // subscribe to user data stream if private endpoint
            if(privacy == "private")
            {
                if(!GetListenKey(assetClass, privacy))
                    return ConnState::Failed;
                
                std::string listenKey = listenKeys.at(connKey);
                url.append("/").append(listenKey);
            }

            LOG_IF(INFO, verbose > 1) << "Connecting to " 
                << privacy << " " << assetClass << " " << url;

            websocketpp::lib::error_code ec;
            WebClient::connection_ptr con = endpoint.get_connection(url, ec);

            if (ec) {
                LOG_IF(WARNING, verbose > 0) << "> Connect initialization error: " << ec.message();
                return ConnState::Invalid;
            }

            ConnHandler::ptr connHdlPtr = websocketpp::lib::make_shared<ConnHandler>(
                                                con, con->get_handle(), url, assetClass);
            
            connHdlPtrsMap.insert_or_assign(connKey, connHdlPtr);

            con->set_open_handler(websocketpp::lib::bind(
                &ConnHandler::onOpen,
                connHdlPtr,
                &endpoint,
                websocketpp::lib::placeholders::_1
            ));
            con->set_fail_handler(websocketpp::lib::bind(
                &ConnHandler::onFail,
                connHdlPtr,
                &endpoint,
                websocketpp::lib::placeholders::_1
            ));
            con->set_close_handler(websocketpp::lib::bind(
                &ConnHandler::onClose,
                connHdlPtr,
                &endpoint,
                websocketpp::lib::placeholders::_1
            ));
            con->set_message_handler(websocketpp::lib::bind(
                &ConnHandler::onMessage,
                connHdlPtr,
                websocketpp::lib::placeholders::_1,
                websocketpp::lib::placeholders::_2
            ));
            con->set_ping_handler(websocketpp::lib::bind(
                &ConnHandler::onPing,
                connHdlPtr,
                &endpoint,
                websocketpp::lib::placeholders::_1
            ));
            con->set_pong_handler(websocketpp::lib::bind(
                &ConnHandler::onPong,
                connHdlPtr,
                &endpoint,
                websocketpp::lib::placeholders::_1
            ));
            con->set_pong_timeout_handler(websocketpp::lib::bind(
                &ConnHandler::onPongTimeout,
                connHdlPtr,
                &endpoint,
                websocketpp::lib::placeholders::_1
            ));

            unsigned int numThreads = 4;
            if(privacy.find("public"))
                numThreads = std::max(numThreads, std::thread::hardware_concurrency()-4);

            workers.push_back(StreamParser(connHdlPtr->GetQueue(), numThreads));

            // set header api expire date
            std::stringstream ssexpire;
            ssexpire << Utils::GetSeconds(24*3600);
            con->replace_header("timestamp", ssexpire.str());
            
            // set header api signature
            std::string query = url;
            size_t pos = url.find_last_of('?');
            if(pos != url.npos)
                query = url.substr(pos+1);

            const Json::Value& secrets = params["secrets"];
            if(privacy == "private")
            {
                std::string apisecret = secrets[assetClass][privacy].get("apisecret", "").asString();
                std::string signature = AuthUtils::GetSignature(apisecret, query);
                con->replace_header("signature", signature);
            }
            
            // set header api key
            std::string apikey = secrets[assetClass][privacy].get("apikey", "").asString();
            con->replace_header("X-MBX-APIKEY", apikey);
            con->replace_header("Accept-Encoding", "gzip,deflate,zlib");

            endpoint.connect(con);
            if(connPtrsMap.count(privacy) == 0)
                connPtrsMap[privacy] = {};
            connPtrsMap.at(privacy).push_back(con);

            // wait for connection status
            conState = connHdlPtr->GetStatus();
            while(conState != ConnState::Opened && 
                conState != ConnState::Failed && 
                conState != ConnState::Closed)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                conState = connHdlPtr->GetStatus();
            }

            if(conState == ConnState::Failed || conState == ConnState::Closed)
            {
                LOG_IF(WARNING, verbose > 0) << "Connection failed " 
                                                        << assetClass << " " << url;
                return conState;
            }

            LOG_IF(INFO, verbose > 2) << "Connected to " << privacy 
                                                << " " << assetClass << " " << url;
        }
    }

    return conState;
}

bool Binance::Send(const std::string& key, const std::string& message)
{
    websocketpp::lib::error_code ec;
    
    if (connHdlPtrsMap.at(key)->GetStatus() != ConnState::Opened) {
        LOG_IF(WARNING, verbose > 0) << "ERROR: Disconnected!\n";
        return false;
    }
    
    endpoint.send(connHdlPtrsMap.at(key)->GetHandler(), 
                message, websocketpp::frame::opcode::text, ec);
    if (ec) 
    {
        LOG_IF(WARNING, verbose > 0) << "ERROR: " << ec.message() << "\n";
        return false;
    }
    return true;
}

bool Binance::Subscribe(const std::string& key, 
    const std::string& market, const Json::Value& symbols, 
    const Json::Value& channels, std::string privacy)
{
    LOG_IF(INFO, verbose > 0) << "Subscribing to Binance " << privacy << " channels...";
    int num = 0;
    for(const auto& member: channels)
    {
        bool success = false;
        std::string interval;
        std::stringstream sstopics;

        Json::StreamWriterBuilder builder;
        Json::Value payload;
        
        builder["indentation"] = "";
        payload["method"] = "SUBSCRIBE";
        payload["id"] = std::time(nullptr);
        payload["params"] = Json::Value(Json::arrayValue);

        if(privacy == "public")
        {
            std::string channel = member.asString();
            if(channelsMap.count(channel) != 0)
            {
                sstopics << channelsMap.at(channel);
            }
            else
                sstopics << channel;

            LOG_IF(INFO, verbose > 2) << "Subscribe to " << key << " " << sstopics.str();
            
            for(const auto& symbol: symbols)
            {
                std::string name(symbol.asString());
                std::stringstream sstag;
                std::transform(name.begin(), name.end(), name.begin(), ::tolower);

                sstag << name << "@" << sstopics.str();
                payload["params"].append(sstag.str());
                success = true;
            }
        }
        else
        {
            std::string channel = member.asString();
            payload["params"].append(channel);
            success = true;
        }

        if(success)
        {
            std::string msg(Json::writeString(builder, payload));
            LOG_IF(INFO, verbose > 1) << "SUBSCRIBE: " << msg;
            num += Send(key, msg);
        }
    }
    
    return num > 0;
}

bool Binance::Subscribe(const Json::Value& params)
{
    int i = 0;
    for(const std::string& privacy: connParams["websocket"].getMemberNames())
    {
        const auto& tag = connParams["websocket"][privacy];
        for(const auto& item: tag["subscribe"])
        {
            std::string assetClass = item.asString();
            std::string connKey = privacy;
            connKey.append("_").append(assetClass);
            ConnState connState = connHdlPtrsMap.at(connKey)->GetStatus();
            
            if(connState == ConnState::Opened && privacy == "public")
            {
                if (connState == ConnState::Opened && privacy == "public" &&
                    Subscribe(connKey, assetClass, tag["instruments"], tag["channels"]))
                {
                    ++i;
                }
            }
        }
    }
    return i > 0;
}

bool Binance::SendKeepAlive(const std::string& key)
{
    bool success = false;
    try
    {
        if(key.find("private") != key.npos)
        {
            std::string path;
            cpr::Payload payload{};
            std::string postData;
            cpr::Header headers{};
            std::string privacy("public");
            std::string assetClass("spot");

            if(key.find("private") != key.npos)
                privacy = "private";

            int pos = key.find(privacy);
            if(pos != key.npos)
                assetClass = key.substr(privacy.length()+1);
                        
            if(assetClass == "future")
                path = "fapi/v1/listenKey";
            else if(assetClass == "option")
                path = "eapi/v1/listenKey";
            else
            {
                path = "api/v3/userDataStream";
                payload.AddPair({"listenKey", listenKeys.at(key)});
            }

            endpoint.ping(connHdlPtrsMap.at(key)->GetHandler(), "0x9");

            std::pair<int,std::string> response = HttpPut(connParams, assetClass, 
                                                        path, payload, postData, 
                                                        headers, false, privacy);
            if(response.first == 200)
                success = true;
            else
                LOG_IF(WARNING, verbose > 0) << response.second;
        }
    }
    catch(websocketpp::exception& e)
    {
        LOG_IF(WARNING, verbose > 0) << "KeepAlive: " << e.what();
    }
    return success;
}

std::thread Binance::KeepAlive()
{
    return std::thread([this]()
    {
        int64_t idleTime = 60;
        int64_t pingTime = pingInterval;
        auto start = std::chrono::system_clock::now();
        while(!exitThread)
        {
            std::this_thread::sleep_for(std::chrono::seconds(idleTime));

            bool success = false;
            auto now = std::chrono::system_clock::now();
            int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();

            connFlag.test_and_set(std::memory_order_release);

            // send keep alive for all private connections
            for(auto& item: connHdlPtrsMap)
            {
                try
                {
                    ConnState state = item.second->GetStatus();
                    if(state == ConnState::Opened)
                    {
                        if(elapsed >= pingInterval)
                        {
                            success = SendKeepAlive(item.first);
                            pingTime = pingInterval;
                            start = now;
                        }

                        // prevent socket closing silente if no data received for a while
                        if(item.first.find("private") != item.first.npos)
                        {
                            item.second->GetConnection()->ping("");
                        }
                    }

                    // auto reconnect
                    if(item.second->GetStatus() == ConnState::Abnormal)
                    {
                        LOG_IF(INFO, verbose > 0) << "Attemp to reconnect " << item.second->GetUrl();
                        endpoint.connect(item.second->GetConnection());
                        pingTime = 15000;

                        if(item.first.find("public") != item.first.npos)
                        {
                            Subscribe(connParams);
                        }
                    }
                }
                catch(const websocketpp::exception& e)
                {
                    LOG_IF(WARNING, verbose > 0) << e.what();
                    endpoint.close(item.second->GetConnection(), 
                        websocketpp::close::status::abnormal_close,  e.what());

                    idleTime = 5;
                }
            }

            connFlag.clear(std::memory_order_acquire); // release
        }
    });
}

void Binance::HttpCommon(
    const std::string &baseurl, const Json::Value& configs, 
    const std::string& function, cpr::Payload& payload, 
    const std::string& postData, cpr::Header& headers, bool signing)
{
    int64_t epoch = Utils::GetMilliseconds(0);
    std::string nonce = Utils::GetUrandom(8);

    headers.emplace("X-MBX-APIKEY", configs["apikey"].asString());
    headers.emplace("Content-Type","application/x-www-form-urlencoded;charset=UTF-8");
        
    if(signing)
    {
        payload.AddPair({"recvWindow", std::to_string(recvWindow)});
        payload.AddPair({"timestamp", std::to_string(epoch)});

        std::string content = payload.content;
        std::string signature = AuthUtils::GetSignature(
            configs["apisecret"].asString(), content);
            
        payload.AddPair({"signature", signature});
    }
}

IntStrPair Binance::HttpPost(const Json::Value& configs, 
    const std::string& tag, const std::string& function, 
    cpr::Payload& payload, const std::string& postData, 
    cpr::Header headers, bool signing, std::string privacy)
{
    std::string url = "/" + function;
    std::string baseurl(configs["http"][privacy][tag].asString());
    const Json::Value& secrets = configs["secrets"][privacy][tag];

    std::shared_ptr<cpr::Session> session;
    while(!exitThread && !sessionPool.try_dequeue(session)); // spin until get sessions

    HttpCommon(baseurl, secrets, function, payload, postData, headers, signing);
    std::string content = payload.content;
    std::string dataPost = postData;
    if(postData.empty())
        dataPost.append(content);

    headers.emplace("Accept-Encoding", "gzip,deflate,zlib");

    session->SetUrl({baseurl + url});
    session->SetOption(cpr::Body(content));
    session->SetVerifySsl(cpr::VerifySsl(false));
    session->SetHeader(headers);

    // post to exchange
    cpr::Response r = session->Post();
    sessionPool.enqueue(session);

    if(r.header.count("X-MBX-USED-WEIGHT-1M"))
        IP_LIMIT_COUNT.store(std::stol(r.header["X-MBX-USED-WEIGHT-1M"]));
    if(r.header.count("X-MBX-ORDER-COUNT-1M"))
        ORDER_LIMIT_COUNT.store(std::stol(r.header["X-MBX-ORDER-COUNT-1M"]));

    if(r.status_code == 429)
        IP_LIMIT_COUNT = REQUEST_LIMIT;

    LOG_IF(INFO, verbose > 1) << "POST: " 
        << "POST: " << baseurl + url << "?" 
        << cpr::Body(dataPost) << "\n"
        << r.status_code 
        << " X-MBX-USED-WEIGHT=" << IP_LIMIT_COUNT
        << " X-MBX-ORDER-COUNT=" << ORDER_LIMIT_COUNT;

    return  std::make_pair(r.status_code, r.text);
}

IntStrPair Binance::HttpGet(
    const Json::Value& configs, 
    const std::string& tag, const std::string& function, 
    cpr::Payload& payload, const std::string& postData, 
    cpr::Header headers, bool signing, std::string privacy)
{
    std::string url = "/" + function;
    std::string baseurl(configs["http"][privacy][tag].asString());
    const Json::Value& secrets = configs["secrets"][privacy][tag];

    std::shared_ptr<cpr::Session> session;
    while(!exitThread && !sessionPool.try_dequeue(session)); // spin until get session

    HttpCommon(baseurl, secrets, function, payload, postData, headers, signing);

    url = "/" + function + ((payload.content != "") ? "?" + payload.content : "");
    std::string postBody ;

    session->SetUrl({baseurl + url});
    session->SetOption(cpr::Body(postBody));
    session->SetVerifySsl(cpr::VerifySsl(false));
    session->SetHeader(headers);

    // get to exchange
    cpr::Response r = session->Get();
    sessionPool.enqueue(session);

    if(r.header.count("X-MBX-USED-WEIGHT-1M"))
        IP_LIMIT_COUNT.store(std::stol(r.header["X-MBX-USED-WEIGHT-1M"]));
    if(r.header.count("X-MBX-ORDER-COUNT-1M"))
        ORDER_LIMIT_COUNT.store(std::stol(r.header["X-MBX-ORDER-COUNT-1M"]));

    LOG_IF(INFO, verbose > 1) 
        << "GET: " << baseurl + url << "\n"
        << r.status_code << " " << r.header["content-type"];

    return  std::make_pair(r.status_code, r.text);
}

IntStrPair Binance::HttpPut(
    const Json::Value& configs, 
    const std::string& tag, const std::string& function, 
    cpr::Payload& payload, const std::string& postData, 
    cpr::Header headers, bool signing, std::string privacy)
{
    std::string url = "/" + function;
    std::string baseurl(configs["http"][privacy][tag].asString());
    const Json::Value& secrets = configs["secrets"][privacy][tag];

    std::shared_ptr<cpr::Session> session;
    while(!exitThread && !sessionPool.try_dequeue(session)); // spin until get session

    HttpCommon(baseurl, secrets, function, payload, postData, headers, signing);

    std::string postBody = payload.content;
    
    session->SetUrl({baseurl + url});
    session->SetOption(cpr::Body(postBody));
    session->SetVerifySsl(cpr::VerifySsl(false));
    session->SetHeader(headers);

    // put to exchange
    cpr::Response r = session->Put();
    sessionPool.enqueue(session);

    if(r.header.count("X-MBX-USED-WEIGHT-1M"))
        IP_LIMIT_COUNT.store(std::stol(r.header["X-MBX-USED-WEIGHT-1M"]));
    if(r.header.count("X-MBX-ORDER-COUNT-1M"))
        ORDER_LIMIT_COUNT.store(std::stol(r.header["X-MBX-ORDER-COUNT-1M"]));

    LOG_IF(INFO, verbose > 1)
        << "PUT: " << baseurl + url << "?" << cpr::Body(postBody) <<  "\n"
        << r.status_code << " " << r.header["content-type"];

    return  std::make_pair(r.status_code, r.text);
}

IntStrPair Binance::HttpDelete(
    const Json::Value& configs, 
    const std::string& tag, const std::string& function, 
    cpr::Payload& payload, const std::string& postData, 
    cpr::Header headers, bool signing, std::string privacy)
{
    std::string url = "/" + function;
    std::string baseurl(configs["http"][privacy][tag].asString());
    const Json::Value& secrets = configs["secrets"][privacy][tag];

    std::shared_ptr<cpr::Session> session;
    while(!exitThread && !sessionPool.try_dequeue(session)); // spin until get session

    headers.emplace("Accept-Encoding", "gzip,deflate,zlib");

    HttpCommon(baseurl, secrets, function, payload, postData, headers, signing);

    url = "/" + function + ((payload.content != "") ? "?" + payload.content : "");
    std::string postBody ;

    session->SetUrl({baseurl + url});
    session->SetOption(cpr::Body(postBody));
    session->SetVerifySsl(cpr::VerifySsl(false));
    session->SetHeader(headers);

    // delete to exchange
    cpr::Response r = session->Delete();
    sessionPool.enqueue(session);

    if(r.header.count("X-MBX-USED-WEIGHT-1M"))
        IP_LIMIT_COUNT.store(std::stol(r.header["X-MBX-USED-WEIGHT-1M"]));
    if(r.header.count("X-MBX-ORDER-COUNT-10S"))
        ORDER_LIMIT_COUNT.store(std::stol(r.header["X-MBX-ORDER-COUNT-10S"]));

    LOG_IF(INFO, verbose > 1) 
        << "DELETE: " << baseurl + url << "\n"
        << r.status_code << r.header["content-type"];

    return  std::make_pair(r.status_code, r.text);
}

Json::Value Binance::GetMarketInfo(const std::string& assetClass)
{
    // parse response
    std::string errs;
    Json::Value data;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    cpr::Payload payload{};
    std::string postData;
    std::string querypath("api/v3/exchangeInfo");
    if(assetClass == "future")
        querypath = "fapi/v1/exchangeInfo";
    else if(assetClass == "option")
        querypath = "eapi/v1/exchangeInfo";
        
    auto response = HttpGet(connParams, assetClass, querypath, payload, postData);
    if(response.first == 200)
    {
        const std::string& msg = response.second;
        reader->parse(msg.c_str(), msg.c_str() + msg.size(),&data, &errs);
    }
    else
        LOG_IF(WARNING, verbose > 0) << response.second;

    return data;
}

flat_set<Filter>& Binance::GetFilters()
{
    return filters;
}

bool Binance::GetListenKey(const std::string& assetClass, const std::string& privacy, bool keepAlive)
{
    bool success = false;
    std::string path;
    cpr::Payload payload{};
    std::string postData;
    cpr::Header headers{};

    if(assetClass == "future")
        path = "fapi/v1/listenKey";
    else if(assetClass == "option")
        path = "eapi/v1/listenKey";
    else
        path = "api/v3/userDataStream";

    std::string key(privacy);
    key.append("_").append(assetClass);
    if(listenKeys.count(key) && !keepAlive)
    {
        auto response = HttpDelete(connParams, assetClass, path, payload, postData, headers, true, privacy);
        if(response.first != 200)
            LOG_IF(WARNING, verbose > 2) << "ERROR: " << response.second;
        else
            std::this_thread::sleep_for(std::chrono::seconds(15));
    }

    auto response = HttpPost(connParams, assetClass, path, payload, postData, headers, true, privacy);
    if(response.first != 200)
    {
        LOG_IF(WARNING, verbose > 1) << "ERROR: " << response.second;
        return success;
    }

    std::string errs;
    Json::Value data;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    const std::string& msg = response.second;
    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&data, &errs))
    {
        if(data.isMember("listenKey"))
        {
            std::string listenKey = data["listenKey"].asString();
            listenKeys.emplace(key, listenKey);
            success = true;
        }
    }

    return success;
}
    
flat_set<BalanceData> Binance::GetSpotAccountBalances(
    const std::set<std::string>& currencies)
{
    BalanceData balance;
    flat_set<BalanceData> balances;

    Json::Value data;
    cpr::Payload payload{}; 
    std::string postData;
    const std::string tag("spot");
    const std::string querypath("api/v3/balance");
    
    auto response = HttpGet(connParams, tag, querypath, payload, postData);

    if(response.first != 200)
    {
        LOG_IF(WARNING, verbose > 2) << response.second;
        return balances;
    }
    
    // parse response
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());
    
    try
    {
        const std::string& msg = response.second;
        if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&data, &errs))
        {
            if(data.isMember("balances"))
            {
                for(Json::Value& item: data["balances"])
                {
                    balance.exchange = "binance";
                    balance.asset = item["asset"].asString();
                    balance.available = std::stod(item["free"].asString());
                    balance.locked = std::stod(item["locked"].asString());
                    balances.insert(balance);
                }
            }
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return balances;
}

flat_set<BalanceData> Binance::GetPerpetualAccountBalances(
    const std::set<std::string>& currencies)
{
    BalanceData balance;
    flat_set<BalanceData> balances;

    Json::Value data;
    cpr::Payload payload{};
    std::string postData; 
    const std::string tag("future");
    const std::string querypath("fapi/v2/balance");
    
    auto response = HttpGet(connParams, tag, querypath, payload, postData);
    if(response.first != 200)
    {
        LOG_IF(WARNING, verbose > 2) << response.second;
        return balances;
    }

    // parse response
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    try
    {
        const std::string& msg = response.second;
        if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&data, &errs))
        {
            for(Json::Value& item: data)
            {
                balance.exchange = "binance";
                balance.asset = item["asset"].asString();
                balance.available = std::stod(item["availableBalance"].asString());
                balance.locked = std::stod(item["balance"].asString()) - balance.available;
                balance.unrealizedPNL = std::stod(item["crossUnPnl"].asString());
                balances.insert(balance);
            }
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }      

    return balances;
}

flat_set<BalanceData> Binance::GetOptionAccountBalances(
    const std::set<std::string>& currencies)
{
    BalanceData balance;
    flat_set<BalanceData> balances;
    
    Json::Value data;
    cpr::Payload payload{};
    std::string postData; 
    const std::string tag("option");
    const std::string querypath("eapi/v1/account");
    
    auto response = HttpGet(connParams, tag, querypath, payload, postData);
    if(response.first != 200)
    {
        LOG_IF(WARNING, verbose > 2) << response.second;
        return balances;
    }
        
    // parse response
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    try
    {
        const std::string& msg = response.second;
        if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&data, &errs))
        {
            if(data.isMember("asset"))
            {
                for(const Json::Value& item: data["asset"])
                {
                    balance.exchange = "binance";
                    balance.asset = item["asset"].asString();
                    balance.available = std::stod(item["available"].asString());
                    balance.locked = std::stod(item["locked"].asString());
                    balance.marginBalance = std::stod(item["marginBalance"].asString());
                    balance.unrealizedPNL = std::stod(item["unrealizedPNL"].asString());
                    balances.insert(balance);
                }
            }
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return balances;
}

bool Binance::BuildNewOrder(const Json::Value &params, cpr::Payload& payload)
{
    bool success = false;
    try
    {
        Filter filter;
        filter.instrum = params["instrum"].asString();
        auto iter = filters.find(filter);
        if(iter != filters.end())
        {
            std::string side = params["side"].asString();

            // might throw execption if not found
            filter = *iter;
            double price = params.get("price", 0.0).asDouble();
            price -= std::remainder(price,filter.tickSize);
            //price = (side == "BUY") ? price - filter.tickSize : price + filter.tickSize; // attemp second bid / ask
            std::stringstream ssp;
            ssp.setf(std::ios::fixed);
            ssp.precision(filter.pxPrecision); 
            ssp << price;

            double stopPrice = params.get("stopPrice", 0.0).asDouble();
            std::stringstream sspl;
            sspl.setf(std::ios::fixed);
            sspl.precision(filter.pxPrecision); 
            sspl << stopPrice;

            double profitPrice = params.get("profitPrice", 0.0).asDouble();
            std::stringstream sstp;
            sstp.setf(std::ios::fixed);
            sstp.precision(filter.pxPrecision); 
            sstp << profitPrice;
            
            double quantity = params.get("quantity", 0.0).asDouble();
            quantity -= std::remainder(quantity, filter.stepSize);
            std::stringstream ssq;
            ssq.setf(std::ios::fixed);
            ssq.precision(filter.pxPrecision);
            ssq << quantity;

            std::string orderType = params.get("orderType", "LIMIT").asString();
            std::transform(orderType.begin(), orderType.end(), orderType.begin(), ::toupper);

            payload.AddPair({"symbol", params["instrum"].asString()});
            payload.AddPair({"side", params["side"].asString()});
            payload.AddPair({"type", orderType});
            payload.AddPair({"timeInForce", params.get("timeInForce","GTC").asString()});        
                        
            if(orderType != "MARKET")
            {
                payload.AddPair({"price", ssp.str()});
                if(stopPrice > 0)
                    payload.AddPair({"stopPrice", sspl.str()});
                if(profitPrice > 0)
                    payload.AddPair({"profitPrice", sstp.str()});
            }

            if(params.isMember("clOrderId") && !params["clOrderId"].asString().empty())
                payload.AddPair({"newClientOrderId", params["clOrderId"].asString()});

            if(params.isMember("marginMode") && !params["marginMode"].asString().empty())
                payload.AddPair({"marginType", params["marginMode"].asString()});

            if(params.get("closePosition", false).asBool())
            {
                payload.AddPair({"closePosition", "true"});
            }
            else
            {
                if(params.get("reduceOnly", false).asBool())
                    payload.AddPair({"reduceOnly", "true"});

                if(params.get("postOnly", false).asBool())
                    payload.AddPair({"postOnly", "true"});

                payload.AddPair({"quantity", ssq.str()});
            }


            success = true;
        }
        else
            LOG_IF(WARNING, verbose > 0) << "Could not find asset filter " << filter.instrum;
    }
    catch(const std::exception& e)
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(WARNING, verbose > 0) 
            << e.what() << "\n" << Json::writeString(builder, params);
    }

    return success;
}

bool Binance::BuildNewOrder(const Json::Value &params, Json::Value& payload)
{
    bool success = false;
    try
    {
        Filter filter;
        filter.instrum = params["instrum"].asString();
        auto iter = filters.find(filter);
        if(iter != filters.end())
        {
            std::string side = params["side"].asString();

            // might throw execption if not found
            filter = *iter;
            double price = params.get("price", 0.0).asDouble();
            price -= std::remainder(price,filter.tickSize);
            //price = (side == "BUY") ? price - filter.tickSize : price + filter.tickSize; // attemp second bid / ask
            std::stringstream ssp;
            ssp.setf(std::ios::fixed);
            ssp.precision(filter.pxPrecision); 
            ssp << price;

            double stopPrice = params.get("stopPrice", 0.0).asDouble();
            std::stringstream sspl;
            sspl.setf(std::ios::fixed);
            sspl.precision(filter.pxPrecision); 
            sspl << stopPrice;

            double profitPrice = params.get("profitPrice", 0.0).asDouble();
            std::stringstream sstp;
            sstp.setf(std::ios::fixed);
            sstp.precision(filter.pxPrecision); 
            sstp << profitPrice;
            
            double quantity = params.get("quantity", 0.0).asDouble();
            quantity -= std::remainder(quantity, filter.stepSize);
            std::stringstream ssq;
            ssq.setf(std::ios::fixed);
            ssq.precision(filter.pxPrecision);
            ssq << quantity;

            std::string orderType = params.get("orderType", "LIMIT").asString();
            std::transform(orderType.begin(), orderType.end(), orderType.begin(), ::toupper);

            payload["symbol"] = params["instrum"].asString();
            payload["side"] = params["side"].asString();
            payload["type"] = orderType;
            payload["timeInForce"] = params.get("timeInForce","GTC").asString();        
                        
            if(orderType != "MARKET")
            {
                payload["price"] = ssp.str();
                if(stopPrice > 0)
                    payload["stopPrice"] = sspl.str();
                if(profitPrice > 0)
                    payload["profitPrice"] = sstp.str();
            }

            if(params.isMember("clOrderId") && !params["clOrderId"].asString().empty())
                payload["newClientOrderId"] = params["clOrderId"].asString();

            if(params.isMember("marginMode") && !params["marginMode"].asString().empty())
                payload["marginType"] = params["marginMode"].asString();

            if(params.get("closePosition", false).asBool())
            {
                payload["closePosition"] = "true";
            }
            else
            {
                if(params.get("reduceOnly", false).asBool())
                    payload["reduceOnly"] = "true";

                if(params.get("postOnly", false).asBool())
                    payload["postOnly"] = "true";

                payload["quantity"] = ssq.str();
            }

            success = true;
        }
        else
            LOG_IF(WARNING, verbose > 0) << "Could not find asset filter " << filter.instrum;
    }
    catch(const std::exception& e)
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(WARNING, verbose > 0) 
            << e.what() << "\n" << Json::writeString(builder, params);
    }

    return success;
}

OrderData Binance::NewSpotOrder(const Json::Value& params, bool isdummy) 
{
    OrderData ordData;
    ordData.exchange = "binance";
    ordData.assetClass = "spot";
    std::string privacy("private");
    try
    {
        // build spot order and send to exchange
        std::string querypath("api/v3/order");
        if(isdummy)
            querypath.append("/test");
        
        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData; 
        if(!BuildNewOrder(params, payload))
        {
            LOG_IF(WARNING, verbose > 2) << "NewSpotOrder failed!";
            return ordData;
        }
        auto response = HttpPost(connParams, ordData.assetClass, querypath,
                                payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 2) << response.second;
            return ordData;
        }

        // parse response 
        ordData = OrdersParserGet(response.second, ordData.assetClass);
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }
    
    return ordData;
}

OrderData Binance::NewPerpetualOrder(const Json::Value& params, bool isdummy) 
{
    OrderData ordData;
    ordData.exchange = "binance";
    ordData.assetClass = "future";
    std::string privacy("private");
    try
    {        
        // build spot order and send to exchange
        std::string querypath("fapi/v1/order");
        
        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData; 
        if(!BuildNewOrder(params, payload))
        {
            LOG_IF(WARNING, verbose > 2) << "NewPerpetualOrder failed!";
            return ordData;
        }
        auto response = HttpPost(connParams, ordData.assetClass, querypath, 
                                payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 1) << response.second << "\n" << payload.content;
            return ordData;
        }

        // parse response 
        ordData = OrdersParserGet(response.second, ordData.assetClass);
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 0) << e.what();
    }
    
    return ordData;
}

OrderData Binance::NewOptionOrder(const Json::Value& params, bool isdummy) 
{
    OrderData ordData;
    ordData.exchange = "binance";
    ordData.assetClass = "option";
    std::string privacy("private");

    try
    {
        // build spot order and send to exchange
        std::string tag("option");
        std::string querypath("eapi/v1/order");
        
        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData; 
        if(!BuildNewOrder(params, payload))
        {
            LOG_IF(WARNING, verbose > 2) << "NewOptionOrder failed!";
            return ordData;
        }
        auto response = HttpPost(connParams, ordData.assetClass, querypath, 
                                payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 2) << response.second;
            return ordData;
        }

        // parse response 
        ordData = OrdersParserGet(response.second, ordData.assetClass);
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }
    
    return ordData;
}

flat_set<OrderData> Binance::NewSpotBatchOrders(const Json::Value& params)
{
    flat_set<OrderData> orders;

    std::string assetClass = "spot";
    std::string privacy("private");
    try
    {
        // build spot order and send to exchange
        std::string querypath("api/v3/batchOrders");
        
        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        Json::Value batchOrders;
        batchOrders["orders"] = Json::Value(Json::arrayValue);

        if(!params.isMember("orders"))
        {
            LOG_IF(WARNING, verbose > 1) << "Given json does not have member 'orders'";
            return orders;
        }

        int64_t overCount = params["orders"].size() - MAX_BATCH_ORDERS;
        if(overCount > 0)
        {
            LOG_IF(WARNING, verbose > 1) 
                << overCount << " orders will not be submitted."
                << "Max orders count is " << MAX_BATCH_ORDERS;
        }

        for(const auto& item: params["orders"])
        {
            Json::Value order;
            if(!BuildNewOrder(item, order))
            {
                LOG_IF(WARNING, verbose > 2) << "NewSpotOrder failed!";
                continue;
            }

            batchOrders["orders"].append(order);
            if(batchOrders["orders"].size() >= MAX_BATCH_ORDERS) break;
        }

        if(batchOrders["orders"].size() > 0)
        {
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "";
            postData.append(Json::writeString(builder, batchOrders["orders"]));
            payload.AddPair({"batchOrders", Json::writeString(builder, batchOrders["orders"])});

            auto response = HttpPost(connParams, assetClass, querypath, 
                                payload, postData, headers, true, privacy);
            if(response.first != 200)
            {
                LOG_IF(WARNING, verbose > 2) << response.second;
                return orders;
            }

            // parse response 
            orders = BatchOrdersParserGet(response.second, assetClass);
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return orders;
}

flat_set<OrderData> Binance::NewPerpetualBatchOrders(const Json::Value& params)
{
    flat_set<OrderData> orders;

    std::string assetClass = "future";
    std::string privacy("private");
    try
    {
        // build spot order and send to exchange
        std::string querypath("fapi/v1/batchOrders");
        
        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        Json::Value batchOrders;
        batchOrders["orders"] = Json::Value(Json::arrayValue);

        if(!params.isMember("orders"))
        {
            LOG_IF(WARNING, verbose > 1) << "Given json does not have member 'orders'";
            return orders;
        }

        int64_t overCount = params["orders"].size() - MAX_BATCH_ORDERS;
        if(overCount > 0)
        {
            LOG_IF(WARNING, verbose > 1) 
                << overCount << " orders will not be submitted."
                << "Max orders count is " << MAX_BATCH_ORDERS;
        }

        for(const auto& item: params["orders"])
        {
            Json::Value order;
            if(!BuildNewOrder(item, order))
            {
                LOG_IF(WARNING, verbose > 2) << "NewSpotOrder failed!";
                continue;
            }

            batchOrders["orders"].append(order);
            if(batchOrders["orders"].size() >= MAX_BATCH_ORDERS) break;
        }

        if(batchOrders["orders"].size() > 0)
        {
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "";
            postData.append(Json::writeString(builder, batchOrders["orders"]));
            payload.AddPair({"batchOrders", Json::writeString(builder, batchOrders["orders"])});

            auto response = HttpPost(connParams, assetClass, querypath, 
                                payload, postData, headers, true, privacy);
            if(response.first != 200)
            {
                LOG_IF(WARNING, verbose > 2) << response.second;
                return orders;
            }

            // parse response 
            orders = BatchOrdersParserGet(response.second, assetClass);
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return orders;
}

OrderData Binance::GetSpotOrder(const std::string& instrum, std::string id, std::string lid) 
{
    OrderData ordData;
    ordData.exchange = "binance";
    ordData.assetClass = "spot";
    std::string privacy("private");

    try
    {
        std::string querypath("api/v3/order");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"origClientOrderId", lid});


        auto response = HttpGet(connParams, ordData.assetClass, querypath, 
                            payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 2) << response.second;
            return ordData;
        }
        
        // parse response 
        ordData = OrdersParserGet(response.second, ordData.assetClass);  
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return ordData;
}

OrderData Binance::GetPerpetualOrder(const std::string& instrum, std::string id, std::string lid)
{
    OrderData ordData;
    ordData.exchange = "binance";
    ordData.assetClass = "future";
    std::string privacy("private");

    try
    { 
        std::string querypath("fapi/v1/order");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"origClientOrderId", lid});


        auto response = HttpGet(connParams, ordData.assetClass, querypath, 
                            payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 2) << response.second;
            return ordData;
        }
        
        // parse response 
        ordData = OrdersParserGet(response.second, ordData.assetClass);           
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return ordData;
}

OrderData Binance::GetOptionOrder(const std::string& instrum, std::string id, std::string lid)
{
    OrderData ordData;
    ordData.exchange = "binance";
    ordData.assetClass = "option";
    std::string privacy("private");
    
    try
    {
        std::string tag("option"); 
        std::string querypath("eapi/v1/order");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"origClientOrderId", lid});

        auto response = HttpGet(connParams, ordData.assetClass, querypath, 
                                payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 2) << response.second;
            return ordData;
        }

        // parse response 
        ordData = OrdersParserGet(response.second, ordData.assetClass);
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return ordData;
}

flat_set<OrderData> Binance::GetPerpetualOpenOrders()
{
    flat_set<OrderData> orders;

    std::string assetClass = "future";
    std::string privacy("private");

    try
    {
        std::string querypath("fapi/v1/openOrders");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        
        auto response = HttpGet(connParams, assetClass, querypath, 
                                payload, postData, headers, true, privacy);

        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 0) << response.second;
        }

        // parse response 
        orders = BatchOrdersParserGet(response.second, assetClass);
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 0) << e.what();
    }

    return orders;
}

bool Binance::CancelSpotOrder(const std::string& instrum, std::string id, std::string lid) 
{
    bool sucess = false;
    std::string assetClass("spot");
    std::string privacy("private");

    try
    {
        std::string tag("spot"); 
        std::string querypath("api/v3/order");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"origClientOrderId", lid});

        auto response = HttpDelete(connParams, assetClass, querypath, 
                                payload, postData, headers, true, privacy);
        sucess = response.first == 200;
        if(response.first != 200)
        {
            sucess = false;
            LOG_IF(WARNING, verbose > 0) << response.second;
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 0) << e.what();
    }

    return sucess;
}

bool Binance::CancelPerpetualOrder(const std::string& instrum, std::string id, std::string lid) 
{
    bool sucess = false;
    std::string assetClass("future");
    std::string privacy("private");

    try
    {
        std::string querypath("fapi/v1/order");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"origClientOrderId", lid});

        auto response = HttpDelete(connParams, assetClass, querypath, 
                            payload, postData, headers, true, privacy);
        sucess = response.first == 200;
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 1) << response.second;
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return sucess;
}

bool Binance::CancelOptionOrder(const std::string& instrum, std::string id, std::string lid) 
{
    bool sucess = false;
    std::string assetClass("option");
    std::string privacy("private");

    try
    {
        std::string querypath("eapi/v1/order");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"origClientOrderId", lid});

        auto response = HttpDelete(connParams, assetClass, querypath, 
                                payload, postData, headers, true, privacy);
        sucess = response.first == 200;
        if(response.first != 200)
        {
            sucess = false;
            LOG_IF(WARNING, verbose > 0) << response.second;
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return sucess;
}

bool Binance::CancelBatchOrders(
    const std::string& assetClass, const std::string& privacy, 
    const std::string& querypath, cpr::Payload& payload)
{
    bool success = false;
    try
    {
        cpr::Header headers{};
        std::string postData;
        
        auto response = HttpDelete(connParams, assetClass, querypath, 
                                payload, postData, headers, true, privacy);
        success = response.first == 200;
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 0) << response.second;
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return success;
}

std::vector<StrPair> Binance::CancelSpotOrders(const std::vector<StrPair>& params) 
{
    std::string assetClass("spot");
    std::string privacy("private");
    std::string querypath("api/v3/batchOrders");
    
    std::vector<StrPair> submmiteds;
    
    cpr::Payload payload{};
    Json::Value batchOrderIds;
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";

    for(const StrPair& item: params)
    {
        submmiteds.emplace_back(item.first, item.second);
        if(!batchOrderIds.isMember(item.first))
            batchOrderIds[item.first] = Json::Value(Json::arrayValue);

        batchOrderIds[item.first].append(item.second);
    }

    for(const StrPair& item: params)
    {
        payload.AddPair({"symbol",item.first});
        payload.AddPair({"orderIdList", Json::writeString(builder, batchOrderIds[item.first])});
        if(!CancelBatchOrders(assetClass, privacy, querypath, payload))
        {
            submmiteds = std::vector<StrPair>{};
        }
    }

    return submmiteds;
}

std::vector<StrPair> Binance::CancelPerpetualOrders(const std::vector<StrPair>& params) 
{
    std::string assetClass("future");
    std::string privacy("private");
    std::string querypath("fapi/v1/batchOrders");
    
    std::vector<StrPair> submmiteds;
    
    cpr::Payload payload{};
    Json::Value batchOrderIds;
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";

    for(const StrPair& item: params)
    {
        submmiteds.emplace_back(item.first, item.second);
        if(!batchOrderIds.isMember(item.first))
            batchOrderIds[item.first] = Json::Value(Json::arrayValue);

        batchOrderIds[item.first].append(item.second);
    }

    for(const StrPair& item: params)
    {
        payload.AddPair({"symbol",item.first});
        payload.AddPair({"orderIdList", Json::writeString(builder, batchOrderIds[item.first])});
        if(!CancelBatchOrders(assetClass, privacy, querypath, payload))
        {
            submmiteds = std::vector<StrPair>{};
        }
    }

    return submmiteds;
}

std::vector<StrPair> Binance::CancelOptionOrders(const std::vector<StrPair>& params) 
{
    std::string assetClass("option");
    std::string privacy("private");
    std::string querypath("eapi/v1/batchOrders");
    
    std::vector<StrPair> submmiteds;
    
    cpr::Payload payload{};
    Json::Value batchOrderIds;
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";

    for(const StrPair& item: params)
    {
        submmiteds.emplace_back(item.first, item.second);
        if(!batchOrderIds.isMember(item.first))
            batchOrderIds[item.first] = Json::Value(Json::arrayValue);

        batchOrderIds[item.first].append(item.second);
    }

    for(const StrPair& item: params)
    {
        payload.AddPair({"symbol",item.first});
        payload.AddPair({"orderIdList", Json::writeString(builder, batchOrderIds[item.first])});
        if(!CancelBatchOrders(assetClass, privacy, querypath, payload))
        {
            submmiteds = std::vector<StrPair>{};
        }
    }

    return submmiteds;
}

Json::Value Binance::GetLastPerpetualTrade(const std::string& instrum, int limit)
{
    std::string exchange("binance");
    std::string assetClass("future");
    std::string privacy("private");

    Json::Value trades;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    try
    { 
        std::string querypath("fapi/v1/userTrades");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        payload.AddPair({"limit", std::to_string(limit)});
        
        auto response = HttpGet(connParams, assetClass, querypath, 
                            payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 2) << response.second;
            return trades;
        }  

        const std::string& msg = response.second;
        reader->parse(msg.c_str(), msg.c_str() + msg.size(),&trades, &errs);    
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 2) << e.what();
    }

    return trades;
}

flat_set<PositionData> Binance::GetPerpetualPositions(const std::string& instrum, std::string lid) 
{
    flat_set<PositionData> positions;

    PositionData posData;
    posData.exchange = "binance";
    posData.assetClass = "future";
    std::string privacy("private");
    try
    { 
        std::string querypath("fapi/v2/positionRisk");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});

        auto response = HttpGet(connParams, posData.assetClass, querypath, 
                                payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 0) << response.second;
            return positions;
        }

        positions = PerpetualPositionParserGet(response.second, posData.assetClass);
        if(!lid.empty())
        {
            posData.lid = lid;
            flat_set<PositionData> items;
            auto piter = positions.find(posData);
            if(piter != positions.end())
                items.insert(*piter);
            positions = items;
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 1) << e.what();
    }

    return positions;
}

flat_set<PositionData> Binance::GetOptionPositions(const std::string& instrum, std::string lid) 
{
    flat_set<PositionData> positions;

    PositionData posData;
    posData.exchange = "binance";
    posData.assetClass = "option";
    std::string privacy("private");
    try
    {
        std::string tag("option"); 
        std::string querypath("eapi/v1/position");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});

        auto response = HttpGet(connParams, posData.assetClass, querypath, 
                                payload, postData, headers, true, privacy);
        if(response.first != 200)
        {
            LOG_IF(WARNING, verbose > 0) << response.second;
            return positions;
        }

        positions = PerpetualPositionParserGet(response.second, posData.assetClass); 
        if(!lid.empty())
        {
            posData.lid = lid;
            flat_set<PositionData> items;
            auto piter = positions.find(posData);
            if(piter != positions.end())
                items.insert(*piter);
            positions = items;
        }
    }
    catch(std::exception& e)
    {
        LOG_IF(WARNING, verbose > 1) << e.what();
    }

    return positions;
}

void Binance::InfoParser(const Json::Value& info)
{
    if(info.isMember("symbols"))
    {
        for(const Json::Value& item: info["symbols"])
        {
            Filter filter;
            filter.instrum = item["symbol"].asString();
            filter.status = item["status"].asString();
            filter.pxPrecision = item["pricePrecision"].asDouble();
            filter.qtyPrecision = item["quantityPrecision"].asDouble();
            filter.basePrecision = item["baseAssetPrecision"].asInt();
            filter.quotePrecision = item["quotePrecision"].asInt();
            if(item.isMember("filters"))
            {
                for(const Json::Value& instFilter: item["filters"])
                {
                    if(instFilter["filterType"].asString() == "PRICE_FILTER")
                    {
                        filter.tickSize = std::stod(instFilter["tickSize"].asString());
                        filter.maxPrice = std::stod(instFilter["maxPrice"].asString());
                    }
                    else if(instFilter["filterType"].asString() == "LOT_SIZE")
                    {
                        filter.stepSize = std::stod(instFilter["stepSize"].asString());
                        filter.maxQty = std::stod(instFilter["maxQty"].asString());
                    }
                }
            }
            filters.insert(filter);

            LOG_IF(INFO, verbose > 2) << "Filter: " << filter;
        }
    }

    if(info.isMember("rateLimits"))
    {
        for(const Json::Value& item: info["rateLimits"])
        {
            if(item["rateLimitType"].asString() == "REQUEST_WEIGHT")
                REQUEST_LIMIT = item["limit"].asInt64();
            else if(item["rateLimitType"].asString() == "ORDERS")
                ORDERS_LIMIT = item["limit"].asInt64();
        }

        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(INFO, verbose > 0) 
            << "rateLimits: " << Json::writeString(builder, info["rateLimits"]);
    }
}

void Binance::ListenKeyParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    std::string privacy("private");
    std::string connKey(privacy);
    connKey.append("_").append(tag);
    std::string assetClass = tag;

    if(connHdlPtrsMap.count(connKey))
    {
        // reconnecto to private stream if keep alive failed
        WebClient::connection_ptr closedCon;
        ConnHandler::ptr connHdl = connHdlPtrsMap.at(connKey);
        if(connHdl)
        {
            WebClient::connection_ptr con = connHdl->GetConnection();
            if(con == nullptr) return;

            connFlag.test_and_set(std::memory_order_release);

            std::string oldListenKey = connHdl->GetUrl();
            if(!GetListenKey(assetClass, privacy))
            {
                LOG_IF(WARNING, verbose > 0) << "Request new listenKey failed!";
                return;
            }

            std::string url = connHdl->GetUrl();
            std::string listenKey = listenKeys.at(connKey);
            size_t pos = url.find(oldListenKey); 
            if(pos == url.npos)
            {
                LOG_IF(WARNING, verbose > 0) << "ListenKey not found in connection uri!";
                return;
            }
            url = url.replace(pos, oldListenKey.length(), listenKey);         

            ConnState state;
            con->close(websocketpp::close::status::extension_required, "ListenKey Expired");
            websocketpp::uri_ptr newUri = websocketpp::lib::make_shared<websocketpp::uri>(url);
            con->set_uri(newUri);

            connHdl->SetUrl(url);
            endpoint.connect(con);

            connFlag.clear(std::memory_order_acquire); // release
        }
    }
}

void Binance::TradesParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {
        if(priceQueue)
        {
            PriceData pxData;
            pxData.exchange = "binance";
            pxData.assetClass = tag;

            const Json::Value& trade = data["data"];

            // convert timestamp into date, time and sec
            pxData.timestamp = trade["T"].asInt64();

            // format date eg: 20190628 12:23:00
            pxData.date = Utils::FormatDate(pxData.timestamp);
            pxData.time = Utils::FormatTime(pxData.timestamp);
            
            // get tick data transaction info
            pxData.instrum = trade["s"].asString();
            pxData.quantity = std::stod(trade["q"].asString());

            std::stringstream ssprice;
            double price = std::stod(trade["p"].asString());
            ssprice << std::setprecision(8) << price;
            ssprice >> pxData.price;

            priceQueue->enqueue(pxData);
        }
    }
    catch(const Json::Exception& e)
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(INFO, verbose > 0) 
            << e.what() << "\n" << Json::writeString(builder, data);
    }    
}

void Binance::CandlesParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) 
{
    try
    {
        if(candleQueue)
        {
            CandleData candle;
            candle.exchange = "binance";
            candle.assetClass = tag;

            const Json::Value& d = data["data"];
            if(d.isMember("k"))
            {
                const Json::Value& kline = d["k"];

                // convert timestamp into date, time and sec
                candle.timestamp = kline["t"].asInt64();
                candle.date = Utils::FormatDate(candle.timestamp);
                candle.time = Utils::FormatTime(candle.timestamp);

                candle.instrum = kline["s"].asString();
                candle.open = std::stod(kline["o"].asString());
                candle.high = std::stod(kline["h"].asString());
                candle.low = std::stod(kline["l"].asString());
                candle.close = std::stod(kline["c"].asString());
                candle.volume = std::stod(kline["q"].asString());

                candleQueue->enqueue(candle);
            }
        }
    }
    catch(std::exception& e)
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(INFO, verbose > 2) 
            << e.what() << "\n" << Json::writeString(builder, data);
    }
}

void Binance::DepthParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {
        /*std::string stream = data.get("stream", "").asString();
        const Json::Value& snapshot = data["data"];

        std::vector<std::string> fields = {"u","pu","T","b","a"};
        if(tag == "spot")
            fields = std::vector<std::string>{"lastUpdateId","U","E","bids","asks"};
        
        int64_t updateId = snapshot.get(fields.at(0), 0).asInt64();
        int64_t prevUupdateId = snapshot.get(fields.at(1), 0).asInt64();
        int64_t timestamp = snapshot.get(fields.at(2), Utils::GetMilliseconds()).asInt64();
        std::string event = snapshot["e"].asString();;
        std::string instrum = snapshot["s"].asString();
        const Json::Value& bids = snapshot[fields.at(3)];
        const Json::Value& asks = snapshot[fields.at(4)];

        size_t bidSz = bids.size();
        size_t askSz = asks.size();
        size_t bookSize = connParams.get("maxDepth", 0).asInt64();
        long maxCount = bookSize > 0 ? bookSize: std::max(bidSz, askSz);
        
        for (int i = 0; i < maxCount; ++i)
        {
            if (i < bidSz)
            {
                const Json::Value &item = bids[i];
                // TODO:
            }

            if (i < askSz)
            {
                const Json::Value &item = asks[i];
                // TODO:
            }
        }*/

        if(depthQueue)
            depthQueue->enqueue(data);
    }
    catch(const std::exception& e)
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(INFO, verbose > 0) 
            << e.what() << "\n" << Json::writeString(builder, data);
    }
}

void Binance::TickersParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {
        if(tickerQueue)
        {
            const Json::Value& ticker = data["data"];

            TickerData tickData;
            tickData.exchange = "binance";
            tickData.assetClass = tag;

            // convert timestamp into date, time and sec
            tickData.timestamp = ticker.get("T", Utils::GetMilliseconds()).asInt64();
            
            // get tick data transaction info
            tickData.instrum = ticker["s"].asString();
            tickData.bidQty = std::stod(ticker["B"].asString());
            tickData.askQty = std::stod(ticker["A"].asString());
            tickData.bid = std::stod(ticker["b"].asString());
            tickData.ask = std::stod(ticker["a"].asString());
            
            if(tickerQueue)
                tickerQueue->enqueue(tickData);
        }
    }
    catch(const std::exception& e)
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(INFO, verbose > 0) 
            << e.what() << "\n" << Json::writeString(builder, data);
    }
}

void Binance::OrdersParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {
        if(orderQueue)
        {
            OrderData ordData;
            ordData.exchange = "binance";
            ordData.assetClass = tag;

            const Json::Value& order = data["o"];
            ordData.instrum = order.get("s", "").asString();
            ordData.state = order.get("X","").asString();
            ordData.id = std::to_string(order.get("i",0).asInt64());
            ordData.lid = order.get("c","").asString();
            ordData.local = false;
            
            ordData.timestamp = order.get("T",0).asInt64();
            ordData.side = order.get("S","").asString();
            ordData.orderType = order.get("o","LIMIT").asString();
            ordData.price = std::stod(order.get("p", "0.0").asString());
            ordData.stopPrice = std::stod(order.get("P", "0.0").asString());
            ordData.quantity = std::stod(order.get("q", "0.0").asString());
            ordData.execQuantity = std::stod(order.get("z", "0.0").asString());
            ordData.timeInForce = order.get("f", "GTC").asString();
            ordData.closePosition = order.get("R", 0).asBool();
            ordData.posSide = order.get("ps", "").asString();

            ordData.date = Utils::FormatDatetime(ordData.timestamp);

            if(orderQueue)
                orderQueue->enqueue(ordData);
        }
    }
    catch(std::exception& e)
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(WARNING, verbose > 0) 
            << e.what() << "\n" << Json::writeString(builder, data);
    }        
}

OrderData Binance::OrdersParserGet(const std::string& msg, const std::string& tag)
{
    OrderData ordData;
    ordData.exchange = "binance";
    ordData.assetClass = tag;
    ordData.local = false;

    Json::Value order;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&order, &errs))
    {
        ordData.state = order.get("state", "").asString();
        if(ordData.state.length() == 0)
            ordData.state = order.get("status", "").asString();

        ordData.instrum = order["symbol"].asString();
        ordData.id = std::to_string(order.get("orderId",0).asInt64());
        ordData.lid = order.get("clientOrderId","").asString();

        ordData.side = order.get("side", "NONE").asString();
        ordData.orderType = order.get("type","LIMIT").asString();
        ordData.price = std::stod(order.get("price", "0.0").asString());
        ordData.stopPrice = std::stod(order.get("stopPrice", "0.0").asString());
        ordData.quantity = std::stod(order.get("origQty", "0.0").asString());
        ordData.execQuantity = std::stod(order.get("executedQty", "0.0").asString());
        ordData.timeInForce = order.get("timeInForce", "GTC").asString();
        ordData.closePosition = order.get("closePosition", 0).asBool();
        ordData.posSide = order.get("positionSide", "").asString();
        ordData.closePosition = order.get("reduceOnly", 0).asBool();
        ordData.attrs["postOnly"] = order.get("postOnly", 0).asBool();
        ordData.attrs["quantityScale"] = order.get("quantityScale", 0).asInt();

        if(order.isMember("optionSide"))
            ordData.posSide = order["optionSide"].asString();

        if(order.isMember("updateTime"))
            ordData.timestamp = order.get("updateTime",0).asInt64();

        if(order.isMember("time"))
            ordData.timestamp = order["time"].asInt64();
        else if(order.isMember("transactTime"))
            ordData.timestamp = order["transactTime"].asInt64();
        else if(order.isMember("createTime"))
            ordData.timestamp = order["createTime"].asInt64();

        ordData.date = Utils::FormatDatetime(ordData.timestamp);
        //ordData.UpdateLocalId();
    }

    return ordData;
}

flat_set<OrderData> Binance::BatchOrdersParserGet(const std::string& msg, const std::string& tag)
{
    flat_set<OrderData> orders;
    
    Json::Value records;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&records, &errs))
    {
        for(const auto& order: records)
        {
            OrderData ordData;
            ordData.exchange = "binance";
            ordData.assetClass = tag;
            ordData.local = false;
            
            ordData.state = order.get("state", "").asString();
            if(ordData.state.length() == 0)
                ordData.state = order.get("status", "").asString();

            ordData.instrum = order["symbol"].asString();
            ordData.id = std::to_string(order.get("orderId",0).asInt64());
            ordData.lid = order.get("clientOrderId","").asString();

            ordData.side = order.get("side", "NONE").asString();
            ordData.orderType = order.get("type","LIMIT").asString();
            ordData.price = std::stod(order.get("price", "0.0").asString());
            ordData.stopPrice = std::stod(order.get("stopPrice", "0.0").asString());
            ordData.quantity = std::stod(order.get("origQty", "0.0").asString());
            ordData.execQuantity = std::stod(order.get("executedQty", "0.0").asString());
            ordData.timeInForce = order.get("timeInForce", "GTC").asString();
            ordData.closePosition = order.get("closePosition", 0).asBool();
            ordData.posSide = order.get("positionSide", "").asString();
            ordData.closePosition = order.get("reduceOnly", 0).asBool();
            ordData.attrs["postOnly"] = order.get("postOnly", 0).asBool();
            ordData.attrs["quantityScale"] = order.get("quantityScale", 0).asInt();

            if(order.isMember("optionSide"))
                ordData.posSide = order["optionSide"].asString();

            if(order.isMember("updateTime"))
                ordData.timestamp = order.get("updateTime",0).asInt64();

            if(order.isMember("time"))
                ordData.timestamp = order["time"].asInt64();
            else if(order.isMember("transactTime"))
                ordData.timestamp = order["transactTime"].asInt64();
            else if(order.isMember("createTime"))
                ordData.timestamp = order["createTime"].asInt64();

            ordData.date = Utils::FormatDatetime(ordData.timestamp);
            //ordData.UpdateLocalId();
            orders.insert(ordData);
        }
    }

    return orders;
}

void Binance::PositionsParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {
        const Json::Value& position = data["a"];
        if(position.isMember("P"))
        {            
            for(const auto& item: position["P"])
            {
                PositionData posData;
                posData.exchange = "binance";
                posData.assetClass = tag;
                posData.local = false;
                posData.instrum = item["s"].asString();
                posData.posSide = item.get("ps","").asString();
                posData.price = std::stod(item.get("ep","0.0").asString());
                posData.quantity = std::stod(item.get("pa","0.0").asString());
                posData.pnl = std::stod(item.get("up","0.0").asString());
                posData.assetClass = item.get("assetClass", tag).asString();
                posData.leverage = item.get("leverage", 1).asInt64();
                posData.timestamp = data["T"].asInt64();
                posData.ltimestamp = posData.timestamp;

                posData.attrs["marginType"] = item.get("mt","");
                posData.side = (posData.quantity > 0) ? "BUY": "SELL";
                posData.entryDate = Utils::FormatDatetime(posData.timestamp);
                posData.UpdateLocalId();

                if(positionQueue)
                    positionQueue->enqueue(posData);
            }
        }
    }
    catch(std::exception& e)
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(INFO, verbose > 0) 
            << e.what() << "\n" << Json::writeString(builder, data);
    }
}

flat_set<PositionData> Binance::PerpetualPositionParserGet(const std::string& msg, const std::string& tag)
{
    flat_set<PositionData> positions;

    PositionData posData;
    posData.exchange = "binance";
    posData.assetClass = tag;
    posData.local = false;

    Json::Value records;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&records, &errs))
    {
        for(const auto& position: records)
        {
            posData.instrum = position["symbol"].asString();
            posData.posSide = position["positionSide"].asString();
            posData.price = std::stod(position["entryPrice"].asString());
            posData.quantity = std::stod(position["positionAmt"].asString());
            posData.pnl = std::stod(position["unRealizedProfit"].asString());
            posData.leverage = std::stoi(position["leverage"].asString());
            posData.timestamp = position.get("updateTime", 0).asInt64();
            posData.entryDate = Utils::FormatDatetime(posData.timestamp);
            posData.closeDate = Utils::FormatDatetime(posData.timestamp); // not necessarely closed

            posData.attrs["liquidationPrice"] = std::stod(position.get("liquidationPrice", "0.0").asString());
            posData.attrs["marginType"] = position.get("marginType", "").asString();
            
            posData.action = (posData.quantity > 0) ? 1: 2;
            posData.side = (posData.quantity > 0) ? "BUY": "SELL";
            posData.ltimestamp = posData.timestamp;
            posData.UpdateLocalId();

            if(posData.IsValid())
                positions.insert(posData);
        }
    }

    return positions;
}

flat_set<PositionData> Binance::OptionPositionParserGet(const std::string& msg, const std::string& tag)
{
    flat_set<PositionData> positions;

    PositionData posData;
    posData.exchange = "binance";
    posData.assetClass = tag;
    posData.local = false;

    Json::Value records;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&records, &errs))
    {
        for(const auto& position: records)
        {
            posData.instrum = position["symbol"].asString();
            posData.posSide = position.get("optionSide", "").asString();
            posData.side = position["side"].asString();
            posData.price = std::stod(position["entryPrice"].asString());
            posData.quantity = std::stod(position["quantity"].asString());
            posData.pnl = std::stod(position["unRealizedProfit"].asString());
            posData.timestamp = std::stol(position.get("expiryDate", "0").asString());
            posData.entryDate = Utils::FormatDatetime(posData.timestamp);
            posData.closeDate = Utils::FormatDatetime(posData.timestamp); // not necessarely closed

            posData.attrs["ror"] = std::stod(position.get("ror", "0.0").asString());
            posData.attrs["markPrice"] = std::stod(position.get("markPrice", "0.0").asString());
            posData.attrs["strikePrice"] = std::stod(position.get("strikePrice", "0.0").asString());
            posData.attrs["positionCost"] = std::stod(position.get("positionCost", "0.0").asString());

            posData.action = (posData.quantity > 0) ? 1: 2;
            posData.ltimestamp = posData.timestamp;
            posData.UpdateLocalId();

            if(posData.IsValid())
                positions.insert(posData);
        }
    }

    return positions;
}


std::thread Binance::StreamParser(MessageQueue& messageQueue, size_t numThreads)
{
    std::thread task([this, &messageQueue, numThreads]
    {
        boost::asio::thread_pool pool(numThreads);

        while(!exitThread)
        {
            StrPair item;
            if(messageQueue.try_dequeue(item))
            {               
                boost::asio::dispatch(pool, [this, item]()
                {
                    std::string errs;
                    Json::Value record;
                    std::unique_ptr<Json::CharReader> reader;
                    Json::CharReaderBuilder rbuilder;
                    reader.reset(rbuilder.newCharReader());

                    //LOG_IF(INFO, verbose > 0) << item.second;
                    std::string msg(item.second);
                    
                    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&record, &errs))
                    {
                        try
                        {
                            int64_t now = Utils::GetMilliseconds(-2000);

                            std::string event;
                            std::string stream = record.get("stream", "").asString();
                            size_t pos = stream.find("@depth");
                            if(pos != stream.npos && item.first == "spot")
                            {
                                std::string instrum = stream.substr(0,pos);
                                std::transform(instrum.begin(), instrum.end(), instrum.begin(), ::toupper);
                                record["data"]["e"] = "depthUpdate";
                                record["data"]["s"] = instrum;
                            }
                            
                            event = record.get("data", record)["e"].asString();

                            // parse message using dispatcher map
                            if(dispatcherMap.count(event))
                            {
                                pfunct caller = dispatcherMap[event];
                                (this->*caller)(record, item.first, now);
                            }
                            else
                                LOG_IF(INFO, verbose > 0) << msg;
                        }
                        catch(const std::exception& e)
                        {
                            LOG_IF(INFO, verbose > 0) << e.what();
                        }
                    }
                    else
                        LOG_IF(INFO, verbose > 1) << item.second;

                });
            }
        }

        pool.stop();
    });

    return task;
}

void Binance::BindTradesQueue(ConcurrentQueue<PriceData>* queue)
{
    priceQueue = queue;
}

void Binance::BindCandlesQueue(ConcurrentQueue<CandleData>* queue)
{
    candleQueue = queue;
}

void Binance::BindDepthQueue(ConcurrentQueue<Json::Value>* queue)
{
    depthQueue = queue;
}

void Binance::BindTickerQueue(ConcurrentQueue<TickerData>* queue)
{
    tickerQueue = queue;
}

void Binance::BindOrderQueue(ConcurrentQueue<OrderData>* queue)
{
    orderQueue = queue;
}

void Binance::BindPositionQueue(ConcurrentQueue<PositionData>* queue)
{
    positionQueue = queue;
}
}

CONNECTOR_MODULE(stelgic::Binance, "binance", "0.0.1");

