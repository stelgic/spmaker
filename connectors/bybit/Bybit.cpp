#include "Bybit.h"
#include <g3log/g3log.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>

namespace stelgic
{
Bybit::Bybit() : recvWindow(5000), pingInterval(60000), 
    ORDERS_LIMIT(300), REQUEST_LIMIT(300)
{
    dispatcherMap["publicTrade"] = (pfunct)&Bybit::TradesParser;
    dispatcherMap["kline"] = (pfunct)&Bybit::CandlesParser;
    dispatcherMap["orderbook"] = (pfunct)&Bybit::DepthParser;
    dispatcherMap["tickers"] = (pfunct)&Bybit::TickersParser;
    dispatcherMap["user.order"] = (pfunct)&Bybit::OrdersParser;
    dispatcherMap["user.position"] = (pfunct)&Bybit::PositionsParser;
    dispatcherMap["auth"] = (pfunct)&Bybit::Authentication;

    edgeModesMap.emplace(0, "BOTH");
    edgeModesMap.emplace(1, "LONG");
    edgeModesMap.emplace(2, "SHORT");

    paramMapping["BOTH"]= 0;
    paramMapping["LONG"]= 1;
    paramMapping["SHORT"]= 2;

    paramMapping["GTC"]= "GoodTillCancel";
    paramMapping["IOC"]= "ImmediateOrCancel";
    paramMapping["FOK"]= "FillOrKill";

    paramMapping["spot"]= "spot";
    paramMapping["future"]= "linear";
    paramMapping["option"]= "option";

    timestamp = 0;
    MAX_BATCH_ORDERS = 5;
    liveMode = LiveState::Stopped;
}

Bybit::~Bybit() 
{
    Close();

    for(auto& worker: workers)
        worker.join();
}

void Bybit::Init(const Json::Value& params, int logLevel, g3::LogWorker* logWorker)
{
#if defined(_WIN32) || defined(_WIN64)
    if(logWorker != nullptr)
        g3::initializeLogging(logWorker);
#endif 
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

void Bybit::Close()
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

bool Bybit::IsInitialized()
{
    return liveMode == LiveState::Started || liveMode == LiveState::Running;
}

void Bybit::Stop()
{ 
    exitThread = {1};
}

void Bybit::Reconnect()
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

bool Bybit::IsOnline()
{
    return liveMode == LiveState::Running;
}

bool Bybit::IsRequestLimitHit()
{
    return (ORDERS_LIMIT - ORDER_LIMIT_COUNT ) <= 50 || (REQUEST_LIMIT - IP_LIMIT_COUNT) <= 1;
}

bool Bybit::ResetRequestLimitTimer(int millis)
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

void Bybit::TestConnectivity()
{
    ConnHandler::ptr connHdlPtr = nullptr;
    for(auto& item: connHdlPtrsMap)
    {
        if(item.first == "public")
            connHdlPtr = item.second;
    }

    if(connHdlPtr == nullptr && connHdlPtrsMap.size() > 0)
        connHdlPtr = connHdlPtrsMap.begin()->second;
    else
    {
        LOG(INFO) << "No connection available!";
        return;
    }

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

Json::Value& Bybit::GetConfiguration()
{
    return connParams;
}

void* Bybit::GetMessageQueue(const std::string& tag)
{
    return nullptr;
}

ConnState Bybit::Connect(const Json::Value& params)
{
    ConnState conState;
    if(!params.isMember("websocket"))
    {
        LOG_IF(WARNING, verbose > 0) << "Missing websocket params in Bybit!";
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
            
            LOG_IF(INFO, verbose > 0) << "Connecting to " 
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
            
            // set header api key
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

            if(privacy == "private" && Authentication(connKey, assetClass, privacy))
            {
                LOG_IF(WARNING, verbose > 0) << "Successful authenticated to private " << assetClass;
            }
        }
    }

    return conState;
}

bool Bybit::Send(const std::string& key, const std::string& message)
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

bool Bybit::Authentication(const std::string& connKey, 
    const std::string& assetClass, const std::string& privacy)
{
    bool success = false;
    Json::Value payload;
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    
    authenticationMap[connKey] = {0};
    int64_t expires = Utils::GetMilliseconds(10000);

    const Json::Value& secrets = connParams["secrets"];
    std::string apikey = secrets[privacy][assetClass].get("apikey", "").asString();
    std::string apisecret = secrets[privacy][assetClass].get("apisecret", "").asString();

    std::string query("GET/realtime");
    query.append(std::to_string(expires));
    std::string signature = AuthUtils::GetSignature(apisecret, query);
    
    payload["op"] = "auth";
    //payload["req_id"] = std::to_string(Utils::GetSeconds());
    payload["args"] = Json::Value(Json::arrayValue);

    payload["args"].append(apikey);
    payload["args"].append(expires);
    payload["args"].append(signature);

    std::string msg(Json::writeString(builder, payload));
    LOG_IF(INFO, verbose > 0) << "AUTHENTICATION: " << msg;
    if(Send(connKey, msg))
    {
        int wait = 3;
        while(!authenticationMap.at(connKey) && wait > 0)
        {
            --wait;
            std::this_thread::sleep_for(std::chrono::seconds{1});
        }

        success = authenticationMap.at(connKey);
    }
    
    return success;
}

bool Bybit::Subscribe(const std::string& key, 
    const std::string& market, const Json::Value& symbols, 
    const Json::Value& channels, std::string privacy)
{
    LOG_IF(INFO, verbose > 1) << "Subscribing to Bybit " << privacy << " channels...";
    int num = 0;
    for(const auto& member: channels)
    {
        bool success = false;
        std::string interval;
        std::stringstream sstopics;

        Json::StreamWriterBuilder builder;
        Json::Value payload;
        
        builder["indentation"] = "";
        payload["op"] = "subscribe";
        payload["req_id"] = std::to_string(Utils::GetSeconds());
        payload["args"] = Json::Value(Json::arrayValue);

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
                std::transform(name.begin(), name.end(), name.begin(), ::toupper);

                sstag << sstopics.str() << "." << name;
                payload["args"].append(sstag.str());
                success = true;
            }
        }
        else
        {
            std::string channel = member.asString();
            payload["args"].append(channel);
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

bool Bybit::Subscribe(const Json::Value& params)
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

            if (connState == ConnState::Opened)
            {
                i += Subscribe(connKey, assetClass, tag["instruments"], tag["channels"], privacy);
            }
        }
    }
    return i > 0;
}

bool Bybit::SendKeepAlive(const std::string& key)
{
    bool success = false;
    try
    {
        if(key.find("private") != key.npos)
        {
            Json::Value payload;
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "";

            payload["op"] = "ping";
            payload["req_id"] = std::to_string(Utils::GetSeconds());

            std::string msg(Json::writeString(builder, payload));
            Send(key, msg);
        }
    }
    catch(websocketpp::exception& e)
    {
        LOG_IF(WARNING, verbose > 0) << "KeepAlive: " << e.what();
    }
    return success;
}

std::thread Bybit::KeepAlive()
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

                        Subscribe(connParams);
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

void Bybit::HttpCommon(
    const std::string &baseurl, const Json::Value& configs, 
    const std::string& function, cpr::Payload& payload, 
    const std::string& postData, cpr::Header& headers, bool signing)
{
    int64_t epoch = Utils::GetMilliseconds(0);
    
    headers.emplace("X-BAPI-API-KEY", configs["apikey"].asString());
    headers.emplace("X-BAPI-RECV-WINDOW", std::to_string(recvWindow));
    headers.emplace("X-BAPI-TIMESTAMP", std::to_string(epoch));
    headers.emplace("Content-Type","application/json");
        
    if(signing)
    {
        // param_str= str(time_stamp) + api_key + recv_window + payload
        std::string content(std::to_string(epoch));
        content.append(configs["apikey"].asString());
        content.append(std::to_string(recvWindow));
        if(!postData.empty())
            content.append(postData);
        else
            content.append(payload.content);

        std::string signature = AuthUtils::GetSignature(
            configs["apisecret"].asString(), content);
            
        headers.emplace("X-BAPI-SIGN", signature);
        headers.emplace("X-BAPI-SIGN-TYPE", "2");
    }
}

IntStrPair Bybit::HttpPost(const Json::Value& configs, 
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
    session->SetOption(cpr::Body(dataPost));
    session->SetVerifySsl(cpr::VerifySsl(false));
    session->SetHeader(headers);

    // post to exchange
    cpr::Response r = session->Post();
    sessionPool.enqueue(session);

    if(r.header.count("X-Bapi-Limit-Status"))
    {
        REQUEST_LIMIT.store(std::stol(r.header["X-Bapi-Limit"]));
        IP_LIMIT_COUNT.store(REQUEST_LIMIT - std::stol(r.header["X-Bapi-Limit-Status"]));
    }
    
    if(r.status_code == 403)
        IP_LIMIT_COUNT = REQUEST_LIMIT.load();

    LOG_IF(INFO, verbose > 1)
        << "POST: " << baseurl + url << "?" 
        << cpr::Body(dataPost) << "\n"
        << r.status_code 
        << " IP_LIMIT_COUNT=" << IP_LIMIT_COUNT;

    return  std::make_pair(r.status_code, r.text);
}

IntStrPair Bybit::HttpGet(
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

    if(r.header.count("X-Bapi-Limit-Status"))
    {
        REQUEST_LIMIT.store(std::stol(r.header["X-Bapi-Limit"]));
        IP_LIMIT_COUNT.store(REQUEST_LIMIT - std::stol(r.header["X-Bapi-Limit-Status"]));
    }

    if(r.status_code == 403)
        IP_LIMIT_COUNT = REQUEST_LIMIT.load();

    LOG_IF(INFO, verbose > 1) 
        << "GET: " << baseurl + url << "\n"
        << r.status_code << " " << r.header["content-type"];

    return  std::make_pair(r.status_code, r.text);
}

IntStrPair Bybit::HttpPut(
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

    std::string content = payload.content;
    std::string dataPost = postData;
    if(postData.empty())
        dataPost.append(content);

    headers.emplace("Accept-Encoding", "gzip,deflate,zlib");
    
    session->SetUrl({baseurl + url});
    session->SetOption(cpr::Body(dataPost));
    session->SetVerifySsl(cpr::VerifySsl(false));
    session->SetHeader(headers);

    // put to exchange
    cpr::Response r = session->Put();
    sessionPool.enqueue(session);

    if(r.header.count("X-Bapi-Limit-Status"))
    {
        REQUEST_LIMIT.store(std::stol(r.header["X-Bapi-Limit"]));
        IP_LIMIT_COUNT.store(REQUEST_LIMIT - std::stol(r.header["X-Bapi-Limit-Status"]));
    }

    if(r.status_code == 403)
        IP_LIMIT_COUNT = REQUEST_LIMIT.load();

    LOG_IF(INFO, verbose > 1)
        << "PUT: " << baseurl + url << "?" << cpr::Body(dataPost) <<  "\n"
        << r.status_code << " " << r.header["content-type"];

    return  std::make_pair(r.status_code, r.text);
}

IntStrPair Bybit::HttpDelete(
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

    if(r.header.count("X-Bapi-Limit-Status"))
    {
        REQUEST_LIMIT.store(std::stol(r.header["X-Bapi-Limit"]));
        IP_LIMIT_COUNT.store(REQUEST_LIMIT - std::stol(r.header["X-Bapi-Limit-Status"]));
    }

    if(r.status_code == 403)
        IP_LIMIT_COUNT = REQUEST_LIMIT.load();

    LOG_IF(INFO, verbose > 1) 
        << "DELETE: " << baseurl + url << "\n"
        << r.status_code << r.header["content-type"];

    return  std::make_pair(r.status_code, r.text);
}

Json::Value Bybit::GetMarketInfo(const std::string& assetClass)
{
    // parse response
    std::string errs;
    Json::Value data;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    cpr::Payload payload{};
    std::string postData;
    std::string querypath = assetClass;
    querypath.append("v3/public/symbols");
    if(assetClass == "future")
        querypath = "derivatives/v3/public/instruments-info";

    payload.AddPair({"category", paramMapping.get(assetClass, "").asString()});
        
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

flat_set<Filter>& Bybit::GetFilters()
{
    return filters;
}
    
flat_set<BalanceData> Bybit::GetSpotAccountBalances(
    const std::set<std::string>& currencies)
{
    BalanceData balance;
    flat_set<BalanceData> balances;

    Json::Value records;
    cpr::Payload payload{};
    std::string postData; 
    const std::string tag("spot");
    const std::string querypath("v5/account/wallet-balance");
    
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
        if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&records, &errs))
        {
            for(const Json::Value& item: records["result"]["list"]["coin"])
            {
                balance.exchange = "bybit";

                balance.asset = item["coin"].asString();
                balance.available = std::stod(item["availableToBorrow"].asString());
                balance.locked = std::stod(item["walletBalance"].asString()) - balance.available;
                balance.unrealizedPNL = std::stod(item["unrealisedPnl"].asString());
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

flat_set<BalanceData> Bybit::GetPerpetualAccountBalances(
    const std::set<std::string>& currencies)
{
    BalanceData balance;
    flat_set<BalanceData> balances;

    Json::Value records;
    cpr::Payload payload{};
    std::string postData; 
    const std::string tag("future");
    const std::string querypath("contract/v3/private/account/wallet/balance");
    
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
        if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&records, &errs))
        {
            for(Json::Value& item: records["list"])
            {
                balance.exchange = "bybit";
                balance.asset = item["asset"].asString();
                balance.available = std::stod(item["availableBalance"].asString());
                balance.locked = std::stod(item["walletBalance"].asString()) - balance.available;
                balance.unrealizedPNL = std::stod(item["unrealisedPnl"].asString());
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

flat_set<BalanceData> Bybit::GetOptionAccountBalances(
    const std::set<std::string>& currencies)
{
    BalanceData balance;
    flat_set<BalanceData> balances;

    LOG(WARNING) << "Not implemented!";

    return balances;
}

bool Bybit::BuildNewOrder(const Json::Value &params, cpr::Payload& payload)
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
            payload.AddPair({"orderType", orderType});     
                        
            if(orderType != "MARKET")
            {
                payload.AddPair({"price", ssp.str()});
                if(stopPrice > 0)
                    payload.AddPair({"stopLoss", sspl.str()});
                if(profitPrice > 0)
                    payload.AddPair({"takeProfit", sstp.str()});
            }

            if(params.isMember("posSide") && !params["posSide"].asString().empty())
                payload.AddPair({"positionIdx", paramMapping.get(params["posSide"].asString(), 0).asInt()});

            if(params.isMember("clOrderId") && !params["clOrderId"].asString().empty())
                payload.AddPair({"orderLinkId", params["clOrderId"].asString()});

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

                payload.AddPair({"qty", ssq.str()});
            }

            std::string timeInForce = params.get("timeInForce","GTC").asString(); 
            payload.AddPair({"timeInForce", paramMapping.get(timeInForce, "GoodTillCancel").asString()});

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

bool Bybit::BuildNewOrder(const Json::Value &params, Json::Value& payload)
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
            std::transform(orderType.begin(), orderType.end(), orderType.begin(), ::tolower);
            orderType.at(0) = ::toupper(orderType.at(0));

            std::string orderSide = params.get("side", "Buy").asString();
            std::transform(orderSide.begin(), orderSide.end(), orderSide.begin(), ::tolower);
            orderSide.at(0) = ::toupper(orderSide.at(0));

            payload["symbol"] = params["instrum"].asString();
            payload["side"] = orderSide;
            payload["orderType"] = orderType;

            if(orderType != "MARKET")
            {
                payload["price"] = ssp.str();
                if(stopPrice > 0)
                    payload["stopLoss"] = sspl.str();
                if(profitPrice > 0)
                    payload["takeProfit"] = sstp.str();
            }

            if(params.isMember("posSide") && !params["posSide"].asString().empty())
                payload["positionIdx"] = paramMapping.get(params["posSide"].asString(), 0).asInt();

            if(params.isMember("clOrderId") && !params["clOrderId"].asString().empty())
                payload["orderLinkId"] = params["clOrderId"].asString();

            if(params.isMember("marginMode") && !params["marginMode"].asString().empty())
                payload["marginType"] = params["marginMode"].asString();

            if(params.get("closePosition", false).asBool())
            {
                payload["closePosition"] = true;
            }
            else
            {
                if(params.get("reduceOnly", false).asBool())
                    payload["reduceOnly"] = true;

                payload["qty"] = ssq.str();
            }

            std::string timeInForce = params.get("timeInForce","GTC").asString(); 
            payload["timeInForce"] = paramMapping.get(timeInForce, "GoodTillCancel");

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

OrderData Bybit::NewSpotOrder(const Json::Value& params, bool isdummy) 
{
    OrderData ordData;
    ordData.exchange = "bybit";
    ordData.assetClass = "spot";
    std::string privacy("private");
    try
    {
        // build spot order and send to exchange
        std::string querypath("v5/order/create");
        if(isdummy)
            querypath.append("/test");
        
        cpr::Header headers{};
        cpr::Payload payload{};
        Json::Value order;

        if(!BuildNewOrder(params, order))
        {
            LOG_IF(WARNING, verbose > 2) << "NewSpotOrder failed!";
            return ordData;
        }

        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        std::string postData(Json::writeString(builder, order));

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

OrderData Bybit::NewPerpetualOrder(const Json::Value& params, bool isdummy) 
{
    OrderData ordData;
    ordData.exchange = "bybit";
    ordData.assetClass = "future";
    std::string privacy("private");
    try
    {        
        // build spot order and send to exchange
        std::string querypath("contract/v3/private/order/create");
        
        cpr::Header headers{};
        cpr::Payload payload{};
        Json::Value order;
        
        if(!BuildNewOrder(params, order))
        {
            LOG_IF(WARNING, verbose > 2) << "NewPerpetualOrder failed!";
            return ordData;
        }

        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        std::string postData(Json::writeString(builder, order));

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

OrderData Bybit::NewOptionOrder(const Json::Value& params, bool isdummy) 
{
    OrderData ordData;
    ordData.exchange = "bybit";
    ordData.assetClass = "option";
    std::string privacy("private");

    LOG(WARNING) << "NOT Implemented!";
    
    return ordData;
}

flat_set<OrderData> Bybit::NewSpotBatchOrders(const Json::Value& params)
{
    flat_set<OrderData> orders;

    std::string assetClass = "spot";
    std::string privacy("private");

    LOG(WARNING) << "NOT Implemented!";

    return orders;
}

flat_set<OrderData> Bybit::NewPerpetualBatchOrders(const Json::Value& params)
{
    flat_set<OrderData> orders;

    std::string assetClass = "future";
    std::string privacy("private");
    
    LOG(WARNING) << "NOT Implemented!";

    return orders;
}

OrderData Bybit::GetSpotOrder(const std::string& instrum, std::string id, std::string lid) 
{
    OrderData ordData;
    ordData.exchange = "bybit";
    ordData.assetClass = "spot";
    std::string privacy("private");

    try
    {
        std::string querypath("v5/order/realtime");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"orderLinkId", lid});

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

OrderData Bybit::GetPerpetualOrder(const std::string& instrum, std::string id, std::string lid)
{
    OrderData ordData;
    ordData.exchange = "bybit";
    ordData.assetClass = "future";
    std::string privacy("private");

    try
    { 
        std::string querypath("contract/v3/private/order/unfilled-orders");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"orderLinkId", lid});


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

OrderData Bybit::GetOptionOrder(const std::string& instrum, std::string id, std::string lid)
{
    OrderData ordData;
    ordData.exchange = "bybit";
    ordData.assetClass = "option";
    std::string privacy("private");
    
    LOG(WARNING) << "NOT Implemented!";

    return ordData;
}

flat_set<OrderData> Bybit::GetPerpetualOpenOrders()
{
    flat_set<OrderData> orders;

    std::string assetClass = "future";
    std::string privacy("private");

    try
    {
        std::string querypath("contract/v3/private/order/list");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;

        payload.AddPair({"orderStatus","Active"});

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

bool Bybit::CancelSpotOrder(const std::string& instrum, std::string id, std::string lid) 
{
    bool sucess = false;
    std::string assetClass("spot");
    std::string privacy("private");

    try
    {
        std::string tag("spot"); 
        std::string querypath("v5/order/cancel");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"orderLinkId", lid});

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

bool Bybit::CancelPerpetualOrder(const std::string& instrum, std::string id, std::string lid) 
{
    bool sucess = false;
    std::string assetClass("future");
    std::string privacy("private");

    try
    {
        std::string querypath("contract/v3/private/order/cancel");

        cpr::Header headers{};
        cpr::Payload payload{};
        std::string postData;
        payload.AddPair({"symbol", instrum});
        if(!id.empty())
            payload.AddPair({"orderId", id});
        if(!lid.empty())
            payload.AddPair({"orderLinkId", lid});

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

bool Bybit::CancelOptionOrder(const std::string& instrum, std::string id, std::string lid) 
{
    bool sucess = false;
    std::string assetClass("option");
    std::string privacy("private");

    LOG(WARNING) << "NOT Implemented!";

    return sucess;
}

bool Bybit::CancelBatchOrders(
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

std::vector<StrPair> Bybit::CancelSpotOrders(const std::vector<StrPair>& params) 
{
    std::string assetClass("spot");
    std::string privacy("private");
    std::string querypath("api/v3/batchOrders");
    
    std::vector<StrPair> submmiteds;
    
    LOG(WARNING) << "NOT Implemented!";

    return submmiteds;
}

std::vector<StrPair> Bybit::CancelPerpetualOrders(const std::vector<StrPair>& params) 
{
    std::string assetClass("future");
    std::string privacy("private");
    std::string querypath("contract/v3/private/order/cancel");
    
    std::vector<StrPair> submmiteds;
    
    LOG(WARNING) << "NOT Implemented!";

    return submmiteds;
}

std::vector<StrPair> Bybit::CancelOptionOrders(const std::vector<StrPair>& params) 
{
    std::string assetClass("option");
    std::string privacy("private");
    std::string querypath("eapi/v1/batchOrders");
    
    std::vector<StrPair> submmiteds;
    
    LOG(WARNING) << "NOT Implemented!";

    return submmiteds;
}

Json::Value Bybit::GetLastPerpetualTrade(const std::string& instrum, int limit)
{
    std::string exchange("Bybit");
    std::string assetClass("future");
    std::string privacy("private");

    Json::Value trades;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    try
    { 
        std::string querypath("contract/v3/private/execution/list");

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

flat_set<PositionData> Bybit::GetPerpetualPositions(const std::string& instrum, std::string lid) 
{
    flat_set<PositionData> positions;

    PositionData posData;
    posData.exchange = "bybit";
    posData.assetClass = "future";
    std::string privacy("private");
    try
    { 
        std::string querypath("contract/v3/private/position/list");

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

flat_set<PositionData> Bybit::GetOptionPositions(const std::string& instrum, std::string lid) 
{
    flat_set<PositionData> positions;

    LOG(WARNING) << "NOT Implemented!";

    return positions;
}

void Bybit::InfoParser(const Json::Value& info)
{
    if(info.get("retCode", "-1").asInt() == 0)
    {
        try
        {
            for(const Json::Value& item: info["result"]["list"])
            {
                Filter filter;
                filter.instrum = item["symbol"].asString();
                filter.status = item["status"].asString();
                filter.pxPrecision = 8; //item["pricePrecision"].asDouble();
                filter.qtyPrecision = 8; //item["basePrecision"].asDouble();
                filter.basePrecision = 8; //item["basePrecision"].asInt();
                filter.quotePrecision = 8; //item["quotePrecision"].asInt();
                filter.tickSize = std::stod(item["priceFilter"]["tickSize"].asString());
                filter.maxPrice = std::stod(item["priceFilter"]["maxPrice"].asString());
                filter.stepSize = std::stod(item["lotSizeFilter"]["qtyStep"].asString());
                filter.maxQty = std::stod(item["lotSizeFilter"]["maxOrderQty"].asString());

                filters.insert(filter);

                LOG_IF(INFO, verbose > 1) << "Filter: " << filter;
            }
        }
        catch(std::exception& e)
        {
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "\t";
            LOG_IF(INFO, verbose > 0) 
                << e.what() << "\n" << Json::writeString(builder, info);
        }
    }
}

void Bybit::AuthenticationParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    std::string privacy("private");
    std::string connKey(privacy);
    connKey.append("_").append(tag);
    
    if(connHdlPtrsMap.count(connKey))
    {
        bool success = data.get("success", 0).asBool();
        authenticationMap[connKey] = success;
    }
}

void Bybit::TradesParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {
        if(priceQueue)
        {
            PriceData pxData;
            pxData.exchange = "bybit";
            pxData.assetClass = tag;

            const Json::Value& trade = data["data"];

            // convert timestamp into date, time and sec
            pxData.timestamp = data["T"].asInt64();

            // format date eg: 20190628 12:23:00
            pxData.date = Utils::FormatDate(pxData.timestamp);
            pxData.time = Utils::FormatTime(pxData.timestamp);

            // get instrument from topic
            pxData.instrum = trade["s"].asString();
            pxData.instrum.erase(pxData.instrum.find_last_of('.')+1);
            
            // get tick data transaction info
            pxData.quantity = std::stod(trade["v"].asString());

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

void Bybit::CandlesParser(const Json::Value& data, const std::string& tag, const std::time_t& ts) 
{
    try
    {
        if(candleQueue)
        {
            CandleData candle;
            candle.exchange = "bybit";
            candle.assetClass = tag;

            const Json::Value& kline = data["data"];

            std::string instrum = data.get("topic", "").asString();
            size_t pos = instrum.find_last_of('.');
            if(pos != instrum.npos)
                instrum = instrum.substr(pos+1);

            // convert timestamp into date, time and sec
            candle.timestamp = kline["start"].asInt64();
            candle.date = Utils::FormatDate(candle.timestamp);
            candle.time = Utils::FormatTime(candle.timestamp);

            candle.instrum = instrum;
            candle.open = std::stod(kline["open"].asString());
            candle.high = std::stod(kline["high"].asString());
            candle.low = std::stod(kline["low"].asString());
            candle.close = std::stod(kline["close"].asString());
            candle.volume = std::stod(kline["volume"].asString());

            candleQueue->enqueue(candle);
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

void Bybit::DepthParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
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

void Bybit::TickersParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {
        if(tickerQueue)
        {
            const Json::Value& ticker = data["data"];

            TickerData tickData;
            tickData.exchange = "bybit";
            tickData.assetClass = tag;

            // convert timestamp into date, time and sec
            tickData.timestamp = data["ts"].asInt64();
            
            // get tick data transaction info
            tickData.instrum = ticker["symbol"].asString();
            tickData.bidQty = std::stod(ticker["bid1Size"].asString());
            tickData.askQty = std::stod(ticker["ask1Size"].asString());
            tickData.bid = std::stod(ticker["bid1Price"].asString());
            tickData.ask = std::stod(ticker["ask1Price"].asString());
            
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

void Bybit::OrdersParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {
        if(orderQueue)
        {
            for(const Json::Value& order: data["data"])
            {
                OrderData ordData;
                ordData.exchange = "bybit";
                ordData.assetClass = tag;

                ordData.instrum = order.get("symbol", "").asString();
                ordData.state = order.get("orderStatus","").asString();
                ordData.id = order.get("orderId","").asString();
                ordData.lid = order.get("orderLinkId","").asString();
                ordData.local = false;
                
                ordData.timestamp = std::stoll(order.get("createdTime","0").asString());
                ordData.side = order.get("side","").asString();
                ordData.orderType = order.get("orderType","LIMIT").asString();
                ordData.price = std::stod(order.get("price", "0.0").asString());
                ordData.stopPrice = std::stod(order.get("stopLoss", "0.0").asString());
                ordData.quantity = std::stod(order.get("qty", "0.0").asString());
                ordData.execQuantity = std::stod(order.get("cumExecQty", "0.0").asString());
                ordData.timeInForce = order.get("timeInForce", "GTC").asString();
                ordData.closePosition = order.get("reduceOnly", 0).asBool();
                ordData.posSide = order.get("posSide", "BOTH").asString();

                ordData.date = Utils::FormatDatetime(ordData.timestamp);

                if(orderQueue)
                    orderQueue->enqueue(ordData);
            }
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

OrderData Bybit::OrdersParserGet(const std::string& msg, const std::string& tag)
{
    OrderData ordData;
    ordData.exchange = "bybit";
    ordData.assetClass = tag;
    ordData.local = false;

    Json::Value records;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&records, &errs) && records["retCode"].asInt() == 0)
    {
        if(records.isMember("result") && records["result"].isMember("orderId"))
        {
            ordData.id = records["result"].get("orderId","").asString();
            ordData.lid = records["result"].get("orderLinkId","").asString();
            ordData.timestamp = std::stoll(records.get("time","0").asString());

            return ordData;
        }

        for(const Json::Value& order: records["list"])
        {
            ordData.instrum = order.get("symbol", "").asString();
            ordData.state = order.get("orderStatus","").asString();
            ordData.id = order.get("orderId","").asString();
            ordData.lid = order.get("orderLinkId","").asString();
            ordData.local = false;
            
            ordData.timestamp = std::stoll(order.get("createdTime","0").asString());
            ordData.side = order.get("side","").asString();
            ordData.orderType = order.get("orderType","LIMIT").asString();
            ordData.price = std::stod(order.get("price", "0.0").asString());
            ordData.stopPrice = std::stod(order.get("stopLoss", "0.0").asString());
            ordData.quantity = std::stod(order.get("qty", "0.0").asString());
            ordData.execQuantity = std::stod(order.get("cumExecQty", "0.0").asString());
            ordData.timeInForce = order.get("timeInForce", "GTC").asString();
            ordData.closePosition = order.get("reduceOnly", 0).asBool();

            int edgeMode = order.get("positionIdx",0).asInt();
            ordData.posSide = edgeModesMap.at(edgeMode);

            ordData.date = Utils::FormatDatetime(ordData.timestamp);

            break;
        }
        //ordData.UpdateLocalId();
    }
    else
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(WARNING, verbose > 0) << Json::writeString(builder, records);
    }

    return ordData;
}

flat_set<OrderData> Bybit::BatchOrdersParserGet(const std::string& msg, const std::string& tag)
{
    flat_set<OrderData> orders;
    
    Json::Value records;
    std::string errs;
    bool success = false;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&records, &errs) && records["retCode"].asInt() == 0)
    {
        for(const Json::Value& order: records["result"]["list"])
        {
            OrderData ordData;
            ordData.exchange = "bybit";
            ordData.assetClass = tag;
            ordData.local = false;
            
            ordData.instrum = order.get("symbol", "").asString();
            ordData.state = order.get("orderStatus","").asString();
            ordData.id = order.get("orderId","").asString();
            ordData.lid = order.get("orderLinkId","").asString();
            ordData.local = false;
            
            ordData.timestamp = std::stoll(order.get("createdTime","0").asString());
            ordData.side = order.get("side","").asString();
            ordData.orderType = order.get("orderType","LIMIT").asString();
            ordData.price = std::stod(order.get("price", "0.0").asString());
            ordData.stopPrice = std::stod(order.get("stopLoss", "0.0").asString());
            ordData.quantity = std::stod(order.get("qty", "0.0").asString());
            ordData.execQuantity = std::stod(order.get("cumExecQty", "0.0").asString());
            ordData.timeInForce = order.get("timeInForce", "GTC").asString();
            ordData.closePosition = order.get("reduceOnly", 0).asBool();

            int edgeMode = order.get("positionIdx",0).asInt();
            ordData.posSide = edgeModesMap.at(edgeMode);

            ordData.date = Utils::FormatDatetime(ordData.timestamp);

            //ordData.UpdateLocalId();
            orders.insert(ordData);
            success = true;
        }
    }
    else
    {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        LOG_IF(WARNING, verbose > 0) << Json::writeString(builder, records);
    }

    return orders;
}

void Bybit::PositionsParser(const Json::Value& data, const std::string& tag, const std::time_t& ts)
{
    try
    {           
        for(const Json::Value& item: data["data"])
        {
            PositionData posData;
            posData.exchange = "bybit";
            posData.assetClass = tag;
            posData.local = false;

            posData.instrum = item.get("symbol","").asString();
            posData.side = item.get("side","").asString();
            posData.price = std::stod(item.get("entryPrice","0.0").asString());
            posData.quantity = std::stod(item.get("size","0.0").asString());
            posData.pnl = std::stod(item.get("unrealisedPnl","0.0").asString());
            posData.leverage = std::stoi(item.get("leverage", "1").asString());
            posData.timestamp = std::stoll(item.get("createdTime", "0").asString());
            posData.ltimestamp = posData.timestamp;

            posData.attrs["marginType"] = item.get("tradeMode","");
            posData.attrs["markPrice"] = std::stod(item.get("markPrice","0.0").asString());
            
            int edgeMode = item.get("positionIdx",0).asInt();
            posData.posSide = edgeModesMap.at(edgeMode);
            posData.entryDate = Utils::FormatDatetime(posData.timestamp);
            posData.UpdateLocalId();

            if(positionQueue)
                positionQueue->enqueue(posData);
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

flat_set<PositionData> Bybit::PerpetualPositionParserGet(const std::string& msg, const std::string& tag)
{
    flat_set<PositionData> positions;

    PositionData posData;
    posData.exchange = "bybit";
    posData.assetClass = tag;
    posData.local = false;

    Json::Value records;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader;
    Json::CharReaderBuilder rbuilder;
    reader.reset(rbuilder.newCharReader());

    if(reader->parse(msg.c_str(), msg.c_str() + msg.size(),&records, &errs))
    {
        for(const Json::Value& item: records["result"]["list"])
        {
            posData.instrum = item.get("symbol","").asString();
            posData.side = item.get("side","").asString();
            posData.price = std::stod(item.get("entryPrice","0.0").asString());
            posData.quantity = std::stod(item.get("positionValue","0.0").asString());
            posData.pnl = std::stod(item.get("unrealisedPnl","0.0").asString());
            posData.leverage = std::stoi(item.get("leverage", "1").asString());
            posData.timestamp = std::stoll(item.get("createdTime", "0").asString());
            posData.ltimestamp = posData.timestamp;
            
            posData.attrs["marginType"] = item.get("tradeMode","");
            posData.attrs["tpslMode"] = item.get("tpslMode","");
            posData.attrs["markPrice"] = std::stod(item.get("markPrice","0.0").asString());
            posData.attrs["liqPrice"] = std::stod(item.get("liqPrice","0.0").asString());
            
            int edgeMode = item.get("positionIdx",0).asInt();
            posData.posSide = edgeModesMap.at(edgeMode);
            posData.entryDate = Utils::FormatDatetime(posData.timestamp);
            posData.UpdateLocalId();

            if(posData.IsValid())
                positions.insert(posData);
        }
    }

    return positions;
}

flat_set<PositionData> Bybit::OptionPositionParserGet(const std::string& msg, const std::string& tag)
{
    flat_set<PositionData> positions;

    LOG(WARNING) << "Not Implemented!";

    return positions;
}


std::thread Bybit::StreamParser(MessageQueue& messageQueue, size_t numThreads)
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

                            // get the event name
                            std::string event = record.get("topic", record.get("auth","")).asString();
                            size_t pos = event.find_last_of('.');
                            if(pos != event.npos)
                                event = event.substr(0,pos);

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

void Bybit::BindTradesQueue(ConcurrentQueue<PriceData>* queue)
{
    priceQueue = queue;
}

void Bybit::BindCandlesQueue(ConcurrentQueue<CandleData>* queue)
{
    candleQueue = queue;
}

void Bybit::BindDepthQueue(ConcurrentQueue<Json::Value>* queue)
{
    depthQueue = queue;
}

void Bybit::BindTickerQueue(ConcurrentQueue<TickerData>* queue)
{
    tickerQueue = queue;
}

void Bybit::BindOrderQueue(ConcurrentQueue<OrderData>* queue)
{
    orderQueue = queue;
}

void Bybit::BindPositionQueue(ConcurrentQueue<PositionData>* queue)
{
    positionQueue = queue;
}
}

CONNECTOR_MODULE(stelgic::Bybit, "bybit", "0.0.1");

