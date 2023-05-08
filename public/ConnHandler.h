#pragma once

//#include "public/IExchange.h"

using namespace moodycamel;

namespace stelgic
{
class ConnHandler
{
public:
    using ptr=websocketpp::lib::shared_ptr<ConnHandler>;
    using ScopedLock = websocketpp::lib::lock_guard<websocketpp::lib::mutex>;

    ConnHandler()
    {
        messageQueue = ConcurrentQueue<StrPair>(2000UL);
    }

    ConnHandler(WebClient::connection_ptr con_ptr, 
            websocketpp::connection_hdl hdl, 
            std::string uri, std::string connTag) 
        : con(con_ptr), connHdl(hdl), url(uri), tag(connTag){}

    virtual ~ConnHandler(){}

    static ContextPtr onInitTLS(websocketpp::connection_hdl hdl)
    {
        ContextPtr ctx(new websocketpp::lib::asio::ssl::context(
            websocketpp::lib::asio::ssl::context::sslv23_client));

        try {
            ctx->set_verify_mode(websocketpp::lib::asio::ssl::verify_none);
        } catch (std::exception& e) {
            std::stringstream ssreason;
        }
        return ctx;
    }

    void onOpen(WebClient* c, websocketpp::connection_hdl hdl) 
    {
        pingTimeout = {0};
        websocketpp::lib::error_code ec;
        status = ConnState::Opening;

        messageQueue.enqueue({tag, std::string("Opening...")});
        con = c->get_con_from_hdl(hdl, ec);
        if(ec)
        {
            messageQueue.enqueue({tag, ec.message()});
            return;
        }

        ScopedLock guard(mlock);
        status = ConnState::Opened;
        messageQueue.enqueue({tag, std::string("Connection Opened.")});
    }

    void onFail(WebClient* c, websocketpp::connection_hdl hdl) 
    {
        pingTimeout = {0};

        con = c->get_con_from_hdl(hdl);
        std::stringstream ssreason;
        ssreason << "Connection Closed" << ": " << con->get_ec().message();
        messageQueue.enqueue({tag, ssreason.str()});

        ScopedLock guard(mlock);
        status = ConnState::Failed;
    }

    void onClose(WebClient* c, websocketpp::connection_hdl hdl) 
    {
        pingTimeout = {0};
        
        con = c->get_con_from_hdl(hdl);
        std::stringstream ssreason;
        websocketpp::close::status::value code = con->get_remote_close_code();
        
        ssreason << "Connection Closed" << ": "
             << "close code: " << code << " (" 
            << websocketpp::close::status::get_string(code) 
            << "), close reason: " << con->get_remote_close_reason();

        messageQueue.enqueue({tag, ssreason.str()});

        ScopedLock guard(mlock);
        if(code == websocketpp::close::status::abnormal_close) 
            status = ConnState::Abnormal;
        else
            status = ConnState::Closed;
    }

    void onMessage(websocketpp::connection_hdl, WebClient::message_ptr msg) 
    {
        messageQueue.enqueue({tag, msg->get_payload()});
    }

    bool onPing(WebClient * c, websocketpp::connection_hdl hdl)
    {
        if(status == ConnState::Closed) 
            return false;  
         
        websocketpp::lib::error_code ec;
        con->pong("0xA", ec);
        if (ec) 
        {
            messageQueue.enqueue({tag, ec.message()});
            return false;
        }
        return true;
    }

    void onPong(WebClient * c, websocketpp::connection_hdl hdl)
    {
        pongRecvTime = Utils::GetMilliseconds();
    }

    void onPongTimeout(WebClient * c, websocketpp::connection_hdl hdl)
    {
        pingTimeout = {1};
        messageQueue.enqueue({tag, "Pong timeout!"});
    }

    websocketpp::connection_hdl GetHandler() const 
    {
        return connHdl;
    }

    WebClient::connection_ptr GetConnection() const
    {
        return con;
    }

    ConnState GetStatus() 
    {
        ScopedLock guard(mlock);
        websocketpp::session::state::value state = con->get_state();
        switch (state)
        {
        case websocketpp::session::state::connecting:
            status = ConnState::Opening;
            break;
        case websocketpp::session::state::open:
            status = ConnState::Opened;
            break;
        case websocketpp::session::state::closed:
            status = ConnState::Closed;
            break;
        default:
            break;
        }

        // override status
        if(pingTimeout)
            status = ConnState::Abnormal;

        return status;
    }

    std::string GetServer() const
    {
        return server;
    }

    std::string GetUrl() const
    {
        return url;
    }

    std::string GetTag() const
    {
        return tag;
    }

    void SetUrl(const std::string& inUrl)
    {
        url = inUrl;
    }

    void SetStatus(const ConnState& inStatus)
    {
        status = inStatus;
    }

    MessageQueue& GetQueue()
    {
        return messageQueue;
    }

    std::atomic<int64_t>& GetPongRecvTime()
    {
        return pongRecvTime;
    }

private:
    std::atomic_bool pingTimeout = ATOMIC_FLAG_INIT;
    std::atomic<int64_t> pongRecvTime = ATOMIC_FLAG_INIT;

    std::string url;
    std::string server;
    std::string tag;

    ConnState status;
    websocketpp::lib::mutex mlock;
    WebClient::connection_ptr con;
    websocketpp::connection_hdl connHdl;

    MessageQueue messageQueue;
};
}
