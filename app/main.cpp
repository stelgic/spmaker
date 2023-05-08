#include <filesystem>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include "public/IExchange.h"
#include "public/ModuleLoader.h"
#include "public/LogHelper.h"
#include "public/JsonHelper.h"
#include "public/SpinLock.h"

namespace fs = std::filesystem;
namespace po = boost::program_options;
using namespace stelgic;

int verbosity = 1;
int NUM_THREADS = 8;
int CAPITAL = 5000;
int RISK_CAPITAL = 1000;
int ORDER_TIMEOUT = 1; // seconds

IExchange* connector = nullptr;
std::atomic_bool running = {1};

// close connection on crtl + c
void Terminate()
{
    if(connector)
        connector->Stop();

    ::internal::shutDownLogging();
}


bool getCommandLineArgs(int argc, char** argv)
{
    // parse command line argument and store 
    // key value pair into map
    po::options_description desc("Craftor commandline options");

    desc.add_options()
    ("help,h", "produce help message")
    ("risk,r", po::value<int>(&RISK_CAPITAL)->default_value(1000), "capital to risk per trade")
    ("capital,c", po::value<int>(&CAPITAL)->default_value(6000), "max capital in USD")
    ("threads,t", po::value<int>(&NUM_THREADS)->default_value(8), "num threads to process data")
    ("timeout,x", po::value<int>(&ORDER_TIMEOUT)->default_value(2), "cancel order if not filled in n seconds")
    ("verbose,v", po::value<int>(&verbosity)->default_value(1), "Logging verbosity level (0,1,2)");

    // Parse command line arguments
    bool success = false;
    try
    {
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).run(), vm);
        po::notify(vm);
        success = true;
    }
    catch(boost::exception const& e)
    {
        std::string msg = boost::diagnostic_information_what(e);
        LOG(WARNING) << msg;
    }

    return success;
}

int main(int argc, char** argv)
{
    InitializeLogger();

    LOG(INFO) << "STARTING...";

    atexit(Terminate);
    // Stop processing on SIGINT
    std::signal(SIGINT, [](int) 
    {
        running = {0};
        LOG(WARNING) << "Program interrupted...";
        _Exit(EXIT_FAILURE);
    });

    if(!getCommandLineArgs(argc, argv))
    {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        _Exit(EXIT_FAILURE);
    }

    /** ########################################################
     * @brief load shared library connector
     * ########################################################
     */

    bool success = false;
    std::string err;
#if defined(_WIN32) || defined(_WIN64)
    std::string MODULE_PATH = fs::canonical(std::string("../modules/binance.dll")).string();
#elif defined(__linux__)
    std::string MODULE_PATH = fs::canonical(std::string("../modules/libbinance.so")).string();
#endif
    std::string CONFIG_PATH = fs::canonical(std::string("../configs/connector.config")).string();

    ModuleLoader<IExchange> module(MODULE_PATH);
    LOG(INFO) << "LODING " << MODULE_PATH << " ...";
    std::tie(success, err) = module.Open();
    if(!success)
    {
        LOG(WARNING) << "Failed to load "<< MODULE_PATH << "! " << err;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        _Exit(EXIT_FAILURE);
    }

    LOG(INFO) << "LOADED " << MODULE_PATH << " successful!";

    // create instance of connector
    IExchange* connector = module.GetInstance();
    if(connector == nullptr)
    {
        LOG(WARNING) << "Failed to create instance of connector " << module.GetName();
        std::this_thread::sleep_for(std::chrono::seconds(2));
        _Exit(EXIT_FAILURE);
    }

    /** ########################################################
     * @brief initialize and connector with configs
     * ########################################################
     */
    // Load exchange json configure file
    Json::Value connParams = LoadJsonFromFile(CONFIG_PATH, err);
    if(connParams.isNull())
    {
        LOG(WARNING) << "Failed to load " << CONFIG_PATH;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        _Exit(EXIT_FAILURE);
    }

    // update num session to match dispatcher
    connParams["numSessions"] = (NUM_THREADS * 2);

    // Initiliaze connector
    LOG(INFO) << "Initializing...";
    connector->Init(connParams["binance"], verbosity);
    if(!connector->IsInitialized())
    {
        LOG(WARNING) << "Failed to Initialize connector";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        _Exit(EXIT_FAILURE);
    } 
    
    SpinLock tickerLock;
    SpinLock orderLock;

    bool resetLimitOn = false;
    std::atomic<int> USED_CAPITAL = 0;
    std::atomic<int64_t> counter = {0};
    std::atomic<int> usedCounter = {0};
    
    std::vector<std::thread> workers;
    flat_set<TickerData> instrumTickers;
    flat_set<OrderData> openOders;
    flat_set<OrderData> openingOrders;
    flat_set<OrderData> closingOrders;
    flat_set<std::string> cancelingOrders;
    std::unordered_map<std::string, std::atomic<int>> positions;

    const auto& filters = connector->GetFilters();

    // get all open orders
    openOders = connector->GetPerpetualOpenOrders();

    /** ################################################################
     * @brief Consume ticker data and implement spread market maker
     * #################################################################
     */
    workers.push_back(std::thread([&]()
    {
        boost::asio::thread_pool pool(NUM_THREADS);
        ConcurrentQueue<TickerData> tickerQueue;
        connector->BindTickerQueue(&tickerQueue);

        while(running)
        {
            TickerData tickers[10];
            size_t n = tickerQueue.try_dequeue_bulk(tickers, 10);
            if(counter < 20)
            {
                ++counter;
                continue;
            }

            for(size_t j=0; j<n; ++j)
            {
                TickerData ticker(tickers[j]);
                if(positions.count(ticker.instrum) == 0 || positions.at(ticker.instrum) < 0)
                {
                    positions[ticker.instrum] = {0};
                }

                bool hasPosition = positions.at(ticker.instrum);
                bool hasBalance = (CAPITAL - USED_CAPITAL) > RISK_CAPITAL;
                bool hitThreadLimit = usedCounter > NUM_THREADS;
                bool hitRequestLimit = connector->IsRequestLimitHit();

                Filter filter;
                filter.instrum = ticker.instrum;
                auto iter = filters.find(filter);

                /** ######################################################
                 * @brief Implement vVery simple strategy based on spread
                 * #######################################################
                 */
                double spread = (ticker.ask - ticker.bid) * iter->tickSize;
                
                // OPENING A POSITION
                if(!hasPosition && !hitThreadLimit && hasBalance 
                    && spread >= 0.03 && !hitRequestLimit)
                {
                    ++usedCounter;
                    resetLimitOn = false;
                    USED_CAPITAL += RISK_CAPITAL;

                    // dispatch create order 5 per request
                    boost::asio::dispatch(pool, [&, ticker]()
                    {
                        // create buy open order
                        Json::Value postOrder;
                        postOrder["instrum"] = ticker.instrum;
                        postOrder["orderType"] = "LIMIT";
                        postOrder["timeinforce"] = "GTC";
                        postOrder["side"] = "BUY";
                        postOrder["posSide"] = "BOTH";
                        postOrder["postOnly"] = true;
                        postOrder["price"] = (ticker.bid + iter->stepSize); // set 5th best price
                        postOrder["quantity"] = (RISK_CAPITAL / ticker.bid);
                        
                        OrderData order = connector->NewPerpetualOrder(postOrder);

                        orderLock.Lock();
                        if(order.state == "PARTIALLY_FILLED" || order.state == "FILLED")
                        {
                            openingOrders.insert(order);
                            ++positions.at(order.instrum);
                        }
                        else if(order.state == "NEW")
                            openOders.insert(order);
                        orderLock.Unlock();

                        --usedCounter;
                    });
                }
                // CLOSING POSITION
                else if(hasPosition && spread >= 0.03)
                {
                    orderLock.Lock();
                    OrderData order = *openingOrders.find(order);
                    orderLock.Unlock();

                    // computes position spread using current bid - order entry price
                    double posSpread = (ticker.bid - order.price);
                    if(abs(posSpread) >= 0.2 && closingOrders.count(order) == 0)
                    {
                        closingOrders.insert(order);

                        // dispatch create order 5 per request
                        boost::asio::dispatch(pool, [&, ticker, order, posSpread]()
                        {
                            Filter filter;
                            filter.instrum = ticker.instrum;
                            auto iter = filters.find(filter);

                            // create buy open order
                            Json::Value reduceOrder;
                            reduceOrder["instrum"] = ticker.instrum;
                            reduceOrder["orderType"] = "LIMIT";
                            reduceOrder["timeinforce"] = "GTC";
                            reduceOrder["side"] = "SELL";
                            reduceOrder["posSide"] = "BOTH";
                            reduceOrder["reduceOnly"] = true;
                            reduceOrder["price"] = ticker.ask - filter.tickSize; // set 5th best price
                            reduceOrder["quantity"] = order.execQuantity;
                            
                            OrderData closeOrder = connector->NewPerpetualOrder(reduceOrder);
                            if(closeOrder.state == "FILLED")
                            {
                                orderLock.Lock();
                                openingOrders.erase(order);
                                closingOrders.erase(order);
                                --positions.at(order.instrum);
                                orderLock.Unlock();

                                USED_CAPITAL -= RISK_CAPITAL;
                            }
                            else if(closeOrder.state == "NEW" || closeOrder.state == "PARTIALLY_FILLED")
                            {
                                orderLock.Lock();
                                closingOrders.erase(order);
                                closingOrders.insert(closeOrder);
                                orderLock.Unlock();
                            }
                        });
                    }
                }

                if(!resetLimitOn && hitRequestLimit)
                {
                    LOG_IF(WARNING, verbosity > 0) << "Hit Request Limit!";
                    connector->ResetRequestLimitTimer(61000);
                    resetLimitOn = true;
                }
            }
        }

        pool.join();
    }));


    /** ########################################################
     * @brief Update and manage orders by status
     * ########################################################
     */
    workers.push_back(std::thread([&]()
    {
        boost::asio::thread_pool pool(4);
        ConcurrentQueue<OrderData> orderQueue;
        connector->BindOrderQueue(&orderQueue);

        while(running)
        {
            OrderData orders[10];
            size_t n = orderQueue.try_dequeue_bulk(orders, 10);
            for(size_t j=0; j < n; ++j)
            {
                OrderData order(orders[j]);
                
                // dispatch create order 5 per request
                boost::asio::dispatch(pool, [&, order]()
                {
                    orderLock.Lock();
                    if(order.state == "PARTIALLY_FILLED")
                    {
                        if(!order.closePosition)
                        {
                            openOders.insert(order);
                            if(openingOrders.erase(order))
                            {
                                openingOrders.erase(order);
                                --positions.at(order.instrum);
                            }
                            openingOrders.insert(order);
                            ++positions.at(order.instrum);
                        }
                        else
                            closingOrders.insert(order);
                    }
                    else if(order.state == "FILLED")
                    {
                        if(!order.closePosition)
                        {
                            openOders.erase(order);
                            openingOrders.erase(order);
                            openingOrders.insert(order);
                            --positions.at(order.instrum);
                        }
                        else
                        {
                            openingOrders.erase(order);
                            closingOrders.erase(order);
                            --positions.at(order.instrum);
                            USED_CAPITAL -= RISK_CAPITAL;
                        }
                    }
                    else if(order.state == "CANCELED")
                    {
                        if(!order.closePosition)
                        {
                            openOders.erase(order);
                        }
                        else
                            closingOrders.erase(order);
                    }
                    
                    orderLock.Unlock();
                });

                LOG_IF(INFO, verbosity > 0) << order;
            }
        }

        pool.join();
    }));


    /** ########################################################
     * @brief Cancel open orders if not filled in x seconds
     * ########################################################
     */
    workers.push_back(std::thread([&]()
    {
        boost::asio::thread_pool pool(NUM_THREADS);
        auto epoch = std::chrono::system_clock::now().time_since_epoch().count();

        while(running)
        {
            epoch = std::chrono::system_clock::now().time_since_epoch().count();

            orderLock.Lock();
            flat_set<OrderData> orders(openOders.begin(), openOders.end());
            orders.insert(closingOrders.begin(), closingOrders.end());
            orderLock.Unlock();

            for(OrderData& order: orders)
            {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::milliseconds(epoch) - std::chrono::milliseconds(order.timestamp));

                bool cancelRequest = cancelingOrders.count(order.id);
                if(!cancelRequest && order.state == "NEW" && elapsed.count() > ORDER_TIMEOUT)
                {
                    orderLock.Lock();
                    cancelingOrders.insert(order.id);
                    orderLock.Unlock();

                    // dispatch create order 5 per request
                    boost::asio::dispatch(pool, [&, order]()
                    {
                        bool canceled = false;
                        if(connector->CancelPerpetualOrder(order.instrum, order.id))
                        {
                            canceled = true;
                        }
                        else
                        {
                            OrderData queryOrder = connector->GetPerpetualOrder(order.instrum, order.id);
                            if(!queryOrder.IsValid())
                            {
                                canceled = true;
                            }
                        }

                        if(canceled)
                        {
                            orderLock.Lock();
                            if(!order.closePosition)
                            {
                                openOders.erase(order);
                                USED_CAPITAL -= RISK_CAPITAL;
                            }
                            else
                            {
                                closingOrders.erase(order);
                            }
                            orderLock.Unlock();
                        }

                        orderLock.Lock();
                        cancelingOrders.erase(order.id);
                        orderLock.Unlock();
                    });
                }

                if(order.closePosition && order.state == "FILLED")
                {
                    orderLock.Lock();
                    if(openingOrders.count(order))
                    {
                        openingOrders.erase(order);
                        --positions.at(order.instrum);
                    }
                    closingOrders.erase(order);
                    orderLock.Unlock();
                }
                else
                {
                    orderLock.Lock();
                    closingOrders.erase(order);
                    orderLock.Unlock();
                }
            }
        }

        pool.join();
    }));
    
    /** ########################################################
     * @brief Connect and subscribe to websocket channels
     * ########################################################
     */

    // start connector threads
    workers.push_back(connector->KeepAlive());

    // connect and subscribe to exchange 
    ConnState state = connector->Connect(connParams["binance"]);
    if(state != ConnState::Opened)
    {
        LOG(WARNING) << "Failed to connect exchange";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        _Exit(EXIT_FAILURE);
    }

    // test connectivity delay using ping/pong
    connector->TestConnectivity();
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // subscribe to websocket channels
    connector->Subscribe(connParams["binance"]);

    for(auto& task: workers)
        task.join();

    return EXIT_SUCCESS;
}
