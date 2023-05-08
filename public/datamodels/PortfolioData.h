#pragma

#include <set>
#include <string>
#include "ExchangeData.h"

namespace stelgic
{
class PortfolioData
{
public:
    PortfolioData() : active(false), riskLimit(1.0f), leverage(1.0f), capital(0.0) {}
    virtual ~PortfolioData() {}
    
    bool active;
    float riskLimit;
    float leverage;
    double capital;
    std::string name;
    std::string type;
    std::string currency;
    std::set<std::string> instruments;
    std::set<std::string> strategies;
    std::set<ExchangeData> balances;
    std::pair<int,int> marketTimes;
};
}
