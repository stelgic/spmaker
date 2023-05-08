#pragma once

#include <memory>
#include <unordered_map>
#include "ModuleLoader.h"
#include "IDataParser.h"
#include "IExchange.h"
#include "IDataProcessor.h"
#include "IStrategy.h"

namespace stelgic
{
    using ProcessorModulesInfo = std::unordered_map<std::string,ModuleInfoPtr<IDataProcessor>>;
    using ExchangeModulesInfo = std::unordered_map<std::string,ModuleInfoPtr<IExchange>>;
    using ParserModulesInfo = std::unordered_map<std::string,ModuleInfoPtr<IDataParser>>;
    using ParserModulesInfo = std::unordered_map<std::string,ModuleInfoPtr<IDataParser>>;
    using StrategyModulesInfo = std::unordered_map<std::string,ModuleInfoPtr<IStrategy>>;

    using ModuleInstance = std::variant<ModuleLoaderPtr<IDataProcessor>,
                                        ModuleLoaderPtr<IExchange>,
                                        ModuleLoaderPtr<IDataParser>,
                                        ModuleLoaderPtr<IStrategy>>;
                                        
    using ModuleInstances = std::unordered_map<std::string, ModuleInstance>;
}
