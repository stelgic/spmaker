#pragma once

#include <string>
#include <sstream>
#include <vector>
#include <atomic>
#include "public/IDataProcessor.h"


namespace stelgic
{
/** struct data container - bars, indicators, order book */
struct StrategyInputData
{
    /** prevent data race on reserve outdata */
    std::atomic_flag lock = ATOMIC_FLAG_INIT;
    /** single instrument OHLCV data length */
    const int64_t& perInstrumBarsLenght;
    /** per OHLCV data point, default 5 */
    const int& perBarsFieldCount;
    /** market depth data point: bids + asks */
    const std::set<std::string>& instruments;
    /** store OHLCV for multiple instruments */
    const std::vector<double>& flatBars;
    /** store computed indicators */
    IndicatorList& indicators;
    /** store data timestamp. for backtesting use last bar timestamp */
    int64_t timestamp;

    StrategyInputData(const int64_t& instrumBarsLenght, 
                        const int& barsFieldCount, 
                        const std::set<std::string>& instrums,
                        const std::vector<double>& inFlatBars,
                        IndicatorList& indicators,
                        const int64_t& epoch)
        : perInstrumBarsLenght(instrumBarsLenght), 
          perBarsFieldCount(barsFieldCount),
          instruments(instrums), 
          flatBars(inFlatBars),
          indicators(indicators), 
          timestamp(epoch) {}
};
}
