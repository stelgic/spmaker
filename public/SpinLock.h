#pragma once

#include <atomic>

class SpinLock
{
public:
    SpinLock(){}
    ~SpinLock()
    {
        Interrup();
    }

    /**
     * @brief reference external variable to stop spining
     * 
     * @param stop 
     */
    void Init(std::atomic_bool& stop)
    {
        _stop = &stop;
    }

    void Lock()
    {
        // spining until get lock
        while (!_stop && _flag.test_and_set(std::memory_order_release));
    }

    void Unlock()
    {
        _flag.clear(std::memory_order_acquire); // release
    }

    void Interrup()
    {
        _stop = {1};
    }

protected:
    std::atomic_bool _stop = ATOMIC_FLAG_INIT;
    std::atomic_flag _flag = ATOMIC_FLAG_INIT;
};
