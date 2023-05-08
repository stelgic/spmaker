#pragma once

#include <memory>
#include <stdexcept>

#if defined(linux) || defined(__linux__)
#include <dlfcn.h>
#endif

namespace stelgic
{
class ModuleLoaderException: public std::runtime_error
{
    ModuleLoaderException(const std::string& msg)
        :runtime_error(msg.c_str()){}
    ModuleLoaderException(const ModuleLoaderException&) = delete;
};

template<class IModule>
struct ModuleInfo
{
public:
    using type = IModule;

    ModuleInfo(){}
    virtual ~ModuleInfo(){}
    std::string name;
    std::string version;
    std::string filename; 
};

template<class IModule>
class ModuleLoader
{
public:
    ModuleLoader(){}
#if defined(linux) || defined(__linux__)
    ModuleLoader(const std::string& filename) : 
        flags(RTLD_LAZY|RTLD_LOCAL), path(filename) {}
#elif defined(_WIN32) || defined(_WIN64)
    ModuleLoader(const std::string& filename) :
        flags(0), path(filename) {}
#endif

    ModuleLoader(const ModuleLoader& other) : 
        flags(other.flags), path(other.path), loaded(false){}

    virtual ~ModuleLoader()
    {
        Close();
        handle = 0;
    }

    bool IsLoaded() const
    {
        return loaded;
    }

    std::string GetName() const
    {
        return std::string(name());
    }

    std::string GetVersion() const
    {
        return std::string(version());
    }

    IModule* GetInstance()
    {
        if(instance == nullptr)
            instance.reset(reinterpret_cast<IModule*>(create()));
        return instance.get();
    }

    std::pair<bool,std::string> Open() 
    {
        loaded = false;
        std::string error;
#if defined(linux) || defined(__linux__)
        handle = dlopen(path.c_str(), flags);
        if(handle != 0)
        {
            create = (IModule* (*)())dlsym(handle, "Create");
            name = (char* (*)())dlsym(handle, "Name");
            version = (char* (*)())dlsym(handle, "Version");
            if(create != NULL && name != NULL && version != NULL)
                loaded = true;
        }
        else
            error = std::string(dlerror());

#elif defined(_WIN32) || defined(_WIN64)
        // open dynamic libraries window
        handle = LoadLibrary(path.c_str());
        if (handle != NULL)
        {
            create = (IModule* (*)())GetProcAddress(handle, "Create");
            name = (char* (*)())GetProcAddress(handle, "Name");
            version = (char* (*)())GetProcAddress(handle, "Version");
            if (create != NULL && name != NULL && version != NULL)
                loaded = true;
        }
#endif
        return std::make_pair(loaded, error);
    }

    std::pair<bool,std::string> Close() 
    {
        std::string error;
#if defined(linux) || defined(__linux__)
        if(handle != 0)
        {
            int refs = dlclose(handle);
            if(refs == 0)
                loaded = false;
            else
                error.append("Module in use. ").append(path);
        }
#elif defined(_WIN32) || defined(_WIN64)
        // close dynamic libraries window
        if (handle != NULL) 
        { 
            BOOL refs = FreeLibrary(handle);
            if (refs)
                loaded = false;
            else
                error.append("Module in use. ").append(path);
        }
#endif
        return std::make_pair(loaded, error);
    }

protected:
#if defined(linux) || defined(__linux__)
    void* handle;
#else
    HMODULE handle;
#endif
    char* (*name)();
    char* (*version)();
    IModule* (*create)();

    bool loaded;
    const int flags;
    std::string path;
    std::shared_ptr<IModule> instance;
};

template<class T>
using ModuleInfoPtr = std::shared_ptr<ModuleInfo<T>>;

template<class T>
using ModuleLoaderPtr = std::shared_ptr<ModuleLoader<T>>;

template<typename...Func>
struct VariantOverload : Func... {
    using Func::operator()...;
};

template<typename...Func> VariantOverload(Func...) -> VariantOverload<Func...>;

}

