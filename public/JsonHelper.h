#include <fstream>
#include <json/json.h>

Json::Value LoadJsonFromFile(const std::string &filename, std::string& errs)
{
    Json::Value data;
    Json::CharReaderBuilder rbuilder;

    std::ifstream stream;
    stream.open(filename);

    if (stream.is_open())
    {
        if (!Json::parseFromStream(rbuilder, stream, &data, &errs))
            data = Json::Value();
        stream.close();
    }

    return data;
}

