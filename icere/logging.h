#pragma once

#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace faf
{
struct logger
{
    logger(std::ostream& os):
      _os(os)
    {
      std::time_t t = std::time(nullptr);
      std::tm tm = *std::localtime(&t);
      os << "ICE: " << std::put_time(&tm, "%F-%T ");
    }

    ~logger()
    {
      _os << _ss.str() << std::endl;
    }

public:
    // accepts just about anything
    template<class T>
    logger &operator<<(const T &x)
    {
      _ss << x;
      return *this;
    }
private:
    std::ostringstream _ss;
    std::ostream& _os;
};

}

#define FAF_LOG_TRACE faf::logger(std::cout) << "[trace] "
#define FAF_LOG_DEBUG faf::logger(std::cout) << "[debug] "
#define FAF_LOG_INFO  faf::logger(std::cout) << "[info] "
#define FAF_LOG_WARN  faf::logger(std::cerr) << "[warn] "
#define FAF_LOG_ERROR faf::logger(std::cerr) << "[error] "

