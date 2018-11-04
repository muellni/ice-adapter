#pragma once

#include <string>
#include <cstdint>

namespace faf
{

struct StunServerInfo
{
  std::string hostname;
  uint16_t port;
};

struct TurnServerInfo : public StunServerInfo
{
  std::string username;
  std::string credential;
};

}
