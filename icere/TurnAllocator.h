#pragma once

#include <memory>
#include <functional>

#include <re.h>

#include "UdpSocket.h"
#include "types.h"

namespace faf {

class TurnAllocator
{
public:
  using AllocationHandler = std::function<void (bool, TurnAllocator*, struct sa*)>;

  TurnAllocator(TurnServerInfo const& info,
                std::shared_ptr<UdpSocket> const& socket,
                struct dnsc* dnsc,
                AllocationHandler const& h);
  virtual ~TurnAllocator();

protected:

  friend void turn_dns_resolved_handler(int err, const struct sa *srv, void *arg);
  void _turn_dns_resolved_handler(int err, const struct sa *srv);

  friend void turnc_handler(int err, uint16_t scode, const char *reason,
                            const struct sa *relay, const struct sa *mapped,
                            const struct stun_msg *msg, void *arg);
  void _turnc_handler(int err, uint16_t scode, const char *reason,
                              const struct sa *relay, const struct sa *mapped,
                              const struct stun_msg *msg);

  TurnServerInfo _info;
  std::shared_ptr<UdpSocket> _socket;
  AllocationHandler _handler;
  struct stun_conf _stun_conf;
  stun_dns* _dnsq = nullptr;
  const sa* _turn_sa = nullptr;
  turnc* _turnc = nullptr;
};

} // namespace faf
