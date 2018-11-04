#pragma once

#include <memory>
#include <functional>

#include <re.h>

#include "UdpSocket.h"
#include "types.h"

namespace faf {

class StunRequester
{
public:
  using RequestHandler = std::function<void (bool, StunRequester*, struct sa*)>;

  StunRequester(StunServerInfo const& stunserver,
                std::shared_ptr<UdpSocket> const& socket,
                struct dnsc* dnsc,
                RequestHandler const& h);
  virtual ~StunRequester();

  std::shared_ptr<UdpSocket> const& socket() const;
protected:
  void _send_binding_request();

  friend void stun_ind_handler(struct stun_msg *msg, void *arg);
  void _stun_ind_handler(struct stun_msg *msg);

  friend void stun_dns_resolved_handler(int err, const struct sa *srv, void *arg);
  void _stun_dns_resolved_handler(int err, const struct sa *srv);

  friend void stun_resp_handler(int err, uint16_t scode, const char *reason,
                                const struct stun_msg *msg, void *arg);
  void _stun_resp_handler(int err, uint16_t scode, const char *reason,
                          const struct stun_msg *msg);

  std::shared_ptr<UdpSocket> _socket;
  stun_dns* _dnsq = nullptr;
  stun* _stun = nullptr;
  const sa* _stun_sa = nullptr;
  struct stun_conf _stun_conf;
  stun_ctrans* _ct_gath = nullptr;

  RequestHandler _handler;

};

} // namespace faf
