#include "TurnAllocator.h"

#include "logging.h"

namespace faf {

void turn_dns_resolved_handler(int err, const struct sa *srv, void *arg)
{
  static_cast<TurnAllocator*>(arg)->_turn_dns_resolved_handler(err, srv);
}

void turnc_handler(int err, uint16_t scode, const char *reason,
        const struct sa *relay, const struct sa *mapped,
        const struct stun_msg *msg, void *arg)
{
  static_cast<TurnAllocator*>(arg)->_turnc_handler(err,
                                              scode,
                                              reason,
                                              relay,
                                              mapped,
                                              msg);
}

TurnAllocator::TurnAllocator(TurnServerInfo const& info,
                             std::shared_ptr<UdpSocket> const& socket,
                             struct dnsc* dnsc,
                             AllocationHandler const& h):
  _info(info),
  _socket(socket),
  _handler(h)
{
  _stun_conf= {STUN_DEFAULT_RTO,
               STUN_DEFAULT_RC,
               STUN_DEFAULT_RM,
               STUN_DEFAULT_TI,
               0x00
              };

  auto err = stun_server_discover(&_dnsq,
                             dnsc,
                             stun_usage_relay,
                             stun_proto_udp,
                             AF_INET,
                             info.hostname.c_str(),
                             info.port,
                             turn_dns_resolved_handler,
                             this);
  if (err)
  {
    FAF_LOG_ERROR << "error in stun_server_discover";
    return;
  }
}

TurnAllocator::~TurnAllocator()
{
  mem_deref(_dnsq);
  mem_deref(_turnc);
}

void TurnAllocator::_turn_dns_resolved_handler(int err, const struct sa *srv)
{
  if (err)
  {
    FAF_LOG_ERROR << "error resolving STUN server";
  }
  else
  {
    //FAF_LOG_DEBUG << "stun server resolved";
    _turn_sa = srv;

    auto err = turnc_alloc(&_turnc,
                           &_stun_conf,
                           IPPROTO_UDP,
                           _socket->socket(),
                           -10,
                           _turn_sa,
                           _info.username.c_str(),
                           _info.credential.c_str(),
                           TURN_DEFAULT_LIFETIME,
                           turnc_handler,
                           this);
    if (err)
    {
      FAF_LOG_ERROR << "error in turnc_alloc";
      return;
    }

  }
}

void TurnAllocator::_turnc_handler(int err, uint16_t scode, const char *reason,
                            const struct sa *relay, const struct sa *mapped,
                            const struct stun_msg *msg)
{
  FAF_LOG_DEBUG << "_turnc_handler";

#if 0

  struct comp *comp = arg;
  struct mnat_media *m = comp->m;
  struct ice_cand *lcand;
  (void)msg;

  --m->nstun;

  /* TURN failed, so we destroy the client */
  if (err || scode) {
    icem_set_turn_client(m->icem, comp->id, NULL);
  }

  if (err) {
    warning("{%u} TURN Client error: %m\n",
            comp->id, err);
    goto out;
  }

  if (scode) {
    warning("{%u} TURN Client error: %u %s\n",
            comp->id, scode, reason);
    err = send_binding_request(m, comp);
    if (err)
      goto out;
    return;
  }

  debug("ice: relay gathered for comp %u (%u %s)\n",
        comp->id, scode, reason);

  lcand = icem_cand_find(icem_lcandl(m->icem), comp->id, NULL);
  if (!lcand)
    goto out;

  if (!sa_cmp(relay, icem_lcand_addr(icem_lcand_base(lcand)), SA_ALL)) {
    err = icem_lcand_add(m->icem, icem_lcand_base(lcand),
             ICE_CAND_TYPE_RELAY, relay);
  }

  if (mapped) {
    err |= icem_lcand_add(m->icem, icem_lcand_base(lcand),
              ICE_CAND_TYPE_SRFLX, mapped);
  }
  else {
    err |= send_binding_request(m, comp);
  }

 out:
  call_gather_handler(err, m, scode, reason);

#endif
}

} // namespace faf
