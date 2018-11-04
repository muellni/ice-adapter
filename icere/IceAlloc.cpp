#include "IceAlloc.h"
#include "logging.h"

#include <chrono>
#include <cmath>

#include <re_sha.h>

void dns_handler(int err, const struct sa *srv, void *arg)
{
  static_cast<IceAlloc*>(arg)->_dns_handler(err, srv);
}

bool net_ifaddr_handler(const char *ifname, const struct sa *sa, void *arg)
{
  return static_cast<IceAlloc*>(arg)->_ifaddr_handler(ifname, sa);
}

void stun_ind_handler(struct stun_msg *msg, void *arg)
{
  static_cast<IceAlloc*>(arg)->_stun_ind_handler(msg);
}

void conncheck_handler(int err, bool update, void *arg)
{
  static_cast<IceAlloc*>(arg)->_conncheck_handler(err, update);
}

void recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
  static_cast<IceAlloc*>(arg)->_recv_handler(src, mb);
}

void turnc_handler(int err, uint16_t scode, const char *reason,
        const struct sa *relay, const struct sa *mapped,
        const struct stun_msg *msg, void *arg)
{
  static_cast<IceAlloc*>(arg)->_turnc_handler(err,
                                              scode,
                                              reason,
                                              relay,
                                              mapped,
                                              msg);
}

void stun_resp_handler(int err, uint16_t scode, const char *reason,
            const struct stun_msg *msg, void *arg)
{
  static_cast<IceAlloc*>(arg)->_stun_resp_handler(err,
                                                  scode,
                                                  reason,
                                                  msg);
}

IceAlloc::IceAlloc():
  _tiebreak(rand_u64())
{
  _stun_conf= {STUN_DEFAULT_RTO,
               STUN_DEFAULT_RC,
               STUN_DEFAULT_RM,
               STUN_DEFAULT_TI,
               0x00
              };

  rand_str(_lufrag, sizeof(_lufrag));
  rand_str(_lpwd,   sizeof(_lpwd));

  auto err = sa_set_str(&_listenaddress, "0.0.0.0", 0);
  if (err)
  {
    FAF_LOG_ERROR << "sa_set_str failed";
    return;
  }
  err = udp_listen(&_socket,
                   &_listenaddress,
                   recv_handler,
                   nullptr);
  if (err)
  {
    FAF_LOG_ERROR << "udp_listen failed";
    return;
  }

  struct sa _socketSa;
  udp_local_get(_socket, &_socketSa);
  _port = sa_port(&_socketSa);

  _dns_alloc();
  _session_alloc();
  _ice_start();
}

void IceAlloc::_dns_alloc()
{
  const char *serr;
  struct sa nsv[4];
  uint32_t nsn = ARRAY_SIZE(nsv);
  int err = 0;
  err = dns_srv_get(NULL, 0, nsv, &nsn);
  if (err)
  {
    FAF_LOG_ERROR << "dns_srv_get failed";
    return;
  }
  err = dnsc_alloc(&_dnsc, NULL, nsv, nsn);
  if (err)
  {
    FAF_LOG_ERROR << "dnsc_alloc failed";
    return;
  }
}

void IceAlloc::_send_binding_request()
{
  auto err = stun_request(&_ct_gath,
                          icem_stun(_icem),
                          IPPROTO_UDP,
                          nullptr,
                          _stun_sa,
                          0,
                          STUN_METHOD_BINDING,
                          nullptr,
                          false,
                          0,
                          stun_resp_handler,
                          this,
                          1,
                          STUN_ATTR_SOFTWARE,
                          stun_software);
  if (err)
  {
    FAF_LOG_ERROR << "stun_request failed";
    return;
  }
}

void IceAlloc::_session_alloc()
{
  auto err = stun_alloc(&_stun,
                        &_stun_conf,
                        &stun_ind_handler,
                        this
                        );
  if (err)
  {
    FAF_LOG_ERROR << "error in stun_alloc";
    return;
  }

  err = stun_server_discover(&_dnsq,
                             _dnsc,
                             stun_usage_relay,
                             stun_proto_udp,
                             AF_INET,
                             _stunServer.c_str(),
                             _stunPort,
                             dns_handler,
                             this);
  if (err)
  {
    FAF_LOG_ERROR << "error in stun_server_discover";
    return;
  }

  ice_role role = _offerer ? ICE_ROLE_CONTROLLING : ICE_ROLE_CONTROLLED;

  icem** icep = &_icem;

  err = icem_alloc(&_icem,
                   ICE_MODE_FULL,
                   role,
                   IPPROTO_UDP,
                   _ice_layer,
                   _tiebreak,
                   _lufrag,
                   _lpwd,
                   conncheck_handler,
                   this);
  if (err)
  {
    FAF_LOG_ERROR << "error in icem_alloc";
    return;
  }

  icem_conf(_icem)->nom   = ICE_NOMINATION_REGULAR;
  icem_conf(_icem)->debug = true;
  icem_conf(_icem)->rc    = 4;

  icem_set_conf(_icem, icem_conf(_icem));
  icem_set_name(_icem, "FAF");

  icem_comp_add(_icem, 1, _socket);
}

void IceAlloc::_ice_start()
{
  net_getifaddrs(net_ifaddr_handler, this);
  icem_update(_icem);
  icem_conncheck_start(_icem);
  _send_binding_request();
}


void IceAlloc::_gather_relayed()
{
  unsigned char coturnKey[] = "banana";

  auto lifetime = std::chrono::system_clock::now();
  lifetime = lifetime + std::chrono::hours(24);
  auto lifetimeEpoch = std::chrono::duration_cast<std::chrono::seconds>(lifetime.time_since_epoch()).count();

  std::string username = std::to_string(lifetimeEpoch) + ":username";

  hmac* hmac;
  auto err = hmac_create(&hmac, HMAC_HASH_SHA1, coturnKey, sizeof(coturnKey));
  if (err)
  {
    FAF_LOG_ERROR << "error in hmac_create";
    return;
  }

  uint8_t credDigest[SHA_DIGEST_LENGTH];
  err = hmac_digest(hmac, credDigest, sizeof(credDigest), reinterpret_cast<const uint8_t*>(username.c_str()), username.size());
  if (err)
  {
    FAF_LOG_ERROR << "error in hmac_digest";
    return;
  }

  char credential[4 * ((SHA_DIGEST_LENGTH+2)/3)] = {0};
  size_t credentialSize = sizeof(credential);
  err = base64_encode(credDigest, sizeof(credDigest), credential, &credentialSize);
  if (err)
  {
    FAF_LOG_ERROR << "error in base64_encode";
    return;
  }

  err = turnc_alloc(&_turnc,
                    stun_conf(icem_stun(_icem)),
                    IPPROTO_UDP,
                    _socket,
                    _ice_layer-10,
                    _stun_sa,
                    username.c_str(),
                    credential,
                    TURN_DEFAULT_LIFETIME,
                    turnc_handler,
                    this);
  if (err)
  {
    FAF_LOG_ERROR << "error in turnc_alloc";
    return;
  }

  err = icem_set_turn_client(_icem, 0, _turnc);
  if (err)
  {
    FAF_LOG_ERROR << "error in icem_set_turn_client";
    return;
  }
}

void IceAlloc::_stun_ind_handler(struct stun_msg *msg)
{
  FAF_LOG_DEBUG << "_stun_ind_handler";
}

void IceAlloc::_dns_handler(int err, const struct sa *srv)
{
  _stun_sa = srv;
  FAF_LOG_DEBUG << "stun server " << _stunServer << " resolved";
  _send_binding_request();
  //_gather_relayed();
}

bool IceAlloc::_ifaddr_handler(const char *ifname, const struct sa *sa)
{
  FAF_LOG_DEBUG << "ifaddr " << ifname << " ";

  char buf[1024];

  if (re_snprintf(buf, sizeof(buf), "%H", sa_print_addr, sa)>= 0)
  {
    FAF_LOG_DEBUG << buf;
  }

  return false;
}

void IceAlloc::_conncheck_handler(int err, bool update)
{
  FAF_LOG_DEBUG << "_conncheck_handler";
}

void IceAlloc::_turnc_handler(int err, uint16_t scode, const char *reason,
                            const struct sa *relay, const struct sa *mapped,
                            const struct stun_msg *msg)
{
  FAF_LOG_DEBUG << "_turnc_handler";
}

void IceAlloc::_recv_handler(const struct sa *src, struct mbuf *mb)
{
  FAF_LOG_DEBUG << "_recv_handler";
}

void IceAlloc::_stun_resp_handler(int err, uint16_t scode, const char *reason,
                                  const struct stun_msg *msg)
{
  if (err || scode > 0)
  {
    FAF_LOG_ERROR << "STUN Request failed";
    return;
  }

  auto attr = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
  if (!attr)
  {
    attr = stun_msg_attr(msg, STUN_ATTR_MAPPED_ADDR);
  }
  if (!attr)
  {
    FAF_LOG_ERROR << "no Mapped Address in Response";
    return;
  }

  auto lcand = icem_cand_find(icem_lcandl(_icem), 1, nullptr);
  if (!lcand)
  {
    FAF_LOG_ERROR << "!lcand";
    return;
  }

  err = icem_lcand_add(_icem,
                       icem_lcand_base(lcand),
                       ICE_CAND_TYPE_SRFLX,
                       &attr->v.sa);
  if (err)
  {
    FAF_LOG_ERROR << "error in icem_lcand_add";
    return;
  }
}

