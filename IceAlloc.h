#pragma once

#include <string>

#include <re.h>

class IceAlloc
{
public:
  IceAlloc();
protected:
  void _dns_alloc();
  void _session_alloc();

  void _ice_start();

  void _send_binding_request();

  void _gather_relayed();

  friend void stun_ind_handler(struct stun_msg *msg, void *arg);
  void _stun_ind_handler(struct stun_msg *msg);

  friend void dns_handler(int err, const struct sa *srv, void *arg);
  void _dns_handler(int err, const struct sa *srv);

  friend void conncheck_handler(int err, bool update, void *arg);
  void _conncheck_handler(int err, bool update);

  friend void turnc_handler(int err, uint16_t scode, const char *reason,
                            const struct sa *relay, const struct sa *mapped,
                            const struct stun_msg *msg, void *arg);
  void _turnc_handler(int err, uint16_t scode, const char *reason,
                              const struct sa *relay, const struct sa *mapped,
                              const struct stun_msg *msg);

  friend void recv_handler(const struct sa *src, struct mbuf *mb, void *arg);
  void _recv_handler(const struct sa *src, struct mbuf *mb);

  friend void stun_resp_handler(int err, uint16_t scode, const char *reason,
                                const struct stun_msg *msg, void *arg);
  void _stun_resp_handler(int err, uint16_t scode, const char *reason,
                          const struct stun_msg *msg);

  std::string _stunServer{"vmrbg145.informatik.tu-muenchen.de"};
  uint16_t _stunPort{3478};

  bool _offerer = true;
  const int _ice_layer{0};
  const uint64_t _tiebreak;
  char _lufrag[8];
  char _lpwd[32];
  dnsc* _dnsc = nullptr;
  stun_dns* _dnsq = nullptr;
  stun* _stun = nullptr;
  const sa* _stun_sa = nullptr;
  struct stun_conf _stun_conf;

  sa _listenaddress;
  udp_sock* _socket = nullptr;
  uint16_t _port = 0;

  stun_ctrans* _ct_gath = nullptr;
  turnc* _turnc = nullptr;
  icem* _icem = nullptr;
};
