#include "StunRequester.h"

#include "logging.h"

namespace faf {

void stun_ind_handler(struct stun_msg *msg, void *arg)
{
  static_cast<StunRequester*>(arg)->_stun_ind_handler(msg);
}

void stun_dns_resolved_handler(int err, const struct sa *srv, void *arg)
{
  static_cast<StunRequester*>(arg)->_stun_dns_resolved_handler(err, srv);
}

void stun_resp_handler(int err, uint16_t scode, const char *reason,
            const struct stun_msg *msg, void *arg)
{
  static_cast<StunRequester*>(arg)->_stun_resp_handler(err,
                                                       scode,
                                                       reason,
                                                       msg);
}

StunRequester::StunRequester(StunServerInfo const& stunserver,
                             std::shared_ptr<UdpSocket> const& socket,
                             struct dnsc* dnsc,
                             RequestHandler const& h):
  _socket(socket),
  _handler(h)
{

  _stun_conf= {STUN_DEFAULT_RTO,
               STUN_DEFAULT_RC,
               STUN_DEFAULT_RM,
               STUN_DEFAULT_TI,
               0x00
              };

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
                             dnsc,
                             stun_usage_relay,
                             stun_proto_udp,
                             AF_INET,
                             stunserver.hostname.c_str(),
                             stunserver.port,
                             stun_dns_resolved_handler,
                             this);
  if (err)
  {
    FAF_LOG_ERROR << "error in stun_server_discover";
    return;
  }
}

StunRequester::~StunRequester()
{
  mem_deref(_stun);
  mem_deref(_dnsq);
}

std::shared_ptr<UdpSocket> const& StunRequester::socket() const
{
  return _socket;
}

void StunRequester::_send_binding_request()
{
  //FAF_LOG_DEBUG << "sending STUN request for socket " << *_socket;
  _socket->setReceiveHandler([this](const struct sa *src, struct mbuf *mb)
  {
    stun_recv(_stun, mb);
  });
  auto err = stun_request(&_ct_gath,
                          _stun,
                          IPPROTO_UDP,
                          _socket->socket(),
                          _stun_sa,
                          0,
                          STUN_METHOD_BINDING,
                          nullptr,
                          0,
                          false,
                          stun_resp_handler,
                          this,
                          1,
                          STUN_ATTR_SOFTWARE,
                          stun_software);
  if (err)
  {
    //FAF_LOG_ERROR << "stun_request failed";
    _socket->setReceiveHandler(UdpSocket::ReceiveHandler());
    if (_handler)
    {
      _handler(false, this, nullptr);
    }
    return;
  }
}

void StunRequester::_stun_ind_handler(struct stun_msg *msg)
{
  FAF_LOG_DEBUG << "_stun_ind_handler";
}

void StunRequester::_stun_dns_resolved_handler(int err, const struct sa *srv)
{
  if (err)
  {
    FAF_LOG_ERROR << "error resolving STUN server";
  }
  else
  {
    //FAF_LOG_DEBUG << "stun server resolved";
    _stun_sa = srv;
    _send_binding_request();
  }
}

void StunRequester::_stun_resp_handler(int err, uint16_t scode, const char *reason,
                        const struct stun_msg *msg)
{
  if (err || scode > 0)
  {
    FAF_LOG_ERROR << "STUN Request failed for socket " << *_socket;
    if (_handler)
    {
      _handler(false, this, nullptr);
    }
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
    if (_handler)
    {
      _handler(false, this, nullptr);
    }
    return;
  }
  //FAF_LOG_DEBUG << "STUN success for socket " << *_socket;
  _socket->setReceiveHandler(UdpSocket::ReceiveHandler());
  if (_handler)
  {
    _handler(true, this, &attr->v.sa);
  }
}


} // namespace faf
