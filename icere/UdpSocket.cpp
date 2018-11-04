#include "UdpSocket.h"

#include "logging.h"

namespace faf {

void recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
  static_cast<UdpSocket*>(arg)->_recv_handler(src, mb);
}

UdpSocket::UdpSocket(struct sa addr):
  _addr(addr),
  _socket(nullptr)
{
  auto err = udp_listen(&_socket,
                        &_addr,
                        recv_handler,
                        this);
  if (err)
  {
    FAF_LOG_ERROR << "error calling udp_listen";
    return;
  }

  err = udp_local_get(_socket, &_addr);
  if (err)
  {
    FAF_LOG_ERROR << "error calling udp_local_get";
    return;
  }
}

UdpSocket::~UdpSocket()
{
  mem_deref(_socket);
}

void UdpSocket::setReceiveHandler(ReceiveHandler const& h)
{
  _receiveHandler = h;
}

struct sa const& UdpSocket::listenAddress() const
{
  return _addr;
}

uint16_t UdpSocket::listenPort() const
{
  return sa_port(&_addr);
}

struct udp_sock* UdpSocket::socket() const
{
  return _socket;
}

void UdpSocket::send(const struct sa *dest, struct mbuf *mb)
{
  udp_send(_socket, dest, mb);
}

void UdpSocket::_recv_handler(const struct sa *src, struct mbuf *mb)
{
  if (_receiveHandler)
  {
    _receiveHandler(src, mb);
  }
}

std::ostream& operator<<(std::ostream& os, UdpSocket const& socket)
{
  char buf[128];
  auto sa = socket.listenAddress();

  if (re_snprintf(buf, sizeof(buf), "%H", sa_print_addr, &sa)>= 0)
  {
    os << "UDP socket listening on " << buf << ":" << socket.listenPort();
  }
  return os;
}

} // namespace faf
