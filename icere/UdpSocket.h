#pragma once

#include <cstdint>
#include <ostream>
#include <functional>

#include <re.h>

struct udp_sock;

namespace faf {

class UdpSocket
{
public:
  UdpSocket(struct sa addr);

  virtual ~UdpSocket();

  using ReceiveHandler=std::function<void (const struct sa *src, struct mbuf *mb)>;
  void setReceiveHandler(ReceiveHandler const& h);

  struct sa const& listenAddress() const;
  uint16_t listenPort() const;
  struct udp_sock* socket() const;

  void send(const struct sa *dest, struct mbuf *mb);
protected:

  friend void recv_handler(const struct sa *src, struct mbuf *mb, void *arg);
  void _recv_handler(const struct sa *src, struct mbuf *mb);

  struct sa _addr;
  struct udp_sock* _socket;

  ReceiveHandler _receiveHandler;
};

std::ostream& operator<<(std::ostream&, UdpSocket const&);

} // namespace faf
