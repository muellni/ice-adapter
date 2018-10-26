#include "IceRelay.h"

IceRelay::IceRelay()
{
  stun_server_discover(&sess->dnsq,
                       dnsc,
                       usage,
                       stun_proto_udp,
                       af,
                       srv,
                       port,
                       dns_handler,
                       sess);

}
