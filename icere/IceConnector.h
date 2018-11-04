#pragma once

#include <vector>
#include <cstdint>
#include <memory>

#include <json/json.h>

#include <re.h>

#include "StunRequester.h"
#include "Timer.h"
#include "TurnAllocator.h"
#include "types.h"
#include "UdpSocket.h"

namespace faf {

class IceConnector
{
public:

  using IceMessageHandler = std::function<void (Json::Value const& iceMessage, IceConnector* c)>;

  IceConnector(bool offerer, IceMessageHandler const& iceMessageHandler);

  void addIceMessage(Json::Value const& iceMessage);

protected:
  // methods
  void _init();
  void _allocDns();
  void _allocIcem();
  void _initTurnInfo();
  void _createSockets();
  void _sendSdp();
  void _startTurn(std::shared_ptr<UdpSocket> socket);

  // handlers
  friend bool net_ifaddr_handler(const char *ifname, const struct sa *sa, void *arg);
  bool _ifaddr_handler(const char *ifname, const struct sa *sa);

  friend void conncheck_handler(int err, bool update, void *arg);
  void _conncheck_handler(int err, bool update);

  void _onStunRequest(bool ok, StunRequester* r, struct sa* sa);

  // state variables
  Timer _initTimer;
  IceMessageHandler _iceMessageHandler;
  std::vector<std::shared_ptr<UdpSocket>> _sockets;
  std::vector<std::unique_ptr<StunRequester>> _stunRequester;
  std::vector<std::unique_ptr<TurnAllocator>> _turnAllocator;
  std::vector<StunServerInfo> _stunServers;
  std::vector<TurnServerInfo> _turnServers;
  const uint64_t _tiebreak;
  char _lufrag[8];
  char _lpwd[32];
  dnsc* _dnsc = nullptr;
  bool _offerer = true;
  const int _ice_layer{0};

  sa _appAddress;
  std::unique_ptr<UdpSocket> _appSocket;

  const unsigned int _compId = 1;
  struct icem *_icem = nullptr;
};

} // namespace faf
