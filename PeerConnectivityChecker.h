#pragma once

#include <chrono>
#include <functional>
#include <string>

#include "api/datachannelinterface.h"
#include "rtc_base/messagehandler.h"
#include "api/optional.h"

#include "Timer.h"

namespace faf {

class PeerConnectivityChecker : public rtc::MessageHandler
{
public:
  typedef std::function<void()> ConnectivityLostCallback;
  PeerConnectivityChecker(rtc::scoped_refptr<webrtc::DataChannelInterface> dc,
                          ConnectivityLostCallback cb);

  virtual ~PeerConnectivityChecker();

  bool handleMessageFromPeer(const uint8_t* data, std::size_t size);

  static const std::string PingMessage;
  static const std::string PongMessage;
protected:
  void OnMessage(rtc::Message* msg) override;

  rtc::scoped_refptr<webrtc::DataChannelInterface> _dataChannel;
  ConnectivityLostCallback _cb;
  rtc::Optional<std::chrono::steady_clock::time_point> _lastSentPingTime;
  rtc::Optional<std::chrono::steady_clock::time_point> _lastReceivedPongTime;
  unsigned int _missedPings{0};
  int _connectionCheckIntervalMs{7000};
};

} // namespace faf
