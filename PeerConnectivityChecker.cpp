#include "PeerConnectivityChecker.h"

#include <cstring>
#include <algorithm>

#include "rtc_base/messagequeue.h"
#include "rtc_base/thread.h"

#include "logging.h"

namespace faf {

const std::string PeerConnectivityChecker::PingMessage = "ICEADAPTERPING";
const std::string PeerConnectivityChecker::PongMessage = "ICEADAPTERPONG";

PeerConnectivityChecker::PeerConnectivityChecker(rtc::scoped_refptr<webrtc::DataChannelInterface> dc,
                                                 ConnectivityLostCallback cb):
  _dataChannel(dc),
  _cb(cb)
{
  rtc::Thread::Current()->PostDelayed(RTC_FROM_HERE, _connectionCheckIntervalMs, this);
}

PeerConnectivityChecker::~PeerConnectivityChecker()
{
  rtc::Thread::Current()->Clear(this);
}

bool PeerConnectivityChecker::handleMessageFromPeer(const uint8_t* data, std::size_t size)
{
  if (std::strncmp(PongMessage.c_str(),  reinterpret_cast<const char*>(data), std::min(size, PongMessage.size())) == 0)
  {
    _lastReceivedPongTime = std::chrono::steady_clock::now();
    return true;
  }
  return false;
}


void PeerConnectivityChecker::OnMessage(rtc::Message* msg)
{
  if (_lastSentPingTime &&
      !_lastReceivedPongTime)
  {
    ++_missedPings;
    if (_missedPings >= 2)
    {
      FAF_LOG_INFO << "PeerConnectivityChecker:" << _missedPings << " missed pings, connectivity lost";
      _cb();
      return;
    }
  }
  _dataChannel->Send(webrtc::DataBuffer(rtc::CopyOnWriteBuffer(PingMessage.c_str(), PingMessage.size()), true));
  _lastSentPingTime = std::chrono::steady_clock::now();
  _lastReceivedPongTime.reset();
  rtc::Thread::Current()->PostDelayed(RTC_FROM_HERE, _connectionCheckIntervalMs, this);
}

} // namespace faf
