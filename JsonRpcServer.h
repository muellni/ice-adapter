#pragma once

#include "rtc_base/asyncsocket.h"

#include "JsonRpc.h"

namespace faf {

class JsonRpcServer : public sigslot::has_slots<>, public JsonRpc
{
public:
  JsonRpcServer();
  ~JsonRpcServer() final;
  void listen(int port, std::string const& hostname = "127.0.0.1");

  int listenPort() const;

  sigslot::signal1<rtc::AsyncSocket*, sigslot::multi_threaded_local> SignalClientConnected;
  sigslot::signal1<rtc::AsyncSocket*, sigslot::multi_threaded_local> SignalClientDisconnected;
protected:
  void _onNewClient(rtc::AsyncSocket* socket);
  void _onClientDisconnect(rtc::AsyncSocket* socket, int);
  void _onRead(rtc::AsyncSocket* socket);
  bool _sendMessage(std::string const& message, rtc::AsyncSocket* socket) override;

  std::unique_ptr<rtc::AsyncSocket> _server;
  std::map<rtc::AsyncSocket*, std::shared_ptr<rtc::AsyncSocket>> _connectedSockets;

  RTC_DISALLOW_COPY_AND_ASSIGN(JsonRpcServer);
};

} // namespace faf
