#pragma once

#include <functional>

#include "rtc_base/messagehandler.h"

namespace faf {

class Timer : public rtc::MessageHandler
{
public:
  Timer();
  ~Timer() final;

  void start(int intervalMs, std::function<void()> callback);
  void singleShot(int delay, std::function<void()> callback);
  bool started() const;
  void stop();
protected:
  void OnMessage(rtc::Message* msg) override;
  int _interval;
  std::function<void()> _callback;
  bool _singleShot{false};

  RTC_DISALLOW_COPY_AND_ASSIGN(Timer);
};

} // namespace faf
