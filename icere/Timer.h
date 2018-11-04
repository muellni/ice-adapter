#pragma once

#include <cstdint>
#include <functional>

#include <re.h>

namespace faf {

class Timer
{
public:
  Timer();
  virtual ~Timer();

  void start(int intervalMs, std::function<void()> callback);
  void singleShot(int delay, std::function<void()> callback);
  bool started() const;
  void stop();
protected:

  friend void timer_handler(void *arg);
  void _timer_handler();

  struct tmr _timer;
  int _interval;
  std::function<void()> _callback;
  bool _singleShot = false;
};

} // namespace faf
