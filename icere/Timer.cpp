#include "Timer.h"

namespace faf {

void timer_handler(void *arg)
{
  static_cast<Timer*>(arg)->_timer_handler();
}

Timer::Timer():
  _interval(0)
{
}

Timer::~Timer()
{
  stop();
}

void Timer::start(int intervalMs, std::function<void()> callback)
{
  stop();
  _interval = intervalMs;
  _callback = callback;
  _singleShot = false;
  tmr_start(&_timer, _interval, timer_handler, this);
}

void Timer::singleShot(int delay, std::function<void()> callback)
{
  stop();
  _callback = callback;
  _singleShot = true;
  tmr_start(&_timer, _interval, timer_handler, this);
}

bool Timer::started() const
{
  return static_cast<bool>(_callback);
}

void Timer::stop()
{
  _callback = std::function<void()>();
  tmr_cancel(&_timer);
}

void Timer::_timer_handler()
{
  if (_callback)
  {
    _callback();
    if (_singleShot)
    {
      /* reset _callback, to make started() return false after this callback */
      _callback = std::function<void()>();
    }
    else
    {
      tmr_start(&_timer, _interval, timer_handler, this);
    }
  }
}

} // namespace faf
