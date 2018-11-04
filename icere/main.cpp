#include "logging.h"

#include <re.h>

#include "IceConnector.h"

static faf::IceConnector* a;
static faf::IceConnector* b;

static void signal_handler(int signum)
{
  (void)re_fprintf(stderr, "caught signal %d\n", signum);
  re_cancel();
}

void iceMessageHandler(Json::Value const& iceMessage, faf::IceConnector* c)
{
  //FAF_LOG_INFO << "iceMessage: " << iceMessage;
  if (c == a)
  {
    b->addIceMessage(iceMessage);
  }
  else
  {
    a->addIceMessage(iceMessage);
  }
}

int main(int argc, char **argv)
{
  auto err = libre_init();
  if (err)
  {
    FAF_LOG_ERROR << "error in libre_init()";
  }

  a = new faf::IceConnector(false, iceMessageHandler);
  b = new faf::IceConnector(true, iceMessageHandler);
  return re_main(signal_handler);
}
