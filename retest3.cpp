#include "logging.h"

#include <re.h>

#include "IceAlloc.h"

static void signal_handler(int signum)
{
  (void)re_fprintf(stderr, "caught signal %d\n", signum);
  re_cancel();
}


int main(int argc, char **argv)
{
  auto err = libre_init();
  if (err)
  {
    FAF_LOG_ERROR << "error in libre_init()";
  }

  IceAlloc a;
  re_main(signal_handler);
  return 0;
}
