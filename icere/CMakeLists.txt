include_directories(${RE_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
find_package(Threads)
find_package(ZLIB)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
include_directories(${JSONCPP_INCLUDE_DIRS})

add_executable(faf-ice-adapter
  IceAlloc.h
  IceAlloc.cpp
  IceConnector.h
  IceConnector.cpp
  IceConnectorConnectivityChecker.h
  IceConnectorConnectivityChecker.cpp
  logging.h
  main.cpp
  StunRequester.cpp
  StunRequester.h
  Timer.cpp
  Timer.h
  TurnAllocator.cpp
  TurnAllocator.h
  types.h
  UdpSocket.cpp
  UdpSocket.h
)

target_link_libraries(faf-ice-adapter
  ${RE_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  Threads::Threads
  ${ZLIB_LIBRARIES}
  ${JSONCPP_LIBRARIES}
)

add_executable(retest
  retest4.cpp
  stunsrv.cpp
  turnsrv.cpp
)

target_link_libraries(retest
  ${RE_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  Threads::Threads
  ${ZLIB_LIBRARIES}
)
