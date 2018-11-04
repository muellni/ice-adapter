#include "IceConnector.h"

#include <chrono>

#include <re_sha.h>

#include "logging.h"

namespace faf {

bool net_ifaddr_handler(const char *ifname, const struct sa *sa, void *arg)
{
  return static_cast<IceConnector*>(arg)->_ifaddr_handler(ifname, sa);
}

void conncheck_handler(int err, bool update, void *arg)
{
  static_cast<IceConnector*>(arg)->_conncheck_handler(err, update);
}

IceConnector::IceConnector(bool offerer, IceMessageHandler const& iceMessageHandler):
  _iceMessageHandler(iceMessageHandler),
  _tiebreak(rand_u64()),
  _offerer(offerer)
{
  _initTimer.singleShot(0, std::bind(&IceConnector::_init, this));
}

void IceConnector::addIceMessage(Json::Value const& iceMessage)
{
  if (iceMessage["type"].asString() != "candidate")
  {
    if (_offerer && iceMessage["type"].asString() == "offer")
    {
      FAF_LOG_ERROR << "offerer receiving offer";
      return;
    }
    if (iceMessage["candidates"].isArray())
    {
      for (Json::ArrayIndex iCand = 0; iCand < iceMessage["candidates"].size(); ++iCand)
      {
        auto err = icem_sdp_decode(_icem, "candidate", iceMessage["candidates"][iCand].asString().c_str());
        if (err)
        {
          FAF_LOG_ERROR << "ice_sdp_decode failed";
        }
      }
    }

    auto err = ice_sdp_decode(_icem, "ice-ufrag", iceMessage["ufrag"].asCString());
    if (err)
    {
      FAF_LOG_ERROR << "ice_sdp_decode failed";
    }
    err = icem_sdp_decode(_icem, "ice-ufrag", iceMessage["ufrag"].asCString());
    if (err)
    {
      FAF_LOG_ERROR << "icem_sdp_decode failed";
    }
    err = ice_sdp_decode(_icem, "ice-pwd", iceMessage["pwd"].asCString());
    if (err)
    {
      FAF_LOG_ERROR << "ice_sdp_decode failed";
    }
    err = icem_sdp_decode(_icem, "ice-ufrag", iceMessage["ufrag"].asCString());
    if (err)
    {
      FAF_LOG_ERROR << "icem_sdp_decode failed";
    }

    if (!_offerer)
    {
      _createSockets();
      _sendSdp();
    }

    if (icem_mismatch(_icem))
    {
      FAF_LOG_ERROR << "icem_mismatch";
    }

    err = icem_conncheck_start(_icem);
    if (err)
    {
      FAF_LOG_ERROR << "icem_conncheck_start failed";
    }
  }

}

void IceConnector::_init()
{
  rand_str(_lufrag, sizeof(_lufrag));
  rand_str(_lpwd,   sizeof(_lpwd));

  _stunServers.push_back({"vmrbg145.informatik.tu-muenchen.de",
                         3478});


  auto err = sa_set_str(&_appAddress, "0.0.0.0", 0);
  if (err)
  {
    FAF_LOG_ERROR << "sa_set_str failed";
    return;
  }
  _appSocket = std::make_unique<UdpSocket>(_appAddress);

  _allocDns();
  _allocIcem();
  _initTurnInfo();

  if (_offerer)
  {
    _createSockets();
    _sendSdp();
  }
}

void IceConnector::_allocDns()
{
  struct sa nsv[4];
  uint32_t nsn = ARRAY_SIZE(nsv);
  int err = 0;
  err = dns_srv_get(nullptr, 0, nsv, &nsn);
  if (err)
  {
    FAF_LOG_ERROR << "dns_srv_get failed";
    return;
  }
  err = dnsc_alloc(&_dnsc, nullptr, nsv, nsn);
  if (err)
  {
    FAF_LOG_ERROR << "dnsc_alloc failed";
    return;
  }
}

void IceConnector::_allocIcem()
{
  auto err = icem_alloc(&_icem,
                        ICE_MODE_FULL,
                        _offerer ? ICE_ROLE_CONTROLLING : ICE_ROLE_CONTROLLED,
                        IPPROTO_UDP,
                        _ice_layer,
                        _tiebreak,
                        _lufrag,
                        _lpwd,
                        conncheck_handler,
                        this);
  if (err)
  {
    FAF_LOG_ERROR << "error in icem_alloc";
    return;
  }

  icem_set_name(_icem, "FAF");

  err = icem_comp_add(_icem, _compId, _appSocket->socket());
  if (err)
  {
    FAF_LOG_ERROR << "error in icem_comp_add";
    return;
  }
}

void IceConnector::_initTurnInfo()
{
  unsigned char coturnKey[] = "banana";

  auto lifetime = std::chrono::system_clock::now();
  lifetime = lifetime + std::chrono::hours(24);
  auto lifetimeEpoch = std::chrono::duration_cast<std::chrono::seconds>(lifetime.time_since_epoch()).count();

  std::string username = std::to_string(lifetimeEpoch) + ":username";

  hmac* hmac;
  auto err = hmac_create(&hmac, HMAC_HASH_SHA1, coturnKey, sizeof(coturnKey));
  if (err)
  {
    FAF_LOG_ERROR << "error in hmac_create";
    return;
  }

  uint8_t credDigest[SHA_DIGEST_LENGTH];
  err = hmac_digest(hmac, credDigest, sizeof(credDigest), reinterpret_cast<const uint8_t*>(username.c_str()), username.size());
  if (err)
  {
    FAF_LOG_ERROR << "error in hmac_digest";
    return;
  }

  char credential[4 * ((SHA_DIGEST_LENGTH+2)/3)] = {0};
  size_t credentialSize = sizeof(credential);
  err = base64_encode(credDigest, sizeof(credDigest), credential, &credentialSize);
  if (err)
  {
    FAF_LOG_ERROR << "error in base64_encode";
    return;
  }

  _turnServers.push_back({{"vmrbg145.informatik.tu-muenchen.de",
                           3478},
                          username,
                          std::string(credential, credentialSize)});

}

void IceConnector::_createSockets()
{
  net_getifaddrs(net_ifaddr_handler, this);
}

std::string encodeCandidate(struct ice_cand *cand)
{
  static char buf[128];
  if (re_snprintf(buf, sizeof(buf), "%H", ice_cand_encode, cand)>= 0)
  {
    return buf;
  }
  else
  {
    FAF_LOG_ERROR << "error encoding candidate";
  }
  return "error";
}

void IceConnector::_sendSdp()
{
  Json::Value root;
  root["type"] = _offerer ? "offer" : "answer";

  Json::Value candidates(Json::arrayValue);
  for (struct le *le = icem_lcandl(_icem)->head; le; le = le->next)
  {
    struct ice_cand *cand = static_cast<struct ice_cand *>(le->data);
    candidates.append(encodeCandidate(cand));
  }
  root["candidates"] = candidates;
  root["ufrag"] = _lufrag;
  root["pwd"] = _lpwd;
  if (_iceMessageHandler)
  {
    _iceMessageHandler(root, this);
  }
}

void IceConnector::_startTurn(std::shared_ptr<UdpSocket> socket)
{
  for (auto info : _turnServers)
  {
    _turnAllocator.push_back(std::make_unique<TurnAllocator>(info,
                                                             socket,
                                                             _dnsc,
                                                             TurnAllocator::AllocationHandler()));
  }
  /*
  _stunRequester.push_back(std::make_unique<StunRequester>(*_stunServers.begin(),
                                                           socket,
                                                           _dnsc,
                                                           h));
                                                           */
}

bool IceConnector::_ifaddr_handler(const char *ifname, const struct sa *sa)
{
  auto socket = std::make_shared<UdpSocket>(*sa);
  _sockets.push_back(socket);

  auto err = icem_cand_add(_icem,
                           _compId,
                           0,
                           ifname,
                           &socket->listenAddress());
  if (err)
  {
    FAF_LOG_ERROR << "error in icem_cand_add";
  }

  StunRequester::RequestHandler h = std::bind(&IceConnector::_onStunRequest,
                                              this,
                                              std::placeholders::_1,
                                              std::placeholders::_2,
                                              std::placeholders::_3);
  _stunRequester.push_back(std::make_unique<StunRequester>(*_stunServers.begin(),
                                                           socket,
                                                           _dnsc,
                                                           h));
  return false;
}

void IceConnector::_conncheck_handler(int err, bool update)
{
  if (err)
  {
    FAF_LOG_ERROR << "conncheck failed";
    return;
  }

  if (_offerer ^ update)
  {
    FAF_LOG_ERROR << "error in update";
    return;
  }

  auto rcand = icem_selected_rcand(_icem, _compId);
  auto raddr = icem_lcand_addr(rcand);

  if (!icem_verify_support(_icem, _compId, raddr))
  {
    FAF_LOG_ERROR << "icem_verify_support failed";
    return;
  }
}

void IceConnector::_onStunRequest(bool ok, StunRequester* r, struct sa* sa)
{
  if (ok)
  {
    auto lcand = icem_cand_find(icem_lcandl(_icem),
                                _compId,
                                nullptr);
    if (!lcand)
    {
      FAF_LOG_ERROR << "!lcand";
      return;
    }

    auto err = icem_lcand_add(_icem,
                              icem_lcand_base(lcand),
                              ICE_CAND_TYPE_SRFLX,
                              sa);


    Json::Value iceMsg;
    iceMsg["type"] = "candidate";
    iceMsg["candidate"] = encodeCandidate(icem_cand_find(icem_lcandl(_icem),
                                                         _compId,
                                                         sa));
    if (_iceMessageHandler)
    {
      _iceMessageHandler(iceMsg, this);
    }

    if (err)
    {
      FAF_LOG_ERROR << "error in icem_lcand_add";
    }
    _startTurn(r->socket());
  }

  auto rIt = _stunRequester.begin();
  while (rIt != _stunRequester.end())
  {
    if (rIt->get() == r)
    {
      rIt = _stunRequester.erase(rIt);
    }
    else
    {
      ++rIt;
    }
  }
}


} // namespace faf
