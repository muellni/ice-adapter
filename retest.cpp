/**
 * @file ice.c ICE Candidate Gathering
 * Copyright (C) 2015 Josh Allmann of Foresight Informatics
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h> // for sleep
#include <re.h>

#define DEBUG_MODULE "ice"
#define DEBUG_LEVEL 10
#include <re_dbg.h>


struct stun_data {
    struct stun_dns *dns;
    struct icem *icem;
    struct media_data *p_md;
    struct sa stun_sock;
};

#define MAX_STUN_SRVS 10
#define MAX_COMPS 32
struct media_data {
    struct dnsc *dnsc;
    struct icem *icem;
    struct sa stun_sock;
    struct stun_data stun_srvs[MAX_STUN_SRVS];
    struct stun_keepalive *p_skas[MAX_COMPS];
    void *p_socks[MAX_COMPS]; // component sockets
    int i_comps, i_stun_srvs;
};

static bool if_handler(const char *ifname, const struct sa *sa, void *arg)
{
    struct media_data *md = static_cast<struct media_data *>(arg);
    char addr[INET6_ADDRSTRLEN + 1] = {0};
    int i, err = 0;
    // skip loopback and link-local addresses
    if (sa_is_loopback(sa) || sa_is_linklocal(sa)) return 0;
    sa_ntop(sa, addr, sizeof(addr));
    for (i = 1; i <= md->i_comps; i++) {
        err |= icem_cand_add(md->icem, i, 0, ifname, sa);
    }
    return 0 != err;
}

static void mapped_addr_handler(int err, const struct sa *map, void *arg)
{
    if (err) {
        fprintf(stderr, "Mapped address error: %d\n", err);
        return;
    }
    re_fprintf(stdout, "Mapped address: %J\n", map);
}

static void ice_gather_handler(int err, uint16_t scode, const char *reason,
    void *arg)
{
#define ICEERR(s) { serr = s; goto ice_gather_fail; }
    const char *serr = NULL;
    struct stun_conf stun_conf;
    struct media_data *md = static_cast<struct media_data *>(arg);
    int i;

    if (err) {
        fprintf(stderr, "Gathering failed: %d\n", err);
        return;
    }

    struct le *elem;
    struct list *cands= icem_lcandl(md->icem);
    LIST_FOREACH(cands, elem) {
        // useless since it doesnt expose the socket we need for keepalives
        const struct ice_cand *cand = static_cast<const struct ice_cand *>(elem->data);
    }
    re_printf("%H", icem_debug, md->icem);

    /*for (i = 1; i < md->i_comps; i++) {
        struct stun_keepalive *ska;
        ska = md->p_skas[i];
        err = stun_keepalive_alloc(&ska, IPPROTO_UDP, md->p_socks[i], 0,
        &md->stun_sock, NULL, mapped_addr_handler, NULL);
        if (err) ICEERR("ska allocation");
        stun_keepalive_enable(ska, 5);
    }
    icem_conncheck_start(md->icem);*/

ice_gather_fail:
    if (err) fprintf(stderr, "ice gather error %d: %s\n", err, serr);
#undef ICEERR
}

static void signal_handler(int signum)
{
  (void)re_fprintf(stderr, "caught signal %d\n", signum);
  re_cancel();
}

static void stun_dns_handler(int err, const struct sa *srv, void *arg)
{
    const char *serr = NULL;
#define DNSERR(s) { serr = s; goto stun_dns_err; }
    struct stun_data *sd = static_cast<struct stun_data *>(arg);
    struct sa *stun_srv = &sd->stun_sock;

    if (err) DNSERR("entering stun dns handler");

    sa_cpy(stun_srv, srv);
    sa_cpy(&sd->p_md->stun_sock, stun_srv);
  re_fprintf(stdout, "Resolved STUN server: %J\n", stun_srv);

    err = icem_gather_srflx(sd->icem, stun_srv);
    if (err) DNSERR("srflx gather");

stun_dns_err:
    if (err) fprintf(stderr, "stun DNS error %d: %s\n", err, serr);
#undef DNSERR
}

static void rtp_handler(const struct sa *src, const struct rtp_header *hdr,
    struct mbuf *mb, void *arg)
{
    printf("Receiving RTP\n");
}

static void rtcp_handler(const struct sa *src, struct  rtcp_msg *msg,
    void *arg)
{
    printf("Receiving RTCP\n");
}

static int init_dns(struct media_data *md)
{
    const char *serr;
#define IDNSERR(s) { serr = s; goto init_dns_fail; }
    struct sa nsv[4];
    uint32_t nsn = ARRAY_SIZE(nsv);
    int err = 0;
    err = dns_srv_get(NULL, 0, nsv, &nsn);
    if (err) IDNSERR("dns_srv_get");
    err = dnsc_alloc(&md->dnsc, NULL, nsv, nsn);
    if (err) IDNSERR("dnsc_alloc");
init_dns_fail:
    if (err) fprintf(stderr, "init_dns error %d: %s\n", err, serr);
    return err;
}

static int get_stun(struct media_data *md,
    char *server, int port)
{
    const char *serr;
#define STUNERR(s) { serr = s; goto stunerr; }
    int err = 0;
    struct stun_data *sd;

    if (md->i_stun_srvs >= MAX_STUN_SRVS) {
        err = ENOBUFS;
        STUNERR("max stun servers reached");
    }

    if (!md->dnsc) {
        err = init_dns(md);
        if (err) STUNERR("init_dns");
    }

    sd = &md->stun_srvs[md->i_stun_srvs++];
    sd->icem = md->icem;
    sd->p_md = md;

    err = stun_server_discover(&sd->dns, md->dnsc, "stun", stun_proto_udp,
        AF_INET, server, port, stun_dns_handler, sd);
    if (err) STUNERR("stun server discover");

stunerr:
    if (err) fprintf(stderr, "stun error %d : %s\n", err, serr);
    return err;
#undef STUNERR
}

static int add_comp(struct media_data *md, struct udp_sock *sock)
{
    int i;
    if (md->i_comps < 0 || md->i_comps >= MAX_COMPS) return -1;
    i = ++md->i_comps; // pre-incr because we start with 1 (from 0)
    md->p_socks[i - 1] = sock; // because we start at 1
    return icem_comp_add(md->icem, i, sock);
}

int main(int argc, char **argv)
{
    const char *serr;
#define MAINERR(s) { serr = s; goto main_err; }
    struct ice *ice = NULL;
    struct rtp_sock *rs = NULL;
    struct media_data media_data = {0};
    struct sa laddr;
    int err, offerer = 1;
    err = libre_init();
    if (err) MAINERR("libre init");
    err = ice_alloc(&ice, ICE_MODE_FULL, offerer);
    if (err) MAINERR("ice allocation");
    err = icem_alloc(&media_data.icem, ice, IPPROTO_UDP, 0, ice_gather_handler,
        NULL, &media_data);
    if (err) MAINERR("icem allocation");
    icem_set_compat(media_data.icem, true);
    sa_init(&laddr, AF_INET); // listen on all interfaces
    if (err) MAINERR("sa_init");
    err = rtp_listen(&rs, IPPROTO_UDP, &laddr, 20000, 20001, true,
        rtp_handler, rtcp_handler, NULL);
    if (err) MAINERR("rtp listen");
    err = add_comp(&media_data, rtp_sock(rs));
    if (err) MAINERR("rtp add");
    err = add_comp(&media_data, rtcp_sock(rs));
    if (err) MAINERR("rtcp add");
    err = net_if_apply(if_handler, &media_data);
    if (err) MAINERR("iface enumeration");
    err = get_stun(&media_data, "stun.l.google.com", 19302);
    if (err) MAINERR("google stun0");
    /*err = get_stun(&media_data, "stun4.l.google.com", 19302);
    if (err) MAINERR("google stun4");
    err = get_stun(&media_data, "stun.iptel.org", 0);
    if (err) MAINERR("iptel stun");
    err = get_stun(&media_data, "stun.ekiga.net", 0);
    if (err) MAINERR("ekiga stun");*/
    re_main(signal_handler);
    return 0;
main_err:
    fprintf(stderr, "Error %d: %s\n", err, serr);
    return 17;
}
