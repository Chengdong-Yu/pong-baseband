// SPDX-License-Identifier: BSD-2-Clause
// Adapted from HoshinoYumeka/chiba233 UniXNU/QcomBaseband at dd0199cf.
// Included by PongBasebandService.cpp. Actual backend registration and
// WDS replies gate link state; interfaces start down, no fabricated IP.
// CommCenter owns WDS and address configuration; this layer never dials or invents addresses.
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <net/kpi_interface.h>
#include <net/kpi_protocol.h>
extern "C" {
#include <net/bpf.h>
}
#include <netinet/in.h>
namespace {
struct bb_pdp_if {
  ifnet_t ifp;
  mbuf_t head, tail;
  uint32_t queued, families, blocked;
  uint64_t tx, rx, dropped, busy, requested;
};
static bb_pdp_if bb_pdp_ifaces[CBP_INTERFACES];
static IOLock *bb_pdp_lock;
static uint32_t bb_pdp_initialized;

static errno_t bb_pdp_demux(ifnet_t, mbuf_t m, char *, protocol_family_t *family)
{
  uint8_t first;
  if (mbuf_copydata(m, 0, 1, &first)) return ENOENT;
  *family = first >> 4 == 4 ? PF_INET : first >> 4 == 6 ? PF_INET6 : 0;
  return *family ? 0 : EPROTONOSUPPORT;
}
static errno_t bb_pdp_add_proto(ifnet_t, protocol_family_t f, const ifnet_demux_desc *, uint32_t)
{ return f == PF_INET || f == PF_INET6 ? 0 : EPROTONOSUPPORT; }
static errno_t bb_pdp_del_proto(ifnet_t ifp, protocol_family_t family)
{
  printf("Pong pdp: unplumb unit %u family %u\n", ifnet_unit(ifp), family);
  return 0;
}
static errno_t bb_pdp_input(ifnet_t ifp, protocol_family_t f, mbuf_t m, char *)
{
  if (proto_input(f, m)) { mbuf_freem(m); ifnet_stat_increment_in(ifp, 0, 0, 1); }
  return 0;
}
static errno_t bb_pdp_pre_output(ifnet_t, protocol_family_t, mbuf_t *, const sockaddr *, void *, char *, char *)
{ return 0; }  // raw IP: no link header, software checksums, no advertised offloads
// in_domifattach/proto_plumb is used again after CommCenter tears an IP service down.
// Match XNU's utun_attach_proto contract, including EEXIST for an attached protocol.
static errno_t bb_pdp_plumb(ifnet_t ifp, protocol_family_t family)
{
  ifnet_attach_proto_param proto = {};
  proto.input = bb_pdp_input; proto.pre_output = bb_pdp_pre_output;
  const errno_t error = ifnet_attach_protocol(ifp, family, &proto);
  printf("Pong pdp: plumb unit %u family %u result %d\n", ifnet_unit(ifp), family, error);
  return error;
}
static errno_t bb_pdp_ioctl(ifnet_t ifp, unsigned long cmd, void *data)
{
  switch (cmd) {
    case SIOCSIFMTU: {
      const int mtu = static_cast<ifreq *>(data)->ifr_mtu;
      if (mtu < 1280 || mtu > 1492) return EINVAL;
      return ifnet_set_mtu(ifp, static_cast<uint32_t>(mtu));
    }
    case SIOCSIFFLAGS: case SIOCSIFADDR: case SIOCSIFDSTADDR: return 0;
    case SIOCGIFMEDIA: {
      auto *m=static_cast<ifmediareq *>(data);
      auto *p=static_cast<bb_pdp_if *>(ifnet_softc(ifp));
      const int medium=IFM_OTHER|IFM_AUTO,requested=m->ifm_count;
      IOLockLock(bb_pdp_lock);const bool up=p->families&&!p->blocked;IOLockUnlock(bb_pdp_lock);
      m->ifm_current=m->ifm_active=medium;m->ifm_mask=0;
      m->ifm_status=IFM_AVALID|(up?IFM_ACTIVE:0);m->ifm_count=1;
      if(requested>0&&m->ifm_ulist)return copyout(&medium,(user_addr_t)m->ifm_ulist,sizeof medium);
      return 0;
    }
    default:
      // Generic network probes repeat these operations for every ifnet.
      // Keep the real unsupported result; log each distinct shape once.
      static unsigned long seen[16];static unsigned used;
      bool known=false;
      IOLockLock(bb_pdp_lock);
      for(unsigned i=0;i<used;i++)if(seen[i]==cmd){known=true;break;}
      bool report=!known&&used<16;if(report)seen[used++]=cmd;
      IOLockUnlock(bb_pdp_lock);
      if(report)printf("Pong pdp: ioctl 0x%lx unit %u unsupported\n", cmd, ifnet_unit(ifp));
      return EOPNOTSUPP;
  }
}
static errno_t bb_pdp_output(ifnet_t ifp, mbuf_t m)
{
  auto *p = static_cast<bb_pdp_if *>(ifnet_softc(ifp));
  __atomic_fetch_add(&p->requested, 1u, __ATOMIC_RELAXED);
  const size_t len = mbuf_pkthdr_len(m);
  uint8_t first = 0;
  if (!len || len > ifnet_mtu(ifp) || mbuf_copydata(m, 0, 1, &first)) { mbuf_freem(m); return EMSGSIZE; }
  const uint32_t bit = cbp_family_bit(first >> 4);
  IOLockLock(bb_pdp_lock);
  if (!bit || !(p->families & bit) || p->blocked || p->queued == 64u) {
    p->dropped++; IOLockUnlock(bb_pdp_lock); mbuf_freem(m); return ENETDOWN;
  }
  mbuf_setnextpkt(m, nullptr);
  if (p->tail) mbuf_setnextpkt(p->tail, m); else p->head = m;
  p->tail = m; p->queued++;
  IOLockUnlock(bb_pdp_lock);
  return 0;
}
static void bb_pdp_receive(uint32_t mux, const uint8_t *ip, uint32_t n, uint32_t version)
{
  if (!bb_pdp_lock || !cbp_mux_ok(mux) || !n || (version != 4 && version != 6)) return;
  auto *p = &bb_pdp_ifaces[mux - 1u];
  IOLockLock(bb_pdp_lock);
  const bool usable = p->ifp && (p->families & cbp_family_bit(version)) && !p->blocked;
  if (!usable) p->dropped++;
  IOLockUnlock(bb_pdp_lock);
  if (!usable || !(ifnet_flags(p->ifp) & IFF_UP)) return;
  mbuf_t m = nullptr;
  if (mbuf_allocpacket(MBUF_DONTWAIT, n, nullptr, &m) || !m) return;
  if (mbuf_copyback(m, 0, n, ip, MBUF_DONTWAIT)) { mbuf_freem(m); return; }
  mbuf_pkthdr_setrcvif(m, p->ifp);
  mbuf_pkthdr_setheader(m, nullptr);
  bpf_tap_in(p->ifp, DLT_RAW, m, nullptr, 0);
  ifnet_stat_increment_param inc = {};
  inc.packets_in = 1; inc.bytes_in = n;
  const errno_t error = ifnet_input(p->ifp, m, &inc);
  if (error) mbuf_freem(m);
  else p->rx++;
}
static void bb_pdp_init()
{
  if (bb_pdp_initialized) return;
  bb_pdp_lock = IOLockAlloc();
  if (!bb_pdp_lock) return;
  const errno_t ipv4 = proto_register_plumber(PF_INET, IFNET_FAMILY_CELLULAR, bb_pdp_plumb, nullptr);
  const errno_t ipv6 = proto_register_plumber(PF_INET6, IFNET_FAMILY_CELLULAR, bb_pdp_plumb, nullptr);
  printf("Pong pdp: protocol plumbers IPv4 %d IPv6 %d\n", ipv4, ipv6);
  for (uint32_t i = 0; i < CBP_INTERFACES; i++) {
    auto *p = &bb_pdp_ifaces[i];
    ifnet_init_eparams init = {};
    init.ver = IFNET_INIT_CURRENT_VERSION; init.len = sizeof init;
    init.flags = IFNET_INIT_LEGACY | IFNET_INIT_NX_NOAUTO;
    init.name = "pdp_ip"; init.unit = i;
    init.family = IFNET_FAMILY_CELLULAR; init.type = IFT_CELLULAR; init.softc = p;
    init.output = bb_pdp_output; init.demux = bb_pdp_demux;
    init.add_proto = bb_pdp_add_proto; init.del_proto = bb_pdp_del_proto; init.ioctl = bb_pdp_ioctl;
    errno_t error = ifnet_allocate_extended(&init, &p->ifp);
    if (!error) {
      ifnet_set_hdrlen(p->ifp, 0); ifnet_set_addrlen(p->ifp, 0);
      ifnet_set_mtu(p->ifp, 1492);  // IPA MTU minus MAPv4 headers, as rmnet_vnd_headroom
      ifnet_set_flags(p->ifp, IFF_POINTOPOINT | IFF_MULTICAST, 0xffff);
      ifnet_set_eflags(p->ifp, IFEF_NOAUTOIPV6LL, IFEF_NOAUTOIPV6LL);
      error = ifnet_attach(p->ifp, nullptr);
      if (error) { ifnet_release(p->ifp); p->ifp = nullptr; }
    }
    if (!error) {
      error = bb_pdp_plumb(p->ifp, PF_INET);
      if (!error || error == EEXIST) error = bb_pdp_plumb(p->ifp, PF_INET6);
      if (!error || error == EEXIST) error = bpf_attach(p->ifp, DLT_RAW, 0, nullptr, nullptr);
    }
    printf("Pong pdp: pdp_ip%u mux %u registered result %d (initially down)\n", i, i + 1u, error);
  }
  pong_wan_receive = bb_pdp_receive;
  bb_pdp_initialized = 1;
}
// Wi-Fi thread only; never hold bbGate while calling the network stack or ringing GSI.
static void bb_pdp_poll()
{
  if (!bb_pdp_initialized) return;
  uint32_t active[CBP_INTERFACES];
  IOLockLock(bbGate);
  for (uint32_t i = 0; i < CBQ_MAX_CLIENTS; i++) {
    if (!bridge.client[i].used || bridge.client[i].service != CBD_SVC_WDS ||
        bb_pdp_owners[i] != (1u + bridge.client[i].cid + (uint32_t(bridge.client[i].channel) << 8)))
      bzero(&bb_pdp_clients[i], sizeof bb_pdp_clients[i]);
  }
  const bool ready = online && pong_wan_ready && pong_wan_ready();
  for (uint32_t i = 0; i < CBP_INTERFACES; i++) active[i] = ready ? cbp_active_families(bb_pdp_clients, CBQ_MAX_CLIENTS, i + 1u) : 0;
  IOLockUnlock(bbGate);
  for (uint32_t i = 0; i < CBP_INTERFACES; i++) {
    auto *p = &bb_pdp_ifaces[i];
    if (!p->ifp) continue;
    IOLockLock(bb_pdp_lock);
    const bool changed = p->families != active[i];
    p->families = active[i];
    IOLockUnlock(bb_pdp_lock);
    if (changed) {
      ifnet_set_flags(p->ifp, active[i] ? IFF_RUNNING : 0, IFF_RUNNING);
      printf("Pong pdp: pdp_ip%u active families %u\n", i, active[i]);
    }
    for (unsigned batch = 0; batch < 16; batch++) {
      IOLockLock(bb_pdp_lock);
      mbuf_t m = p->head;
      if (m) { p->head = mbuf_nextpkt(m); if (!p->head) p->tail = nullptr; p->queued--; mbuf_setnextpkt(m, nullptr); }
      const bool usable = p->families && !p->blocked;
      IOLockUnlock(bb_pdp_lock);
      if (!m) break;
      uint8_t ip[1492];
      const uint32_t n = static_cast<uint32_t>(mbuf_pkthdr_len(m));
      int error = ENETDOWN;
      if (usable && (ifnet_flags(p->ifp) & IFF_UP) && !mbuf_copydata(m, 0, n, ip) &&
          (active[i] & cbp_family_bit(ip[0] >> 4))) error = pong_wan_send(i + 1u, ip, n);
      if (error == EBUSY) {
        IOLockLock(bb_pdp_lock);
        if (p->queued >= 64u) { p->dropped++; IOLockUnlock(bb_pdp_lock); mbuf_freem(m); break; }
        mbuf_setnextpkt(m, p->head); p->head = m; if (!p->tail) p->tail = m; p->queued++; p->busy++;
        IOLockUnlock(bb_pdp_lock);
        break;
      }
      if (!error) { bpf_tap_out(p->ifp, DLT_RAW, m, nullptr, 0); p->tx++; ifnet_stat_increment_out(p->ifp, 1, n, 0); }
      else { p->dropped++; ifnet_stat_increment_out(p->ifp, 0, 0, 1); }
      mbuf_freem(m);
    }
  }
}
static IOReturn bb_pdp_block(uint32_t unit, uint32_t blocked)
{
  if (unit >= CBP_INTERFACES || !bb_pdp_lock) return kIOReturnBadArgument;
  IOLockLock(bb_pdp_lock); bb_pdp_ifaces[unit].blocked = !!blocked; IOLockUnlock(bb_pdp_lock);
  return kIOReturnSuccess;
}
static void bb_pdp_report(unsigned second)
{
  if (!bb_pdp_lock) return;
  IOLockLock(bb_pdp_lock);
  for (uint32_t i = 0; i < CBP_INTERFACES; i++) {
    const auto &p = bb_pdp_ifaces[i];
    printf("Pong pdp: %u s unit %u families %u blocked %u queued %u tx %llu rx %llu drop %llu busy %llu\n",
      second, i, p.families, p.blocked, p.queued, p.tx, p.rx, p.dropped, p.busy);
    if (p.ifp && (p.requested || p.rx)) printf("Pong pdp stack: %u s unit %u requested %llu flags 0x%x mtu %u\n",
      second, i, p.requested, ifnet_flags(p.ifp), ifnet_mtu(p.ifp));
  }
  IOLockUnlock(bb_pdp_lock);
}
} // namespace
