#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

uint16_t calc_ip_checksum(ip_hdr *ip_header) {
  uint16_t prev_checksum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint32_t new_checksum = 0;
  uint16_t ip_len = 4 * ip_header->ip_hl;
  for (uint16_t *p = (uint16_t *)ip_header, i = 0; i < ip_len; i+=2, p++) {
    new_checksum += ntohs(*p);
    // fprintf(stderr, "%04x ", ntohs(*p));
  }
  // fprintf(stderr, "\nchecksum: (%x)", new_checksum);
  ip_header->ip_sum = prev_checksum;
  new_checksum = (new_checksum & 0xffff) + (new_checksum >> 16);
  new_checksum = (new_checksum & 0xffff) + (new_checksum >> 16);
  // fprintf(stderr, " %x\n",  (uint16_t)~new_checksum);
  return htons((uint16_t)~new_checksum);
}

uint16_t calc_icmp_checksum(icmp_hdr *icmp_h, uint32_t len) {
  uint16_t prev_checksum = icmp_h->icmp_sum;
  icmp_h->icmp_sum = 0;
  uint32_t new_checksum = 0;
  for (uint16_t *p = (uint16_t *)icmp_h, i = 0; i < len; i+=2, p++) {
    new_checksum += ntohs(*p);
  }
  icmp_h->icmp_sum = prev_checksum;
  new_checksum = (new_checksum & 0xffff) + (new_checksum >> 16);
  new_checksum = (new_checksum & 0xffff) + (new_checksum >> 16);
  return htons((uint16_t)~new_checksum);
}

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  // std::cerr << std::endl << "-------------------------------" << std::endl;
  // std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    // std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  // extract ethernet frame
  struct ethernet_hdr* ethHdr = (struct ethernet_hdr*)packet.data();
  if (ethertype(packet.data()) != ethertype_ip) { // ignore non ip packets
    // std::cerr << "invalid ethertype" << ethertype(packet.data()) << std::endl;
    return;
  }

  // std::cerr << "routing table:\n" << getRoutingTable() << std::endl;
  // std::cerr << "arp cache:\n" << m_arp << std::endl;
  // std::cerr <<"[Packet Received]\n";
  // print_hdr_eth(packet.data());

  auto packet_mac = macToString(ethHdr->ether_dhost);
  if (packet_mac != macToString(iface->addr) && packet_mac != "FF:FF:FF:FF:FF:FF") {
    return;
  }

  // handle ip packet
  struct ip_hdr* ipHdr = (struct ip_hdr*)(packet.data() + sizeof(struct ethernet_hdr));
  // print_hdr_ip((uint8_t*)ipHdr);

  // error checking
  if (ipHdr->ip_len < 20 || ipHdr->ip_sum != calc_ip_checksum(ipHdr)) {
    return;
  }

  uint32_t src_ip = ipHdr->ip_src;
  uint32_t dst_ip = ipHdr->ip_dst;

  // find if dst is me
  bool dst_is_me = false;
  for (auto& iface: m_ifaces) {
    if (iface.ip == dst_ip) {
      dst_is_me = true;
      break;
    }
  }
  // if (dst_ip == 0xFFFFFFFF) // broadcast
  //   dst_is_me = true;

  if (dst_is_me) {
    // std::cerr << "Dst is me!" << std::endl;
    // std::cerr << "sending packet" << std::endl;
    if (ipHdr->ip_p == ip_protocol_icmp) { // icmp packet
      // handle icmp packet
      struct icmp_hdr* icmpHdr = (struct icmp_hdr*)(packet.data() + sizeof(struct ethernet_hdr)
        + sizeof(struct ip_hdr));
      uint32_t icmp_len = ntohs(ipHdr->ip_len) - 4 * ipHdr->ip_hl;

      // error checking
      if (icmpHdr->icmp_sum != calc_icmp_checksum(icmpHdr, icmp_len)) {
        return;
      }
      
      if (icmpHdr->icmp_type == 0x08) { // ECHO
        // packet for sending
        Buffer out_packet(packet);
        struct ethernet_hdr* out_ethHdr = (struct ethernet_hdr*)out_packet.data();
        struct ip_hdr* out_ipHdr = (struct ip_hdr*)(out_packet.data() + sizeof(struct ethernet_hdr));
        struct icmp_hdr* out_icmpHdr = (struct icmp_hdr*)(out_packet.data() + sizeof(struct ethernet_hdr)
          + sizeof(struct ip_hdr));
        
        // swap mac addr
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
          auto tmp = out_ethHdr->ether_dhost[i];
          out_ethHdr->ether_dhost[i] = out_ethHdr->ether_shost[i];
          out_ethHdr->ether_shost[i] = tmp;
        }
        // swap src and dst ip
        out_ipHdr->ip_dst = src_ip;
        out_ipHdr->ip_src = dst_ip;
        // change ip ttl
        out_ipHdr->ip_ttl = 64;
        // change icmp type
        out_icmpHdr->icmp_type = 0x00;
        // checksums
        out_icmpHdr->icmp_sum = calc_icmp_checksum(out_icmpHdr, icmp_len);
        out_ipHdr->ip_sum = calc_ip_checksum(out_ipHdr);

        // std::cerr << "sending packet" << std::endl;
        // print_hdr_eth((uint8_t*)out_ethHdr);
        // print_hdr_ip((uint8_t*)out_ipHdr);
        // print_hdr_icmp((uint8_t*)out_icmpHdr);
        sendPacket(out_packet, inIface);
      }
    }
  } else { // routing
    Buffer out_packet(packet);
    struct ethernet_hdr* out_ethHdr = (struct ethernet_hdr*)out_packet.data();
    struct ip_hdr* out_ipHdr = (struct ip_hdr*)(out_packet.data() + sizeof(struct ethernet_hdr));
    out_ipHdr->ip_ttl--;
    if (out_ipHdr->ip_ttl == 0) // ttl = 0
      return;
    out_ipHdr->ip_sum = calc_ip_checksum(out_ipHdr);

    auto entry = m_routingTable.lookup(dst_ip);
    auto out_iface = findIfaceByName(entry.ifName);
    // std::cerr << "found entry: " << ipToString(entry.gw) << " / " << entry.ifName << std::endl;

    auto arpEntry = m_arp.lookup(dst_ip);
    if (arpEntry.get() != NULL) { // send packet
      // std::cerr << "got arp entry" << std::endl;
      memcpy(out_ethHdr->ether_shost, out_iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(out_ethHdr->ether_dhost, arpEntry.get()->mac.data(), ETHER_ADDR_LEN);
      // print_hdr_eth((uint8_t*)out_ethHdr);
      // print_hdr_ip((uint8_t*)out_ipHdr);
      sendPacket(out_packet, out_iface->name);
      // std::cerr << "packet sent through " << out_iface->name << std::endl;
    } else { // generate arp request
      m_arp.queueRequest(dst_ip, out_packet, entry.ifName);
      // std::cerr << "arp request queued" << std::endl;
    }
  }
}

SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
