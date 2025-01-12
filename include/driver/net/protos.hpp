#ifndef NET_HPP
#define NET_HPP

#include <cstddef>
#include <cstdint>
#include <driver/net/device.hpp>
#include <driver/net/types.hpp>

namespace net  {
    namespace arp {
        void arp_send(net::device *dev, net::mac dest_mac, uint32_t dest_ip);
        void arp_handle(net::device *dev, void *pkt);
        void arp_probe(net::device *dev, uint32_t ip);

        void arp_wait(net::device *dev, uint32_t ip);
    }

    namespace ipv4 {
        void ipv4_send(net::device *dev, uint32_t dest_ip, 
            uint8_t proto, void *buf, size_t len, uint8_t ttl = 254);
        void ipv4_handle(net::device *dev, void *pkt, size_t len);

        void icmp_send(net::device *dev, uint32_t dest_ip, 
            uint8_t type, uint8_t code, uint32_t rem, void *buf, size_t len);
        void icmp_handle(net::device *dev, uint32_t src_ip, void *pkt, size_t len);
    }
}

#endif