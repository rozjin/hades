#include "driver/net/ip.hpp"
#include "driver/net/icmp.hpp"
#include "driver/net/types.hpp"
#include <cstddef>
#include <cstdint>
#include <driver/net/protos.hpp>

static log::subsystem logger = log::make_subsystem("IP");
void net::ipv4::ipv4_handle(net::device *dev, void *pkt, size_t len) {
    net::pkt::ipv4 *ipv4_pkt = (pkt::ipv4 *) pkt;
    size_t hdr_len = (ipv4_pkt->ihl * 4);

    uint8_t *options = (uint8_t *) (ipv4_pkt + sizeof(pkt::ipv4));
    size_t options_size =  hdr_len - sizeof(pkt::ipv4);
    
    uint16_t pkt_len = ntohs(ipv4_pkt->len);

    void *body = (void *) ((char *) pkt + hdr_len);
    size_t body_size = pkt_len - hdr_len;

    // 5.2.2 Tests

    bool bad_length = true;
    // Test 1
    if (len >= sizeof(pkt::ipv4)) {
        // Good length
        bad_length = false;
    }

    if (pkt_len >= hdr_len) {
        bad_length = false;
    }

    net::checksum checksum{};
    checksum.update(ipv4_pkt, hdr_len);
    uint16_t checksum_val = checksum.finalize();

    // Test 2
    if (checksum_val) {
        // Drop the packet
        return;
    }

    // Test 3
    if (ipv4_pkt->ver != 4) {
        // Drop the packet
    }

    // Test 4
    if (hdr_len != sizeof(pkt::ipv4)) {
        if (ipv4_pkt->ihl == 4) {
            if (bad_length && len >= 16 && pkt_len >= 16) {
                // Send ICMP Parameter Problem
                return;
            }
        }

        return;
    }

    uint32_t dest_ip = ntohl(ipv4_pkt->dest_ip);
    uint32_t src_ip = ntohl(ipv4_pkt->src_ip);

    if (dest_ip != dev->ipv4_host) {
        // Not us
        return;
    }

    switch(ipv4_pkt->proto) {
        case 0x01: {
            icmp_handle(dev, src_ip, body, body_size);
        }

        case 0x06: {
            break;
        }

        case 0x11: {
            break;
        }
    }
}

// TODO: connection state for UDP/TCP to report back errors
void net::ipv4::ipv4_send(net::device *dev, uint32_t dest_ip, 
        uint8_t proto, void *buf, size_t len, uint8_t ttl) {
    uint32_t gateway_ip;

    // we are on the same network
    if ((dest_ip & dev->ipv4_netmask) == (dev->ipv4_host & dev->ipv4_netmask)) {
        gateway_ip = dest_ip;
    } else {
        gateway_ip = dev->route(dest_ip);
        if (gateway_ip == 0) {
            gateway_ip = dev->ipv4_gateway;
        }
    }

    uint8_t *gateway_mac = dev->arp_table[dest_ip];
    if (gateway_mac == nullptr) {
        arp::arp_probe(dev, dest_ip);
        arp::arp_wait(dev, dest_ip);

        if (dev->arp_table[dest_ip] == nullptr) {
            char dest_addr[16];
            kmsg(logger, "Unable to resolve destination %s", ipv4_ntop(dest_ip, dest_addr));
            return;
        }
    }
    
    size_t eth_pkt_len = sizeof(net::eth) + sizeof(pkt::ipv4) + len;
    char *eth_pkt = (char *) kmalloc(eth_pkt_len);

    net::eth *eth_hdr = (net::eth *) eth_pkt;
    memcpy(eth_hdr->dest, gateway_mac, net::eth_alen);
    memcpy(eth_hdr->src, dev->mac, net::eth_alen);
    eth_hdr->type = net::htons(0x0800);

    pkt::ipv4 *ipv4_pkt = (pkt::ipv4 *) (eth_pkt + sizeof(net::eth));

    ipv4_pkt->ver = 4;
    ipv4_pkt->ihl = sizeof(pkt::ipv4) / 4;
    ipv4_pkt->len = htons(sizeof(pkt::ipv4) + len);
    ipv4_pkt->ttl = 64;
    ipv4_pkt->proto = proto;

    ipv4_pkt->src_ip = htonl(dev->ipv4_host);
    ipv4_pkt->dest_ip = htonl(dest_ip);
    ipv4_pkt->checksum = 0;

    net::checksum checksum{};
    checksum.update(ipv4_pkt, sizeof(pkt::ipv4));

    ipv4_pkt->checksum = htons(checksum.finalize());
    memcpy((char *) ipv4_pkt + sizeof(pkt::ipv4), buf, len);

    dev->send(eth_pkt, eth_pkt_len);
    kfree(eth_pkt);
}

void net::ipv4::icmp_send(net::device *dev, uint32_t dest_ip, 
        uint8_t type, uint8_t code, uint32_t rem, void *buf, size_t len) {
    size_t icmp_pkt_len = sizeof(pkt::icmp) + len;
    pkt::icmp *icmp_pkt = (pkt::icmp *) kmalloc(icmp_pkt_len);
    memcpy((char *) icmp_pkt + sizeof(pkt::icmp), buf, len);
    
    icmp_pkt->type = type;
    icmp_pkt->code = code;
    icmp_pkt->rem = htonl(rem);
    icmp_pkt->checksum = 0;

    net::checksum checksum{};
    checksum.update(icmp_pkt, icmp_pkt_len);

    icmp_pkt->checksum = htons(checksum.finalize());

    ipv4_send(dev, dest_ip, 1, icmp_pkt, icmp_pkt_len);
    kfree(icmp_pkt);
}

void net::ipv4::icmp_handle(net::device *dev, uint32_t src_ip, void *pkt, size_t len) {
    net::pkt::icmp *icmp_pkt = (net::pkt::icmp *) pkt;

    void *pkt_data = (char *) pkt + sizeof(pkt::icmp);
    size_t pkt_len = len - sizeof(pkt::icmp);

    net::checksum checksum{};
    checksum.update(pkt, len);
    uint16_t checksum_val = checksum.finalize();

    if (checksum_val) {
        // TODO: some error handling
        return;
    }

    switch (icmp_pkt->type) {
        // echo reply
        case 0: {

        };

        // unreachable
        case 3: {
            switch (icmp_pkt->code) {
                // TODO: report which code it is
            }

            if (len < sizeof(pkt::icmp) + sizeof(pkt::ipv4) + 8) {
                return;
            }

            pkt::ipv4 *ipv4_hdr = (pkt::ipv4 *) ((char *) pkt + sizeof(pkt::icmp));
            // todo: match up to active socket and report error

            uint32_t dest_ip = ntohl(ipv4_hdr->dest_ip);

            char ipv4_dest_addr[16];
            kmsg(logger, "ICMP: Unreachable, dest: %s", ipv4_ntop(dest_ip, ipv4_dest_addr));

            break;
        }

        // quench
        case 4: {
            break;
        }

        // redirect
        case 5: {
            break;
        }

        // alternate host addr
        case 6: {
            break;
        }

        // echo request
        case 8: {
            uint32_t dest_ip = src_ip;
            uint16_t ident = ntohl(icmp_pkt->rem) >> 16;
            uint16_t seq = ntohl(icmp_pkt->rem) & 0xFFFF;
            icmp_send(dev, dest_ip,
                0, 0, (ident << 16) | seq, pkt_data, pkt_len);

            break;
        }

        // router advertisment
        case 9: {
            break;
        }

        // time exceeded
        case 11: {
            break;
        }

        // invalid IP header
        case 12: {
            break;
        }

        // timestamp request
        case 13: {
            break;
        }

        // info request
        case 15: {
            break;
        }

        // addr mask request
        case 17: {
            break;
        }
    }
}
