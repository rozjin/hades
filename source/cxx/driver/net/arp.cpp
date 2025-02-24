#include "arch/types.hpp"
#include "driver/net/device.hpp"
#include "mm/mm.hpp"
#include "sys/sched/event.hpp"
#include "sys/sched/time.hpp"
#include "sys/sched/event.hpp"
#include "util/types.hpp"
#include <cstdint>
#include <driver/net/protos.hpp>
#include <driver/net/arp.hpp>
#include <driver/net/ip.hpp>

log::subsystem netlog = log::make_subsystem("NET");
void net::arp::arp_send(net::device *dev, net::mac dest_mac, uint32_t dest_ip) {
    size_t eth_pkt_len = sizeof(net::eth) + sizeof(net::pkt::arp_eth_ipv4);
    char *eth_pkt = (char *) kmalloc(eth_pkt_len);

    net::eth *eth_hdr = (net::eth *) eth_pkt;
    memcpy(eth_hdr->dest, dest_mac, net::eth_alen);
    memcpy(eth_hdr->src, dev->mac, net::eth_alen);
    eth_hdr->type = net::htons(0x0806);

    net::pkt::arp_eth_ipv4 *arp_pkt = (net::pkt::arp_eth_ipv4 *) (eth_pkt + sizeof(net::eth));

    arp_pkt->host_type = net::htons(1);
    arp_pkt->proto_type = net::htons(0x0800);

    arp_pkt->host_len = net::eth_alen;
    arp_pkt->proto_len = net::ipv4_alen;

    arp_pkt->op = net::htons(net::pkt::arp_res);

    memcpy(arp_pkt->src_addr, dev->mac, net::eth_alen);
    arp_pkt->src_ip = htonl(dev->ipv4_host);

    memcpy(arp_pkt->dest_addr, dest_mac, net::eth_alen);
    arp_pkt->dest_ip = htonl(dest_ip);

    dev->send(eth_pkt, eth_pkt_len);
    kfree(eth_pkt);
}

void net::arp::arp_handle(net::device *dev, void *pkt) {
    net::pkt::arp_eth_ipv4 *arp_pkt = (net::pkt::arp_eth_ipv4 *) pkt;

    uint16_t host_type = net::ntohs(arp_pkt->host_type);
    uint16_t proto_type = net::ntohs(arp_pkt->proto_type);

    uint8_t host_len = arp_pkt->host_len;
    uint8_t proto_len = arp_pkt->proto_len;

    uint16_t op = net::ntohs(arp_pkt->op);

    // TODO: gratuitous arp

    if (host_type != 1 || proto_type != 0x800) {
        return;
    }

    if (host_len != net::eth_alen || proto_len != net::ipv4_alen) {
        return;
    }

    // TODO: process other people's ARP requests
    switch (op) {
        case net::pkt::arp_res: {
            net::mac dest_mac;
            memcpy(dest_mac, arp_pkt->dest_addr, net::eth_alen);
            if (!net::is_same_mac(dest_mac, dev->mac)) {
                return;
            }

            net::mac src_mac;
            memcpy(src_mac, arp_pkt->src_addr, net::eth_alen);
            uint32_t src_ip = net::ntohl(arp_pkt->src_ip);

            if (dev->arp_table.contains(src_ip)) {
                uint8_t *old_mac = dev->arp_table[src_ip];
                dev->arp_table.remove(src_ip);
                kfree(old_mac);
            }

            uint8_t *arp_mac = (uint8_t *) kmalloc(net::eth_alen);
            memcpy(arp_mac, src_mac, net::eth_alen);

            dev->arp_table.insert(src_ip, arp_mac);
            for (auto tid: dev->pending_arps[src_ip]) {
                ipc::send({tid}, ARP_FOUND);
            }

            dev->pending_arps.remove(src_ip);

            char ipv4_str[16];
            kmsg(netlog, "%s is at %x:%x:%x:%x:%x:%x", net::ipv4_ntop(src_ip, ipv4_str), src_mac[0], src_mac[1], src_mac[2],
                src_mac[3], src_mac[4], src_mac[5]);
            break;
        }

        case net::pkt::arp_req: {
            net::mac dest_mac;
            memcpy(dest_mac, arp_pkt->src_addr, net::eth_alen);
            uint32_t dest_ip = ntohl(arp_pkt->src_ip);

            arp_send(dev, dest_mac, dest_ip);

            break;
        }
    }
}

void net::arp::arp_probe(net::device *dev, uint32_t ip) {
    size_t eth_pkt_len = sizeof(net::eth) + sizeof(net::pkt::arp_eth_ipv4);
    char *eth_pkt = (char *) kmalloc(eth_pkt_len);

    net::eth *eth_hdr = (net::eth *) eth_pkt;
    memcpy(eth_hdr->dest, net::broadcast_mac, net::eth_alen);
    memcpy(eth_hdr->src, dev->mac, net::eth_alen);
    eth_hdr->type = net::htons(0x0806);

    net::pkt::arp_eth_ipv4 *arp_pkt = (net::pkt::arp_eth_ipv4 *) (eth_pkt + sizeof(net::eth));

    arp_pkt->host_type = net::htons(1);
    arp_pkt->proto_type = net::htons(0x0800);

    arp_pkt->host_len = net::eth_alen;
    arp_pkt->proto_len = net::ipv4_alen;

    arp_pkt->op = net::htons(net::pkt::arp_req);

    memcpy(arp_pkt->src_addr, dev->mac, net::eth_alen);
    arp_pkt->src_ip = 0;

    memset(arp_pkt->dest_addr, 0, net::eth_alen);
    arp_pkt->dest_ip = htonl(ip);

    dev->send(eth_pkt, eth_pkt_len);
    kfree(eth_pkt);
}

void net::arp::arp_wait(net::device *dev, uint32_t ip) {
    auto timeout = sched::timespec::ms(30000);
    if (!dev->pending_arps.contains(ip)) {
        dev->pending_arps.insert(ip, frg::vector<tid_t, memory::mm::heap_allocator>());
    } 

    dev->pending_arps[ip].push(arch::get_tid());
    ipc::receive({ ARP_FOUND }, false, &timeout);
}