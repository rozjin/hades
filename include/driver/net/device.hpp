#ifndef NET_DEVICE_HPP
#define NET_DEVICE_HPP

#include "fs/dev.hpp"
#include "ipc/wire.hpp"
#include "util/types.hpp"
#include <frg/hash_map.hpp>
#include <frg/rcu_radixtree.hpp>
#include <driver/net/types.hpp>
#include <mm/mm.hpp>

namespace net {
    struct setup_args {
        vfs::devfs::bus_space *flash_space;
        vfs::devfs::bus_space *reg_space;
        int irq;
        int flags;
    };

    class device {
        public:
            frg::hash_map<uint32_t, uint8_t *, frg::hash<uint32_t>, memory::mm::heap_allocator> arp_table;
            frg::vector<net::route, memory::mm::heap_allocator> ipv4_routing_table;

            frg::hash_map<uint32_t, ipc::wire, 
                frg::hash<uint32_t>,  memory::mm::heap_allocator> pending_arps;

            // TODO: IP Fragmemtation
            net::mac mac;
            char *ipv4_gateway_addr;
            char *ipv4_host_addr;
            char *ipv4_netmask_addr;

            uint32_t ipv4_gateway;
            uint32_t ipv4_host;
            uint32_t ipv4_netmask;

            virtual void init_routing() = 0;
            virtual void add_route(const char *ipv4_dest, 
                const char *ipv4_gateway, const char *ipv4_netmask, 
                uint16_t mtu,
                uint32_t dest_mask) = 0;
            virtual uint32_t route(uint32_t dest) = 0;
            virtual void send(const void *buf, size_t len) = 0;

            device(): arp_table(frg::hash<uint32_t>()), ipv4_routing_table(), pending_arps(frg::hash<uint32_t>()) {}
    };
}

#endif