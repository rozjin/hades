#include "arch/types.hpp"
#include "driver/net/arp.hpp"
#include "driver/net/ip.hpp"
#include "driver/net/types.hpp"
#include "lai/helpers/pci.h"
#include "mm/pmm.hpp"
#include "sys/pci.hpp"
#include "util/log/log.hpp"
#include "util/misc.hpp"
#include <cstdint>
#include <mm/common.hpp>
#include <mm/mm.hpp>
#include <cstddef>
#include <util/io.hpp>
#include <driver/net/e1000.hpp>

static log::subsystem logger = log::make_subsystem("E1000");
log::subsystem netlog = log::make_subsystem("NET");

e1000::device *net_dev;
void e1000::device::write(uint16_t off, uint32_t value) {
    if (bar_type) {
        io::mmio::write(mem_base + off, value);
    } else {
        io::writed(io_base, off);
        io::writed(io_base + 4, value);
    }
}

uint32_t e1000::device::read(uint16_t off) {
    if (bar_type) {
        return io::mmio::read<uint32_t>(mem_base + off);
    }

    io::writed(io_base, off);
    return io::readd(io_base + 4);
}

bool e1000::device::check_eeprom() {
    uint32_t val = 0;
    write(reg_eeprom_read, 0x1);

    // TODO: better wait
    for (size_t i = 0; i < 1000 && !has_eeprom; i++) {
        val = read(reg_eeprom_read);
        if (val & 0x10) {
            has_eeprom = true;
        } else {
            has_eeprom = false;
        }
    }

    return has_eeprom;
}

uint32_t e1000::device::read_eeprom(uint8_t off) {
    uint16_t data = 0;
    uint32_t tmp = 0;

    if (has_eeprom) {
        write(reg_eeprom_read, (1 << 0) | ((uint32_t)(off) << 8));
        while (!((tmp = read(reg_eeprom_read)) & (1 << 4))) asm volatile("pause");
    } else {
        write(reg_eeprom_read, (1 << 0) | ((uint32_t)(off) << 2));
        while (!((tmp = read(reg_eeprom_read)) & (1 << 1))) asm volatile("pause");
    }

    data = (uint16_t) ((tmp >> 16) & 0xFFFF);
    return data;
}

bool e1000::device::read_mac() {
    if (has_eeprom) {
        uint32_t tmp;
        tmp = read_eeprom(0);
        mac[0] = tmp & 0xFF;
        mac[1] = tmp >> 8;

        tmp = read_eeprom(1);
        mac[2] = tmp & 0xFF;
        mac[3] = tmp >> 8;

        tmp = read_eeprom(2);
        mac[4] = tmp & 0xFF;
        mac[5] = tmp >> 8;
    } else {
        uint8_t *mem_base_mac_8 = (uint8_t *) (mem_base + 0x5400);
        uint32_t *mem_base_mac_32 = (uint32_t *) (mem_base + 0x5400);

        if (mem_base_mac_32[0] != 0) {
            for (size_t i = 0; i < 6; i++) {
                mac[i] = mem_base_mac_8[i];
            }
        } else return false;
    }

    return true;
}

void e1000::device::reset() {
    write(reg_rctl, 0);
    write(reg_tctl, bit_tctl_psp);
    read(reg_status);

    write(reg_ctrl, read(reg_ctrl) | bit_ctrl_rst);

    while(read(reg_ctrl) & bit_ctrl_rst) { asm volatile("pause"); }
}

void e1000::device::rx_init() {
    uint8_t *rx_base = (uint8_t *) memory::pmm::alloc(util::ceil(sizeof(rx_desc) * rx_max, memory::page_size));

    rx_desc *descs = (rx_desc *) rx_base;
    for (size_t i = 0; i < rx_max; i++) {
        rx_descs[i] = (rx_desc *) ((uint8_t *) descs + (i * sizeof(rx_desc)));

        rx_descs[i]->address = (uint64_t) ((uint8_t *) memory::pmm::alloc(2));
        rx_descs[i]->address = rx_descs[i]->address - memory::x86::virtualBase;

        rx_descs[i]->status = 0;
    }

    write(reg_rx_desc_lo, (uint32_t) ((((uint64_t) rx_base) - memory::x86::virtualBase) & 0xFFFFFFFF));
    write(reg_rx_desc_hi, (uint32_t) ((((uint64_t) rx_base) - memory::x86::virtualBase) >> 32));
    write(reg_rx_desc_len, rx_max * sizeof(rx_desc));

    write(reg_rx_desc_head, 0);
    write(reg_rx_desc_tail, rx_max - 1);

    rx_cur = 0;
    write(reg_rctl, bit_rctl_en | bit_rctl_sbp | bit_rctl_upe | bit_rctl_mpe
                       | bit_rctl_loop | bit_rctl_rdmts_half | bit_rctl_bam | bit_rctl_secrc | bit_rctl_bsize_8k);
}

void e1000::device::tx_init() {
    uint8_t *tx_base = (uint8_t *) memory::pmm::alloc(util::ceil(sizeof(tx_desc) * tx_max, memory::page_size));

    tx_desc *descs = (tx_desc *) tx_base;
    for (size_t i = 0; i < tx_max; i++) {
        tx_descs[i] = (tx_desc *) ((uint8_t *) descs + (i * sizeof(tx_desc)));

        tx_descs[i]->address = 0;
        tx_descs[i]->cmd = 0;
        tx_descs[i]->status = tx_desc::tx_bit_done;
    }

    write(reg_tx_desc_lo, (uint32_t) ((((uint64_t) tx_base) - memory::x86::virtualBase) & 0xFFFFFFFF));
    write(reg_tx_desc_hi, (uint32_t) ((((uint64_t) tx_base) - memory::x86::virtualBase) >> 32));
    write(reg_tx_desc_len, tx_max * sizeof(tx_desc));

    write(reg_tx_desc_head, 0);
    write(reg_tx_desc_tail, 0);

    tx_cur = 0;
    write (reg_tctl, bit_tctl_en | bit_tctl_psp
            | (15 << bit_tctl_ct_shift)
            | (64 << bit_tctl_cl_shift)
            | bit_tctl_rtlc);
    write(reg_tx_ipg, (10 << 0) | (8 << 10) | (6 << 20));
}

void e1000::device::enable_irq() {
    write(reg_imc, 0xFFFFFFFF);
    write(reg_icr, 0xFFFFFFFF);
    read(reg_icr);

    write(reg_ims, bit_ims_lsc | bit_ims_rxdmt | bit_ims_rxt0 | bit_ims_gpi);
    read(reg_icr);
}

void e1000::device::rx_handle() {
    uint16_t old_rx_cur;

    while ((rx_descs[rx_cur]->status & rx_desc::rx_bit_done)) {
        uint8_t *buf = (uint8_t *) (rx_descs[rx_cur]->address + memory::x86::virtualBase);
        uint16_t len = rx_descs[rx_cur]->length;

        net::eth *eth_hdr = (net::eth *) buf;
        switch(net::ntohs(eth_hdr->type)) {
            case 0x0806:
                arp_handle(((char *) eth_hdr) + sizeof(net::eth));
                break;
            default:
                kmsg(netlog, "Unknown packet type receive");
                break;
        }

        // TODO: handle protocols here

        rx_descs[rx_cur]->status = 0;
        old_rx_cur = rx_cur;
        rx_cur = (rx_cur + 1) % rx_max;
        write(reg_rx_desc_tail, old_rx_cur);
    }
}

void e1000::device::arp_send(net::mac dest_mac, uint32_t dest_ip) {
    size_t eth_pkt_len = sizeof(net::eth) + sizeof(net::pkt::arp_eth_ipv4);
    char *eth_pkt = (char *) kmalloc(eth_pkt_len);

    net::eth *eth_hdr = (net::eth *) eth_pkt;
    memcpy(eth_hdr->dest, dest_mac, net::eth_alen);
    memcpy(eth_hdr->src, mac, net::eth_alen);
    eth_hdr->type = net::htons(0x0806);

    net::pkt::arp_eth_ipv4 *arp_pkt = (net::pkt::arp_eth_ipv4 *) (eth_pkt + sizeof(net::eth));

    arp_pkt->host_type = net::htons(1);
    arp_pkt->proto_type = net::htons(0x0800);

    arp_pkt->host_len = net::eth_alen;
    arp_pkt->proto_len = net::ipv4_alen;

    arp_pkt->op = net::htons(net::pkt::arp_res);

    memcpy(arp_pkt->src_addr, mac, net::eth_alen);
    arp_pkt->src_ip = net::ipv4_aton(ipv4_addr);

    memcpy(arp_pkt->dest_addr, dest_mac, net::eth_alen);
    arp_pkt->dest_ip = dest_ip;

    send(eth_pkt, eth_pkt_len);
}

void e1000::device::arp_handle(void *pkt) {
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
            if (!net::is_same_mac(dest_mac, this->mac)) {
                return;
            }

            net::mac src_mac;
            memcpy(src_mac, arp_pkt->src_addr, net::eth_alen);
            uint32_t src_ip = net::ntohl(arp_pkt->src_ip);

            if (arp_table.contains(src_ip)) {
                uint8_t *old_mac = arp_table[src_ip];
                arp_table.remove(src_ip);
                kfree(old_mac);
            }

            uint8_t *arp_mac = (uint8_t *) kmalloc(net::eth_alen);
            memcpy(arp_mac, src_mac, net::eth_alen);

            arp_table.insert(src_ip, arp_mac);

            char *ipv4_str = (char *) kmalloc(16);

            kmsg(netlog, "%s is at %x:%x:%x:%x:%x:%x", net::ipv4_ntoa(src_ip, ipv4_str), src_mac[0], src_mac[1], src_mac[2],
                src_mac[3], src_mac[4], src_mac[5]);
            break;
        }

        case net::pkt::arp_req: {
            net::mac dest_mac;
            memcpy(dest_mac, arp_pkt->src_addr, net::eth_alen);
            uint32_t dest_ip = arp_pkt->src_ip;

            arp_send(dest_mac, dest_ip);
        }
    }
}

void e1000::device::arp_probe() {
    size_t eth_pkt_len = sizeof(net::eth) + sizeof(net::pkt::arp_eth_ipv4);
    char *eth_pkt = (char *) kmalloc(eth_pkt_len);

    net::eth *eth_hdr = (net::eth *) eth_pkt;
    memcpy(eth_hdr->dest, net::broadcast_mac, net::eth_alen);
    memcpy(eth_hdr->src, mac, net::eth_alen);
    eth_hdr->type = net::htons(0x0806);

    net::pkt::arp_eth_ipv4 *arp_pkt = (net::pkt::arp_eth_ipv4 *) (eth_pkt + sizeof(net::eth));

    arp_pkt->host_type = net::htons(1);
    arp_pkt->proto_type = net::htons(0x0800);

    arp_pkt->host_len = net::eth_alen;
    arp_pkt->proto_len = net::ipv4_alen;

    arp_pkt->op = net::htons(net::pkt::arp_req);

    memcpy(arp_pkt->src_addr, mac, net::eth_alen);
    arp_pkt->src_ip = 0;

    memset(arp_pkt->dest_addr, 0, net::eth_alen);
    arp_pkt->dest_ip = net::ipv4_aton(ipv4_gateway);

    send(eth_pkt, eth_pkt_len);
}

bool e1000::device::init() {
    reset();

    check_eeprom();
    if (!read_mac()) return false;

    for (size_t i = 0; i < 0x80; i++) {
        write(0x5200 + (i * 4), 0);
    }

    kmsg(logger, "MAC: %x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    write(reg_fcal, 0);
    write(reg_fcah, 0);
    write(reg_fct, 0);
    write(reg_fcttv, 0);

    write(reg_ctrl, bit_ctrl_asde | bit_ctrl_slu);

    rx_init();
    tx_init();

    write(reg_rx_desc_adv, 0);
    write(reg_rx_delay_tmr, bit_rx_delay_tmr_fpd | 0);
    write(reg_itr, 5000);

    enable_irq();

    return true;
}

void e1000::device::send(const void *buf, size_t len) {
    tx_descs[tx_cur]->address = ((uint64_t) buf) - memory::x86::virtualBase;
    tx_descs[tx_cur]->length = len;

    tx_descs[tx_cur]->cmd = tx_desc::tx_bit_eop | tx_desc::tx_bit_fcs | tx_desc::tx_bit_rs;
    tx_descs[tx_cur]->status = 0;

    uint8_t old_tx_cur = tx_cur;
    tx_cur = (tx_cur + 1) % tx_max;
    write(reg_tx_desc_tail, tx_cur);

    while ((tx_descs[old_tx_cur]->status & tx_desc::tx_bit_done) == 0) { asm volatile("pause"); }
}

void e1000::irq_handler(arch::irq_regs *r) {
    uint32_t status = net_dev->read(reg_icr);
    if (status & 0x04) {
        // TODO: read link speed
    } else if (status & 0x10) {
        // TODO: allocate more rx buffers
    } else if (status & 0x80) {
        net_dev->rx_handle();
    }
}

void e1000::init() {
    pci::device *pci_dev;
    if (!(pci_dev = pci::get_device(intel_id, emu_id))
        && !(pci_dev = pci::get_device(intel_id, i217_id))
        && !(pci_dev = pci::get_device(intel_id, lm_id))) {
        kmsg(netlog, "No E1000 Network Controllers found");
        return;
    }

    pci::bar net_bar;
    if (!pci_dev->read_bar(0, net_bar)) {
        kmsg(logger, "Invalid BAR0");
        return;
    }

    uint8_t bar_type = net_bar.is_mmio;
    uint16_t io_base = net_bar.base;
    uint64_t mem_base = net_bar.base;

    pci_dev->enable_busmastering();
    if (bar_type) pci_dev->enable_mmio();

    net_dev = frg::construct<e1000::device>(memory::mm::heap);

    net_dev->bar_type = bar_type;
    net_dev->io_base = io_base;
    net_dev->mem_base = mem_base + memory::x86::virtualBase;

    net_dev->is_e1000e = pci_dev->get_device() == i217_id || pci_dev->get_device() == lm_id;
    net_dev->has_eeprom = false;

    // TODO: ioctl to configure the gateway
    net_dev->ipv4_gateway = (char *) "192.168.100.1";
    net_dev->ipv4_addr = (char *) "192.168.100.2";

    acpi_resource_t irq_resource;
    auto err = lai_pci_route_pin(&irq_resource, 0, pci_dev->get_bus(), pci_dev->get_slot(), pci_dev->get_func(), pci_dev->read_pin());
    if (err > 0) {
        kmsg(logger, "Unable to initialize interrupts");
        frg::destruct(memory::mm::heap, net_dev);
        return;
    }

    size_t vector = arch::install_irq(e1000::irq_handler);
    arch::route_irq(irq_resource.base, vector);

    net_dev->init();
    kmsg(logger, "device initialized");

    net_dev->arp_probe();
}