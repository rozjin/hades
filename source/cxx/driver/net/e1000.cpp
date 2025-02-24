#include "arch/types.hpp"
#include "driver/net/ip.hpp"
#include "driver/net/types.hpp"
#include <driver/net/protos.hpp>
#include "fs/dev.hpp"
#include "lai/helpers/pci.h"
#include "mm/pmm.hpp"
#include "util/log/log.hpp"
#include "util/misc.hpp"
#include "util/types.hpp"
#include <cstdint>
#include <mm/common.hpp>
#include <mm/mm.hpp>
#include <cstddef>
#include <util/io.hpp>
#include <driver/net/e1000.hpp>

static log::subsystem logger = log::make_subsystem("E1000");

void e1000::device::write(uint16_t off, uint32_t value) {
    reg_space->writed(reg_handle, off, value);
}

uint32_t e1000::device::read(uint16_t off) {
    return reg_space->readb(reg_handle, off);
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
        uintptr_t mem_base = (uintptr_t) reg_space->vaddr(reg_handle);
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
    uint8_t *rx_base = (uint8_t *) rx_dma->vaddr();

    rx_desc *descs = (rx_desc *) rx_base;
    for (size_t i = 0; i < rx_max; i++) {
        rx_descs[i] = (rx_desc *) ((uint8_t *) descs + (i * sizeof(rx_desc)));

        auto desc_dma = bus->get_dma(memory::page_size * 2);
        rx_descs[i]->address = desc_dma->paddr();
        rx_desc_dma.push_back(std::move(desc_dma));

        rx_descs[i]->status = 0;
    }

    write(reg_rx_desc_lo, (uint32_t) (rx_dma->paddr() & 0xFFFFFFFF));
    write(reg_rx_desc_hi, (uint32_t) (rx_dma->paddr() >> 32));
    write(reg_rx_desc_len, rx_max * sizeof(rx_desc));

    write(reg_rx_desc_head, 0);
    write(reg_rx_desc_tail, rx_max - 1);

    rx_cur = 0;
    write(reg_rctl, bit_rctl_en | bit_rctl_sbp | bit_rctl_upe | bit_rctl_mpe
                       | bit_rctl_loop | bit_rctl_rdmts_half | bit_rctl_bam | bit_rctl_secrc | bit_rctl_bsize_8k);
}

void e1000::device::tx_init() {
    uint8_t *tx_base = (uint8_t *) tx_dma->vaddr();

    tx_desc *descs = (tx_desc *) tx_base;
    for (size_t i = 0; i < tx_max; i++) {
        tx_descs[i] = (tx_desc *) ((uint8_t *) descs + (i * sizeof(tx_desc)));

        tx_descs[i]->address = 0;
        tx_descs[i]->cmd = 0;
        tx_descs[i]->status = tx_desc::tx_bit_done;
    }

    write(reg_tx_desc_lo, (uint32_t) (tx_dma->paddr() & 0xFFFFFFFF));
    write(reg_tx_desc_hi, (uint32_t) (tx_dma->paddr() >> 32));
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
        bus_addr_t rx_base = rx_desc_dma[rx_cur]->vaddr();

        uint8_t *buf = (uint8_t *) rx_base;
        uint16_t len = rx_descs[rx_cur]->length;

        net::eth *eth_hdr = (net::eth *) buf;

        size_t pkt_len = len - sizeof(net::eth);
        void *pkt_data = ((char *) eth_hdr) + sizeof(net::eth);

        switch(net::ntohs(eth_hdr->type)) {
            case 0x0806:
                net::arp::arp_handle(this, pkt_data);
                break;
            case 0x0800:
                net::ipv4::ipv4_handle(this, pkt_data, pkt_len);
                break;
            default:
                break;
        }

        // TODO: handle protocols here

        rx_descs[rx_cur]->status = 0;
        old_rx_cur = rx_cur;
        rx_cur = (rx_cur + 1) % rx_max;
        write(reg_rx_desc_tail, old_rx_cur);
    }
}

bool e1000::device::setup() {
    this->ipv4_gateway_addr = (char *) "192.168.100.1";
    this->ipv4_host_addr = (char *) "192.168.100.2";
    this->ipv4_netmask_addr = (char *) "255.255.255.0";

    this->ipv4_host = net::ipv4_pton(this->ipv4_host_addr);
    this->ipv4_gateway = net::ipv4_pton(this->ipv4_gateway_addr);
    this->ipv4_netmask = net::ipv4_pton(this->ipv4_netmask_addr);

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
    net::arp::arp_probe(this, this->ipv4_gateway);

    return true;
}

void e1000::device::init_routing() {
    add_route(net::broadcast_ipv4, ipv4_gateway_addr, net::broadcast_ipv4);
    add_route(ipv4_gateway_addr, net::broadcast_ipv4, "255.255.255.0", ~(0xFF));
}

void e1000::device::add_route(const char *ipv4_dest,
    const char *ipv4_gateway, const char *ipv4_netmask,
    uint16_t mtu,
    uint32_t dest_mask)  {
    uint32_t dest = net::ipv4_pton(ipv4_dest) & dest_mask;
    uint32_t gateway = net::ipv4_pton(ipv4_gateway);
    uint32_t netmask = net::ipv4_pton(ipv4_netmask);

    ipv4_routing_table.push(net::route(dest, gateway, netmask, mtu));
}

uint32_t e1000::device::route(uint32_t dest) {
    uint32_t gateway = 0;
    uint32_t current_mask = 0;

    // search for the longest prefix
    for (auto route: ipv4_routing_table) {
        if ((route.dest & route.netmask) == (dest & route.netmask)) {
            if (route.netmask > current_mask) {
                gateway = route.gateway;
                current_mask = route.netmask;
            }
        }
    }

    return gateway;
}

void e1000::device::send(const void *buf, size_t len) {
    auto tx_dma = bus->get_dma(len);
    memcpy((void *) tx_dma->vaddr(), buf, len);

    tx_descs[tx_cur]->address = tx_dma->paddr();
    tx_descs[tx_cur]->length = len;

    tx_descs[tx_cur]->cmd = tx_desc::tx_bit_eop | tx_desc::tx_bit_fcs | tx_desc::tx_bit_rs;
    tx_descs[tx_cur]->status = 0;

    uint8_t old_tx_cur = tx_cur;
    tx_cur = (tx_cur + 1) % tx_max;
    write(reg_tx_desc_tail, tx_cur);

    while ((tx_descs[old_tx_cur]->status & tx_desc::tx_bit_done) == 0) { asm volatile("pause"); }
}

void e1000::irq_handler(arch::irq_regs *r, void *aux) {
    auto dev = (e1000::device *) aux;
    uint32_t status = dev->read(reg_icr);
    if (status & 0x04) {
        // TODO: read link speed
    } else if (status & 0x10) {
        // TODO: allocate more rx buffers
    } else if (status & 0x80) {
        dev->rx_handle();
    }
}