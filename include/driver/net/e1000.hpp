#ifndef E1000_HPP
#define E1000_HPP

#include "fs/dev.hpp"
#include "mm/common.hpp"
#include "util/types.hpp"
#include <driver/net/device.hpp>
#include <driver/net/types.hpp>
#include <frg/functional.hpp>
#include <frg/hash_map.hpp>
#include <mm/mm.hpp>
#include <driver/bus/pci.hpp>
#include <cstddef>
#include <cstdint>
#include <arch/x86/types.hpp>

namespace e1000 {
    constexpr size_t tx_max = 8;
    constexpr size_t rx_max = 32;

    constexpr size_t reg_ctrl        = 0x0;
    constexpr size_t reg_status      = 0x8;
    constexpr size_t reg_eeprom_ctl  = 0x10;
    constexpr size_t reg_eeprom_read = 0x14;
    constexpr size_t reg_flash       = 0x1C;
    constexpr size_t reg_icr         = 0xC0;
    constexpr size_t reg_itr         = 0xC4;
    constexpr size_t reg_ims         = 0xD0;
    constexpr size_t reg_imc         = 0xD8;

    constexpr size_t reg_fcal  = 0x28;
    constexpr size_t reg_fcah  = 0x2C;
    constexpr size_t reg_fct   = 0x30;
    constexpr size_t reg_fcttv = 0x170;

    constexpr size_t reg_rctl         = 0x100;
    constexpr size_t reg_rx_desc_lo   = 0x2800;
    constexpr size_t reg_rx_desc_hi   = 0x2804;
    constexpr size_t reg_rx_desc_len  = 0x2808;
    constexpr size_t reg_rx_desc_head = 0x2810;
    constexpr size_t reg_rx_desc_tail = 0x2818;

    constexpr size_t reg_rx_delay_tmr = 0x2820;
    constexpr size_t reg_rx_desc_ctrl = 0x2828;
    constexpr size_t reg_rx_desc_adv  = 0x282C;
    constexpr size_t reg_rx_spd       = 0x2C00;

    constexpr uint32_t bit_rx_delay_tmr_fpd = (1 << 31);

    constexpr size_t bit_ims_txdw  = (1 << 0);
    constexpr size_t bit_ims_txqe  = (1 << 1);
    constexpr size_t bit_ims_lsc   = (1 << 2);
    constexpr size_t bit_ims_rxdmt = (1 << 4);
    constexpr size_t bit_ims_rxo   = (1 << 6);
    constexpr size_t bit_ims_rxt0  = (1 << 7);
    constexpr size_t bit_ims_mdac  = (1 << 9);
    constexpr size_t bit_ims_gpi   = (2 << 13);

    constexpr size_t bit_ctrl_slu = (1 << 6);
    constexpr size_t bit_ctrl_asde = (1 << 5);
    constexpr size_t bit_ctrl_rst = (1 << 26);

    constexpr size_t bit_rctl_en         = (1 << 1);
    constexpr size_t bit_rctl_sbp        = (1 << 2);
    constexpr size_t bit_rctl_upe        = (1 << 3);
    constexpr size_t bit_rctl_mpe        = (1 << 4);
    constexpr size_t bit_rctl_lpe        = (1 << 5);
    constexpr size_t bit_rctl_loop       = (0 << 6);
    constexpr size_t bit_rctl_phy        = (3 << 6);
    constexpr size_t bit_rctl_rdmts_half = (0 << 8);
    constexpr size_t bit_rctl_rdmts_quar = (2 << 8);
    constexpr size_t bit_rctl_rdmts_eith = (2 << 8);

    constexpr size_t bit_rctl_mo_36 = (0 << 12);
    constexpr size_t bit_rctl_mo_35 = (1 << 12);
    constexpr size_t bit_rctl_mo_34 = (2 << 12);
    constexpr size_t bit_rctl_mo_32 = (3 << 12);

    constexpr size_t bit_rctl_bam   = (1 << 15);
    constexpr size_t bit_rctl_vfe   = (1 << 18);
    constexpr size_t bit_rctl_cfien = (1 << 19);
    constexpr size_t bit_rctl_cfi   = (1 << 20);
    constexpr size_t bit_rctl_dpf   = (1 << 22);
    constexpr size_t bit_rctl_pmcf  = (1 << 23);
    constexpr size_t bit_rctl_secrc = (1 << 26);

    constexpr size_t bit_rctl_bsize_256  = (3 << 16);
    constexpr size_t bit_rctl_bsize_512  = (2 << 16);
    constexpr size_t bit_rctl_bsize_1k   = (1 << 16);
    constexpr size_t bit_rctl_bsize_2k   = (0 << 16);
    constexpr size_t bit_rctl_bsize_4k   = ((3 << 16) | (1 << 25));
    constexpr size_t bit_rctl_bsize_8k   = ((2 << 16) | (1 << 25));
    constexpr size_t bit_rctl_bsize_16k  = ((1 << 16) | (1 << 25));

    constexpr size_t reg_tctl         = 0x400;
    constexpr size_t reg_tx_ipg       = 0x410;
    constexpr size_t reg_tx_desc_lo   = 0x3800;
    constexpr size_t reg_tx_desc_hi   = 0x3804;
    constexpr size_t reg_tx_desc_len  = 0x3808;
    constexpr size_t reg_tx_desc_head = 0x3810;
    constexpr size_t reg_tx_desc_tail = 0x3818;

    constexpr size_t bit_tctl_en       = (1 << 1);
    constexpr size_t bit_tctl_psp      = (1 << 3);
    constexpr size_t bit_tctl_ct_shift = 4;
    constexpr size_t bit_tctl_cl_shift = 12;
    constexpr size_t bit_tctl_swxoff   = (1 << 22);
    constexpr size_t bit_tctl_rtlc     = (1 << 24);

    // checksum is unadjusted 16 bit ones complement
    struct [[gnu::packed]] rx_desc {
        static constexpr size_t rx_bit_done = (1 << 0);
        uint64_t address;
        uint16_t length;
        uint16_t checksum;
        uint8_t status;
        uint8_t error;

        uint16_t special;
    };

    struct [[gnu::packed]] tx_desc {
        static constexpr size_t tx_bit_done = (1 << 0);

        static constexpr size_t tx_bit_eop = (1 << 0);
        static constexpr size_t tx_bit_fcs = (1 << 1);
        static constexpr size_t tx_bit_rs  = (1 << 3);

        uint64_t address;

        uint16_t length;
        uint8_t check_offset;
        uint8_t cmd;
        uint8_t status;

        uint8_t check_start;
        uint16_t special;
    };

    void irq_handler(arch::irq_regs *r, void *aux);

    struct device: vfs::devfs::device, net::device {
        private:
            pci::device *pci_dev;

            vfs::devfs::bus_space *flash_space;
            vfs::devfs::bus_space *reg_space;

            size_t irq_vector;
    
            bus_handle_t flash_handle;
            bus_handle_t reg_handle;

            bool is_e1000e;
            bool has_eeprom;

            frg::vector<shared_ptr<vfs::devfs::bus_dma>, memory::mm::heap_allocator> rx_desc_dma;
            shared_ptr<vfs::devfs::bus_dma> rx_dma;
            shared_ptr<vfs::devfs::bus_dma> tx_dma;

            rx_desc *rx_descs[rx_max];
            tx_desc *tx_descs[tx_max];

            uint16_t rx_cur;
            uint16_t tx_cur;

            void write(uint16_t off, uint32_t value);
            uint32_t read(uint16_t off);

            bool read_mac();
            bool check_eeprom();
            uint32_t read_eeprom(uint8_t off);

            void reset();
            void rx_init();
            void tx_init();
            void enable_irq();

            void rx_handle();
        public:
            friend void irq_handler(arch::irq_regs *r, void *aux);

            bool setup();
            
            void init_routing() override;
            void add_route(const char *ipv4_dest, 
                const char *ipv4_gateway, const char *ipv4_netmask,
                uint16_t mtu = 576,
                uint32_t dest_mask = 0xFFFFFFFF) override;
            uint32_t route(uint32_t dest) override;
            void send(const void *buf, size_t len) override;

            size_t get_vector();

            device(vfs::devfs::busdev *bus, ssize_t major, ssize_t minor, void *aux):
                vfs::devfs::device(bus, major, minor, aux, vfs::devfs::device_class::OTHER), net::device(),
                rx_desc_dma(),

                rx_dma(bus->get_dma(sizeof(rx_desc) * rx_max)),
                tx_dma(bus->get_dma(sizeof(tx_desc) * tx_max))
            {
                net::setup_args *args = (net::setup_args *) aux;

                is_e1000e = args->flags;
                has_eeprom = false;

                irq_vector = args->irq;

                flash_space = args->flash_space;
                reg_space = args->reg_space;

                reg_handle = reg_space->map(0, 128 * memory::page_size);
                if (flash_space) flash_handle = flash_space->map(0, 512 * memory::page_size);
            }
    };
}

#endif