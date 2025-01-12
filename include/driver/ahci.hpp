#ifndef AHCI_HPP
#define AHCI_HPP

#include <mm/mm.hpp>
#include <cstddef>
#include <cstdint>
#include <frg/vector.hpp>
#include <fs/dev.hpp>
#include <sys/pci.hpp>
#include <sys/sched/wait.hpp>
#include <util/lock.hpp>

namespace ahci {
    constexpr size_t SIG_ATA   = 0x00000101;
    constexpr size_t SIG_ATAPI = 0xEB140101;
    constexpr size_t SEG_SEMB  = 0xC33C0101;
    constexpr size_t SIG_PM    = 0x96690101;
    constexpr size_t SIG_NULL  = 0x0;

    constexpr size_t DEV_ATA   = 1;
    constexpr size_t DEV_ATAPI = 2;
    constexpr size_t DEV_SEMB  = 3;
    constexpr size_t DEV_PM    = 4;
    constexpr size_t DEV_NULL  = 0;

    constexpr size_t FIS_REG_H2D = 0x27;
    constexpr size_t FIS_REG_D2H = 0x34;
    constexpr size_t FIS_DMA_ACT = 0x39;
    constexpr size_t FIS_DMA_STP = 0x41;
    constexpr size_t FIS_DATA    = 0x46;
    constexpr size_t FIS_BIST    = 0x58;
    constexpr size_t FIS_PIO_STP = 0x5F;
    constexpr size_t FIS_DEV_BTS = 0xA1;

    constexpr size_t AHCI_CLASS    = 0x01;
    constexpr size_t AHCI_SUBCLASS = 0x06;
    constexpr size_t AHCI_PROG_IF  = 0x01;

    constexpr size_t ATA_DEVICE_BUSY           = 0x80;
    constexpr size_t ATA_DEVICE_DRQ            = 0x08;
    constexpr size_t ATA_COMMAND_IDENTIFY      = 0xEC;
    constexpr size_t ATA_COMMAND_DMA_READ      = 0xC8;
    constexpr size_t ATA_COMMAND_DMA_EXT_READ  = 0x25;
    constexpr size_t ATA_COMMAND_DMA_WRITE     = 0xCA;
    constexpr size_t ATA_COMMAND_DMA_EXT_WRITE = 0x35;

    constexpr size_t HBA_PxCMD_ST  = 0x0001;
    constexpr size_t HBA_PxCMD_SSS = 0x0002;
    constexpr size_t HBA_PxCMD_FRE = 0x0010;
    constexpr size_t HBA_PxCMD_FR  = 0x4000;
    constexpr size_t HBA_PxCMD_CR  = 0x8000;

    constexpr size_t ATAPI_COMMAND_IDENTIFY = 0xA1;

    constexpr size_t MAX_SLOTS = 32;

    namespace fis {
        struct [[gnu::packed]] reg_h2d {
            uint8_t fis_type;

            uint8_t pmport       : 4;
            uint8_t rsv          : 3;
            uint8_t cmd_ctl      : 1;

            uint8_t command;
            uint8_t feature;

            uint8_t lba0;
            uint8_t lba1;
            uint8_t lba2;
            uint8_t dev;
            
            uint8_t lba3;
            uint8_t lba4;
            uint8_t lba5;
            uint8_t feature_hi;

            uint8_t countl;
            uint8_t counth;

            uint8_t icc;
            uint8_t control;

            uint8_t reserved[4];
        };

        struct [[gnu::packed]] reg_d2h {
            uint8_t fis_type;

            uint8_t pmport     : 4;
            uint8_t reserved   : 2;
            uint8_t interrupt  : 1;
            uint8_t reserved1  : 1;

            uint8_t status;
            uint8_t err;

            uint8_t lba0;
            uint8_t lba1;
            uint8_t lba2;
            uint8_t device;

            uint8_t lba3;
            uint8_t lba4;
            uint8_t lba5;
            uint8_t reserved2;

            uint8_t countl;
            uint8_t counth;

            uint8_t reserved3[2];
            uint8_t reserved4[4];
        };

        struct [[gnu::packed]] data {
            uint8_t fis_type;

            uint8_t pmport   : 4;
            uint8_t reserved : 4;

            uint8_t reserved1[2];

            uint32_t data[1];
        };

        struct [[gnu::packed]] pio_setup {
            uint8_t fis_type;

            uint8_t pmport    : 4;
            uint8_t reserved  : 1;
            uint8_t direction : 1;
            uint8_t interrupt : 1;
            uint8_t reserved1 : 1;

            uint8_t status;
            uint8_t err;

            uint8_t lba0;
            uint8_t lba1;
            uint8_t lba2;
            uint8_t device;

            uint8_t lba3;
            uint8_t lba4;
            uint8_t lba5;
            uint8_t reserved2;

            uint8_t countl;
            uint8_t counth;

            uint8_t reserved3;
            uint8_t new_status;

            uint16_t transfer_count;
            uint8_t reserved4[2];
        };

        struct [[gnu::packed]] dma_setup {
            uint8_t fis_type;

            uint8_t pmport    : 4;
            uint8_t reserved  : 1;
            uint8_t direction : 1;
            uint8_t interrupt : 1;
            uint8_t available : 1;

            uint8_t reserved1[2];

            uint64_t dma_buf_id;

            uint32_t reserved2;

            uint32_t dma_buf_offset;
            uint32_t transfer_count;
            
            uint32_t reserved3;
        };

        struct [[gnu::packed]] hba {
            dma_setup dsfis;
            uint8_t p0[4];

            pio_setup psfis;
            uint8_t p1[12];

            reg_d2h rfis;
            uint8_t p2[4];

            uint8_t sdbfis[8];

            uint8_t ufis[64];
            uint8_t resv[96];
        };
    };

    struct [[gnu::packed]] port {
        uint32_t commands_addr;
        uint32_t commands_addr_upper;
        uint32_t fis_addr;
        uint32_t fis_upper;

        uint32_t ist;
        uint32_t ine;
        uint32_t cas;

        uint32_t reserved;

        uint32_t tfd;
        uint32_t sig;
        
        uint32_t sata_status;
        uint32_t sata_ctl;
        uint32_t sata_err;
        uint32_t sata_active;

        uint32_t cmd_issue;
        uint32_t sata_notify;
        uint32_t fbs;

        uint32_t reserved1[11];
        uint32_t vs[4];
    };

    struct [[gnu::packed]] abar {
        uint32_t cap;
        uint32_t ghc;
        uint32_t isr;
        uint32_t port_implemented;
        uint32_t version;
        uint32_t ccc_ctl;
        uint32_t ccc_ports;
        uint32_t em_loc;
        uint32_t em_ctl;
        uint32_t cap2;
        uint32_t bohc;

        uint8_t reserved[116];
        uint8_t vsr[96];

        port ports[];
    };

    struct [[gnu::packed]] prdt_entry {
        uint32_t base;
        uint32_t base_hi;
        uint32_t reserved;

        uint32_t bytes     : 22;
        uint32_t reserved1 : 9;
        uint32_t interrupt : 1;
    };


    struct [[gnu::packed]] command_header {
        uint32_t cmd_fis_len  : 5;
        uint32_t atapi        : 1;
        uint32_t write        : 1;
        uint32_t prefetchable : 1;
        uint32_t reset_ctl    : 1;
        uint32_t bist         : 1;
        uint32_t clear        : 1;
        uint32_t resv0        : 1;
        uint32_t pmp          : 4;
        uint32_t prdt_cnt     : 16;

        uint32_t prdtbc;

        uint32_t command_entry;
        uint32_t command_entry_hi;
        uint8_t resv1[16];
    };

    struct [[gnu::packed]] command_entry {
        uint8_t cfis[64];
        uint8_t acmd[16];
        uint8_t reserved[48];
        prdt_entry prdts[];
    };

    struct command_slot {
        int idx;
        command_entry *entry;
    };

    constexpr size_t major = 0xA;
    constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

    constexpr size_t get_fis_size(size_t n_fis) {
        return sizeof(command_entry) + sizeof(prdt_entry) * n_fis;
    }

    constexpr size_t get_prdt_bytes(size_t count) {
        return (((count + 1) & ~1) - 1) & 0x3FFFFF;
    }

    struct device;
    void init();
    ssize_t find_cmdslot(ahci::device *device);

    struct device : vfs::devfs::device {
        private:
            util::lock lock;

            size_t sectors;
            size_t sector_size;
            bool exists;
            volatile abar *bar;
            int64_t id;
            bool lba48;
            volatile ahci::port *port;

            ssize_t find_cmdslot();
            command_slot issue_read_write(void *buf, uint16_t count, size_t offset, bool rw);
            ssize_t do_sector_io(void *buf, uint16_t count, size_t offset, bool rw);
        public:
            friend void ahci::init();
            friend ssize_t find_cmdslot(ahci::device *device);
            
            device() {};

            void setup();
            void identify_sata();
            ssize_t read(void *buf, size_t count, size_t offset) override;
            ssize_t write(void *buf, size_t count, size_t offset) override; 
    };
};

#endif