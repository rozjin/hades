#ifndef PART_HPP
#define PART_HPP

#include <cstddef>
#include <cstdint>
#include <fs/vfs.hpp>
#include <fs/dev.hpp>

namespace part {
    constexpr uint64_t EFI_MAGIC = 0x5452415020494645;

    namespace gpt {
        struct [[gnu::packed]] part {
            char uuid[16];
            char guid[16];
            
            uint64_t lba_start;
            uint64_t lba_end;
            uint64_t attr;

            const char name[72];
        };

        struct [[gnu::packed]] header {
            uint64_t sig;

            uint32_t rev;
            uint32_t len;
            uint32_t checksum;
            uint32_t _;

            uint64_t self_lba;
            uint64_t alt_lba;
            uint64_t usable_start;
            uint64_t usable_end;

            char guid[16];
            uint64_t part_start;
            uint32_t part_len;
            uint32_t part_size;
            uint32_t part_checksum;
        };
    };

    namespace mbr {
        struct [[gnu::packed]] header {
            char bootstrap[440];
            char sig[4];
            char _[2];
            char parts[64];
            uint16_t magic;
        };

        struct [[gnu::packed]] part {
            uint8_t attr;
            uint8_t resv[3];
            uint8_t type;
            uint8_t resv1[3];

            uint32_t lba_start;
            uint32_t len;
        };
    }

    size_t probe(vfs::devfs::device *dev);
}

#endif