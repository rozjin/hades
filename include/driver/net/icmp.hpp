#ifndef ICMP_HPP
#define ICMP_HPP

#include "driver/net/types.hpp"
#include "frg/string.hpp"
#include <cstddef>
#include <cstdint>

namespace net {
    namespace pkt {
        struct [[gnu::packed]] icmp {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
            uint32_t rem;
        };
    }
}

#endif