#ifndef IP_HPP
#define IP_HPP

#include "driver/net/types.hpp"
#include "frg/string.hpp"
#include <cstddef>
#include <cstdint>
namespace net {
    constexpr size_t ipv4_alen = 4;
    inline uint32_t ipv4_part_parse(const char *s) {
        uint32_t res = 0, idx = 0;

        while (s[idx] >= '0' && s[idx] <= '9') {
            res = 10 * res + (s[idx++] - '0');
        }

        return res;
    }

    inline uint32_t ipv4_pton(const char* ip_str) {
        uint32_t ipv4 = 0;

        frg::string_view view(ip_str);
        size_t dot_idx = 0;
        for (uint32_t i = 0; i < 4; i++) {
            uint32_t part = ipv4_part_parse(view.data());
            if (part > 255) {
                return uint32_t(-1);
            }

            ipv4 += part << (8 * (4 - (i + 1)));

            dot_idx = view.find_first('.');
            view = view.sub_string(dot_idx + 1);
        }

        return ipv4;
    }

    inline char *ipv4_ntop(uint32_t ipv4, char *ipv4_str) {
        uint8_t bytes[4];
        bytes[0] = ipv4 & 0xFF;
        bytes[1] = (ipv4 >> 8) & 0xFF;
        bytes[2] = (ipv4 >> 16) & 0xFF;
        bytes[3] = (ipv4 >> 24) & 0xFF;

        size_t offset = 0;
        uint8_t part_size = 0;
        for (size_t i = 0; i < 4; i++) {
            uint8_t part = bytes[3 - i];
            part_size = 1;
            if (part > 99) {
                part_size = 3;
            } else if (part > 9) {
                part_size = 2;
            }

            util::num_fmt(ipv4_str + offset, part_size + 1, bytes[3 - i], 10, 0, ' ', 0, 0, -1);
            ipv4_str[offset + part_size] = '.';
            offset += part_size + 1;
        }
        
        ipv4_str[offset + part_size] = '\0';
        return ipv4_str;
    }

    static const char *broadcast_ipv4 = "0.0.0.0";

    namespace pkt {
        struct [[gnu::packed]] ipv4 {
            uint8_t ihl : 4;
            uint8_t ver : 4;

            uint8_t diff_serv : 6;
            uint8_t ecn  : 2;

            uint16_t len;
            uint16_t id;

            uint16_t frag_off;

            uint8_t ttl;
            uint8_t proto;
            uint16_t checksum;
            
            uint32_t src_ip;
            uint32_t dest_ip;
        }; 
    }
}

#endif