#include "driver/net/types.hpp"
#include <cstddef>
#include <cstdint>

void net::checksum::update(uint16_t word) {
    state += word;
    while (state >> 16 != 0) {
        state = (state >> 16) + (state & 0xFFFF);
    }
}

void net::checksum::update(const void *buf, size_t size) {
    auto begin = (uint8_t *) buf;
    if (size % 2 != 0) {
        size--;
        update(begin[size] << 8);
    }

    auto end = begin + size;
    for (; begin < end; begin += 2) {
        update(begin[0] << 8 | begin[1]);
    }
}

uint16_t net::checksum::finalize() {
    return ~this->state;
}