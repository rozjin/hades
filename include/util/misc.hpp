#ifndef MISC_HPP
#define MISC_HPP

#include <cstddef>
#include <cstdint>
#include <initializer_list>

namespace util {
    inline size_t ceil(size_t a, size_t b) {
        return (a + (b - 1)) / b;
    }

    inline size_t align(size_t a, size_t b) {
        return ceil(a, b) * b;
    }

    inline size_t max(size_t a, size_t b) {
        return (a < b) ? b : a;
    }

    inline size_t max(size_t a, void *b) {
        return max(a, (size_t) b);
    }

    inline size_t min(size_t a, size_t b) {
        return !(b < a) ? a : b;
    }

    inline size_t min(size_t a, void *b) {
        return min(a, (size_t) b);
    }

    inline size_t within(size_t x, size_t min, size_t max) {
        if (x >= min && x <= max) {
            return true;
        }

        return false;
    }

    inline size_t within(size_t x, void *min, void *max) {
        return within(x, (size_t) min, (size_t) max);
    }

    template <typename T>
    constexpr T min(std::initializer_list<T> list) {
        auto it = list.begin();
        T x = *it;
        ++it;
        while(it != list.end()) {
            if (*it < x)
                x = *it;
            ++it;
        }
        return x;
    }

    template <typename T>
    constexpr T max(std::initializer_list<T> list) {
        auto it = list.begin();
        T x = *it;
        ++it;
        while(it != list.end()) {
            if (*it > x)
                x = *it;
            ++it;
        }
        return x;
    }

    template<typename T>
    void *endof(T *ptr) {
        return (void *) (((size_t) ptr) + sizeof(T));
    }

    inline void bit_set(uint8_t *bitmap, uint64_t index) {
        bitmap[index / 8] |= (1 << (index % 8));
    }

    inline void bit_clear(uint8_t *bitmap, uint64_t index) {
        bitmap[index / 8] &= ~(1 << (index % 8));
    }

    inline bool bit_test(uint8_t *bitmap, uint64_t index) {
        return (bitmap[index / 8] >> (index % 8)) & 0x1;
    }
};

#endif