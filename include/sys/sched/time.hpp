#ifndef TIME_HPP
#define TIME_HPP

#include <frg/vector.hpp>
#include <mm/mm.hpp>
#include <cstddef>
#include <cstdint>

namespace ipc {
    struct trigger;
};

namespace sched {    
    constexpr long TIMER_HZ = 1000000000;

    constexpr size_t CLOCK_REALTIME = 0;
    constexpr size_t CLOCK_MONOTONIC = 1;

    struct timespec {
        public:
            int64_t tv_sec;
            long tv_nsec;

            timespec operator+(timespec const& other) {
                timespec res = {
                    .tv_sec = this->tv_sec + other.tv_sec,
                    .tv_nsec = this->tv_nsec + other.tv_nsec
                };

                if (res.tv_nsec > TIMER_HZ) {
                    res.tv_nsec -= TIMER_HZ;
                    res.tv_sec++;
                }

                return res;
            };

            timespec operator-(timespec const &other) {
                timespec res = {
                    .tv_sec = this->tv_sec - other.tv_sec,
                    .tv_nsec = this->tv_nsec - other.tv_nsec
                };

                if (res.tv_nsec < 0) {
                    res.tv_nsec += TIMER_HZ;
                    res.tv_sec--;
                }

                if (res.tv_sec < 0) {
                    res.tv_nsec = 0;
                    res.tv_sec = 0;
                }

                return res;                    
            }

            timespec ms(int ms);
    };

    struct timer {
        timespec spec;
        frg::vector<ipc::trigger *, memory::mm::heap_allocator> triggers;
    };

    inline timespec clock_rt{};
    inline timespec clock_mono{};
}

#endif