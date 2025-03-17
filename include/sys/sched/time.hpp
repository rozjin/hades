#ifndef TIME_HPP
#define TIME_HPP

#include <frg/vector.hpp>
#include <mm/mm.hpp>
#include <cstddef>
#include <util/types.hpp>

namespace ipc {
    struct wire;
}

namespace sched {    
    class thread;

    constexpr long NANOS_PER_MILLI = 1000000000;

    constexpr size_t CLOCK_REALTIME = 0;
    constexpr size_t CLOCK_MONOTONIC = 1;

    struct timespec {
        public:
            time_t tv_sec;
            long tv_nsec;

            timespec operator+(timespec const& other) {
                timespec res = {
                    .tv_sec = this->tv_sec + other.tv_sec,
                    .tv_nsec = this->tv_nsec + other.tv_nsec
                };

                if (res.tv_nsec > NANOS_PER_MILLI) {
                    res.tv_nsec -= NANOS_PER_MILLI;
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
                    res.tv_nsec += NANOS_PER_MILLI;
                    res.tv_sec--;
                }

                if (res.tv_sec < 0) {
                    res.tv_nsec = 0;
                    res.tv_sec = 0;
                }

                return res;                    
            }

            static timespec ms(int ms) {
                return {
                    .tv_sec = ms / 1000,
                    .tv_nsec = (ms % 1000) * 100000
                };
            }
    };

    struct timer {
        timespec spec;
        ipc::wire *wire;
    };

    extern timespec clock_rt;
    extern timespec clock_mono;

    extern frg::vector<sched::timer, memory::mm::heap_allocator> timers;
}

#endif