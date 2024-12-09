#ifndef LOG_HPP
#define LOG_HPP

#include <util/lock.hpp>
#include <sys/x86/apic.hpp>
#include <util/io.hpp>

namespace util {
    static constexpr auto digits_upper = "0123456789ABCDEF";
    static constexpr auto digits_lower = "0123456789abcdef";
    inline char *num_fmt(char *buf, size_t buf_len, uint64_t i, int base, int padding, char pad_with, int handle_signed, int upper, int len) {
        int neg = (signed) i < 0 && handle_signed;

        if (neg)
            i = (unsigned) (-((signed) i));

        char *ptr = buf + buf_len - 1;
        *ptr = '\0';

        const char *digits = upper ? digits_upper : digits_lower;

        do {
            *--ptr = digits[i % base];
            if (padding)
                padding--;
            if (len > 0)
                len--;
            buf_len--;
        } while ((i /= base) != 0 && (len == -1 || len) && buf_len);

        while (padding && buf_len) {
            *--ptr = pad_with;
            padding--;
            buf_len--;
        }

        if (neg && buf_len)
            *--ptr = '-';

        return ptr;
    }    
}

struct log {
    enum class level {
        TRACE,
        DEBUG,
        INFO,
        WARN,
        ERR
    };


    struct subsystem {
        int id;
        const char *prefix;
    };

    static subsystem make_subsystem(const char *prefix);
};

void kmsg(log::subsystem subsystem, log::level level, const char *fmt, ...);
void kmsg(log::subsystem subsystem, const char *fmt, ...);

#endif