#include "arch/types.hpp"
#include <driver/video/vesa.hpp>
#include <util/log/qemu.hpp>
#include <util/log/serial.hpp>
#include <util/log/log.hpp>
#include <cstdarg>
#include <cstddef>
#include <cstdint>

static constexpr auto num_buf_len = 48;
char num_buf[num_buf_len];

constexpr size_t KMSG_MAX = (1 << 16);
char kmsg_buf[KMSG_MAX];

size_t cur_pointer = 0;
void write_log(char c) {
    kmsg_buf[cur_pointer++] = c;
    if (cur_pointer >= KMSG_MAX) {
        cur_pointer = 0;
    }

    ports::qemu::write_log(c);
    ports::serial::write_log(c);
    video::vesa::write_log(c);
}

void write_log(const char *str) {
    while(*str) {
        write_log(*str++);
    }
}

const char *level_string(log::level level) {
    switch (level) {
        case log::level::TRACE:
            return "TRACE";
        case log::level::DEBUG:
            return "DEBUG";
        case log::level::INFO:
            return "INFO";
        case log::level::WARN:
            return "WARN";
        case log::level::ERR:
            return "ERR";
    }

    return "UNKNOWN";
}

constexpr size_t MAX_SUBSYSTEMS = 64;
size_t cur_subsystem = 0;
log::subsystem subsystem_list[MAX_SUBSYSTEMS];

log::subsystem log::make_subsystem(const char *prefix) {
    for (size_t i = 0; i < MAX_SUBSYSTEMS; i++) {
        if (strcmp(subsystem_list[i].prefix, prefix) == 0) {
            return subsystem_list[i];
        }
    }

    subsystem_list[cur_subsystem].id = cur_subsystem;
    subsystem_list[cur_subsystem].prefix = prefix;

    return subsystem_list[cur_subsystem];
}

void write_subsystem(log::subsystem subsystem, log::level level) {
    write_log('[');
    write_log(level_string(level));
    write_log(':');
    
    write_log(subsystem.prefix);
    write_log(']');
    write_log(' ');
}

util::lock log_lock{};

void write_msg(const char *fmt, va_list args) {
    while (*fmt) {
        if (*fmt == '%') {
            fmt++;
            if (*fmt == '%') {
                write_log('%');
            } else if (*fmt == 'c') {
                int c = va_arg(args, int);
                write_log(c);
            } else if (*fmt == 's') {
                char *str = va_arg(args, char *);
                while (*str) {
                    write_log(*str++);
                }
            } else if (*fmt == 'd' || *fmt == 'i') {
                uint32_t val = va_arg(args, uint32_t);
                auto decimal = util::num_fmt(num_buf, num_buf_len, val, 10, 0, ' ', ((int32_t) val > 0) ? 0 : 1, 0, -1);
                while (*decimal) {
                    write_log(*decimal++);
                }
            } else if (*fmt == 'u') {
                uint32_t val = va_arg(args, uint32_t);
                auto decimal = util::num_fmt(num_buf, num_buf_len, val, 10, 0, ' ', 0, 0, -1);
                while (*decimal) {
                    write_log(*decimal++);
                }
            } else if (*fmt++ == 'l') {
                if (*fmt == 'x') {
                    uint64_t val = va_arg(args, uint64_t);
                    auto pointer = util::num_fmt(num_buf, num_buf_len, val, 16, 0, ' ', 0, 0, 16);
                    while (*pointer) {
                        write_log(*pointer++);
                    }
                } else if (*fmt == 'u') {
                    uint64_t val = va_arg(args, uint64_t);
                    auto decimal = util::num_fmt(num_buf, num_buf_len, val, 10, 0, ' ', 0, 0, -1);
                    while (*decimal) {
                        write_log(*decimal++);
                    }
                } else if (*fmt == 'd') {
                    uint64_t val = va_arg(args, uint64_t);
                    auto decimal = util::num_fmt(num_buf, num_buf_len, val, 10, 0, ' ', ((int64_t) val > 0) ? 0 : 1, 0, -1);
                    while (*decimal) {
                        write_log(*decimal++);
                    }                    
                }
            } else if (*fmt++ == 'x') {
                uint32_t val = va_arg(args, uint32_t);
                auto pointer = util::num_fmt(num_buf, num_buf_len, val, 16, 0, ' ', 0, 0, 16);
                while (*pointer) {
                    write_log(*pointer++);
                }
            } else if (*fmt++ == 'X') {
                uint64_t val = va_arg(args, uint64_t);
                auto pointer = util::num_fmt(num_buf, num_buf_len, val, 16, 0, ' ', 0, 1, 16);
                while (*pointer) {
                    write_log(*pointer++);
                }
            }
        } else {
            write_log(*fmt);
        }

        fmt++;
    }
}

void kmsg(log::subsystem subsystem, log::level level, const char *fmt, ...) {
    log_lock.irq_acquire();

    write_subsystem(subsystem, level);

    va_list args;
    va_start(args, fmt);

    write_msg(fmt, args);

    write_log('\n');
    va_end(args);

    log_lock.irq_release();
}

void kmsg(log::subsystem subsystem, const char *fmt, ...) {
    log_lock.irq_acquire();

    write_subsystem(subsystem, log::level::INFO);

    va_list args;
    va_start(args, fmt);

    write_msg(fmt, args);

    write_log('\n');
    va_end(args);

    log_lock.irq_release();
}

static log::subsystem debug_logger = log::make_subsystem("DEBUG");
void debug(const char *fmt, ...) {
    log_lock.irq_acquire();

    write_subsystem(debug_logger, log::level::INFO);

    va_list args;
    va_start(args, fmt);

    write_msg(fmt, args);

    write_log('\n');
    va_end(args);

    log_lock.irq_release();
}

void panic(const char *fmt, ...) {
    arch::irq_off();
    arch::stop_all_cpus();

    log_lock.irq_acquire();

    write_log("[PANIC]");

    va_list args;
    va_start(args, fmt);

    write_msg(fmt, args);

    write_log('\n');
    va_end(args);

    log_lock.irq_release();

    arch::stall_cpu();    
}