#include "arch/types.hpp"
#include "fs/cache.hpp"
#include "util/lock.hpp"
#include <driver/video/vesa.hpp>
#include <util/log/qemu.hpp>
#include <util/log/serial.hpp>
#include <util/log/log.hpp>
#include <cstdarg>
#include <cstddef>

#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 0
#define NANOPRINTF_IMPLEMENTATION
#include <util/log/nanoprintf.h>

static constexpr auto num_buf_len = 48;
char num_buf[num_buf_len];

constexpr size_t KMSG_MAX = (1 << 16);
char kmsg_buf[KMSG_MAX];

size_t cur_pointer = 0;
void write_log(int c, void *_) {
    kmsg_buf[cur_pointer++] = c;
    if (cur_pointer >= KMSG_MAX) {
        cur_pointer = 0;
    }

    ports::qemu::write_log(c);
    ports::serial::write_log(c);
    video::vesa::write_log(c);
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
    npf_pprintf(&write_log, nullptr, "[%s]: %s ", level_string(level), subsystem.prefix);
}

util::spinlock log_lock{};
void kmsg(log::subsystem subsystem, log::level level, const char *fmt, ...) {
    util::lock_guard guard{log_lock};

    write_subsystem(subsystem, level);

    va_list args;
    va_start(args, fmt);

    npf_vpprintf(&write_log, nullptr, fmt, args);
    write_log('\n', nullptr);

    va_end(args);
}

void kmsg(log::subsystem subsystem, const char *fmt, ...) {
    util::lock_guard guard{log_lock};

    write_subsystem(subsystem, log::level::INFO);

    va_list args;
    va_start(args, fmt);

    npf_vpprintf(&write_log, nullptr, fmt, args);
    write_log('\n', nullptr);

    va_end(args);
}

static log::subsystem debug_logger = log::make_subsystem("DEBUG");
void debug(const char *fmt, ...) {
    util::lock_guard guard{log_lock};

    write_subsystem(debug_logger, log::level::INFO);

    va_list args;
    va_start(args, fmt);

    npf_vpprintf(&write_log, nullptr, fmt, args);
    write_log('\n', nullptr);

    va_end(args);

}

void panic(const char *fmt, ...) {
    arch::irq_off();
    arch::stop_all_cpus();
    
    util::lock_guard guard{log_lock};

    cache::halt_sync();
    npf_pprintf(&write_log, nullptr, "[PANIC]: Not syncing");

    va_list args;
    va_start(args, fmt);

    npf_vpprintf(&write_log, nullptr, fmt, args);
    write_log('\n', nullptr);

    va_end(args);
    
    arch::stall_cpu();    
}