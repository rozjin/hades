#ifndef DTABLE_HPP
#define DTABLE_HPP

#include <cstddef>
#include <fs/dev.hpp>
#include <driver/matchers.hpp>
#include <driver/majtable.hpp>

// match_data is bus-specific

namespace dtable {
    constexpr size_t MATCH_ANY = 0xFFFF;
    struct entry {
        int match_data[16];
        ssize_t major;
        vfs::devfs::matcher *matcher;
    };

    static entry entries[] = {
        { .match_data = {MATCH_ANY, MATCH_ANY, 0x1, 0x6, 0x1}, .major = majors::AHCIBUS, .matcher = new pci::ahcibus::matcher()},
        { .match_data = {0}, .major=majors::AHCI, .matcher = new ahci::matcher()},
        { .match_data = {0x8086, 0x100e, MATCH_ANY, MATCH_ANY, MATCH_ANY}, .major = majors::NET, .matcher = new pci::net::matcher()},
        { .match_data = {0}, .major=majors::FB, .matcher = new fb::matcher()},
        { .match_data = {0}, .major=majors::KB, .matcher = new kb::matcher()},
        { .match_data = {0}, .major=majors::PTM, .matcher = new tty::ptm::matcher()},
        { .match_data = {0}, .major=majors::PTS, .matcher = new tty::pts::matcher()},
        { .match_data = {0}, .major=majors::PTMX, .matcher = new tty::ptmx::matcher()},
        { .match_data = {0}, .major=majors::SELF_TTY, .matcher = new tty::self::matcher()},
        { .match_data = {0}, .major=majors::VT, .matcher = new vt::matcher()}
    };

    vfs::devfs::matcher *lookup_by_data(int *match_data, size_t len);
    vfs::devfs::matcher *lookup_by_major(ssize_t major);
}

#endif