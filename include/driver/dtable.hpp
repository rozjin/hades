#ifndef DTABLE_HPP
#define DTABLE_HPP

#include <cstddef>
#include <fs/dev.hpp>
#include <driver/matchers.hpp>

// match_data is bus-specific

namespace dtable {
    constexpr size_t MATCH_ANY = 0xFFFF;
    struct entry {
        int match_data[16];
        ssize_t major;
        vfs::devfs::matcher *matcher;
    };

    namespace majors {
        constexpr size_t AHCI = 9;
        constexpr size_t SELF_TTY = 15;
        constexpr size_t PTMX = 163;
        constexpr size_t AHCIBUS = 10;
        constexpr size_t NET = 11;
        constexpr size_t FB = 13;
        constexpr size_t KB = 14;
        constexpr size_t PTM = 161;
        constexpr size_t PTS = 162;
        constexpr size_t VT = 164;
    }

    static entry entries[] = {
        { .match_data = {MATCH_ANY, MATCH_ANY, 0x1, 0x6, 0x1}, .major = majors::AHCIBUS, .matcher = new pci::ahci::matcher()},
        { .match_data = {0x8086, 0x100e, MATCH_ANY, MATCH_ANY, MATCH_ANY}, .major = majors::NET, .matcher = new pci::net::matcher()},
        { .match_data = {0}, .major=majors::FB, .matcher = new fb::matcher()},
        { .match_data = {0}, .major=majors::KB, .matcher = new kb::matcher()},
        { .match_data = {0}, .major=majors::PTM, .matcher = new tty::ptm::matcher()},
        { .match_data = {0}, .major=majors::PTS, .matcher = new tty::pts::matcher()},
        { .match_data = {0}, .major=majors::VT, .matcher = new vt::matcher()}
    };

    vfs::devfs::matcher *lookup_by_data(int *match_data, size_t len);
    vfs::devfs::matcher *lookup_by_major(ssize_t major);
}

#endif
