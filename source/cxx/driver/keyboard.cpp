#include "driver/keyboard.hpp"
#include "arch/types.hpp"
#include "arch/x86/types.hpp"
#include "driver/tty/tty.hpp"
#include "sys/sched/event.hpp"
#include "util/io.hpp"
#include "util/lock.hpp"
#include <cstddef>
#include <cstdint>

static bool is_shift;
static bool is_shift_locked;
static bool is_ctrl;
static bool extended_map;

static char keymap_plain[] = {
	'\0', '\0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	'-', '=', '\b', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',
	'o', 'p', '[', ']', '\n', '\0', 'a', 's', 'd', 'f', 'g', 'h',
	'j', 'k', 'l', ';', '\'', '`', '\0', '\\', 'z', 'x', 'c', 'v',
	'b', 'n', 'm', ',', '.',  '/', '\0', '\0', '\0', ' '
};

static char keymap_caps[] = {
	'\0', '\0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	'-','=', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
	'O', 'P', '[', ']', '\n', '\0', 'A', 'S', 'D', 'F', 'G', 'H',
	'J', 'K', 'L', ';', '\'', '`', '\0', '\\', 'Z', 'X', 'C', 'V',
	'B', 'N', 'M', ',', '.', '/', '\0', '\0', '\0', ' '
};

static char keymap_shift_nocaps[] = {
	'\0', '\0', '!', '@', '#',	'$', '%', '^',	'&', '*', '(', ')',
	'_', '+', '\b', '\t', 'Q',	'W', 'E', 'R',	'T', 'Y', 'U', 'I',
	'O', 'P', '{', '}', '\n',  '\0', 'A', 'S',	'D', 'F', 'G', 'H',
	'J', 'K', 'L', ':', '\"', '~', '\0', '|', 'Z', 'X', 'C', 'V',
	'B', 'N', 'M', '<', '>',  '?', '\0', '\0', '\0', ' '
};

static char keymap_shift_caps[] = {
	'\0', '\0', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
	'_', '+', '\b', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',
	'o', 'p', '{', '}', '\n',  '\0', 'a', 's', 'd', 'f', 'g', 'h',
	'j', 'k', 'l', ':', '\"', '~', '\0', '|', 'z', 'x', 'c', 'v',
	'b', 'n', 'm', '<', '>',  '?', '\0', '\0', '\0', ' '
};

static char control_sequence_raw[] = {
	'\033', '[', 'A', 0, // 4
	'\033', '[', 'B', 0, // 8
	'\033', '[', 'C', 0, // 12
	'\033', '[', 'D', 0, // 16
	'\033', '[', '3', '~', 0, // 21
	'\033', '[', '1', '~', 0, // 26
	'\033', '[', '4', '~', 0, // 31
};

static char *control_sequence[] = {
	control_sequence_raw + 0,
	control_sequence_raw + 4,
	control_sequence_raw + 8,
	control_sequence_raw + 12,
	control_sequence_raw + 21,
	control_sequence_raw + 26,
	control_sequence_raw + 31,
};

static int get_character(char *character) {
    uint8_t code = io::readb(kb::KBD_PS2_DATA);
    bool was_released = code & 0x80;

    if (code == 0x2A || code == 0x36
        || code == 0xAA || code == 0xB6) {
        if (!was_released) {
            is_shift = true;
        } else {
            is_shift = false;
        }

        return -1;
    }

    if (code == 0x1D || code == 0x9D) {
        if (!was_released) {
            is_ctrl = true;
        } else {
            is_ctrl = false;
        }

        return -1;
    }

    if (code == 0x3A) {
        is_shift_locked ^= 1;
        return -1;
    }

    if (code == 0xE0) {
        extended_map = true;
        return -1;
    }

    if (!extended_map) {
        goto no_extended;
    }

    extended_map = false;
    switch (code) {
        case 0x53:
            return 5;
        case 0x47:
            return 6;
        case 0x4F:
            return 7;
        case 0x4B:
            return 3;
        case 0x48:
            return 0;
        case 0x50:
            return 1;
        case 0x4D:
            return 2;
        default:
            return -1;
    }

    no_extended:
        if (was_released) {
            return -1;
        }

        if (code < sizeof(keymap_plain)) {
            if (!is_shift_locked && !is_shift) {
                *character = keymap_plain[code];
            } else if (is_shift_locked && !is_shift) {
                *character = keymap_caps[code];
            } else if (!is_shift_locked && is_shift) {
                *character = keymap_shift_nocaps[code];
            } else if (is_shift_locked && is_shift) {
                *character = keymap_shift_caps[code];
            }
        }

        if (is_ctrl) {
            if ((*character >= 'A' && (*character <= 'z'))) {
                if (*character >= 'a') {
                    *character = *character - 'a' + 1;
                } else if (*character <= '^') {
                    *character = *character - 'A' + 1;
                }
            }
        }

        return -1;
}

void validate();

void enable() {
    while (io::readb(kb::KBD_PS2_STATUS) & (1 << 1)) asm volatile("pause");
    io::writeb(kb::KBD_PS2_COMMAND, (uint8_t) 0xAE);

    while (io::readb(kb::KBD_PS2_STATUS) & (1 << 1)) asm volatile("pause");
    io::writeb(kb::KBD_PS2_COMMAND, (uint8_t) 0xA8);
}

void disable() {
    while (io::readb(kb::KBD_PS2_STATUS) & (1 << 1)) asm volatile("pause");
    io::writeb(kb::KBD_PS2_COMMAND, (uint8_t) 0xAD);

    while (io::readb(kb::KBD_PS2_STATUS) & (1 << 1)) asm volatile("pause");
    io::writeb(kb::KBD_PS2_COMMAND, (uint8_t) 0xA7);
}

void flush() {
    while (io::readb(kb::KBD_PS2_STATUS) & (1 << 0)) {
        io::readb(kb::KBD_PS2_DATA);
    }
}

void kb::irq_handler(arch::irq_regs *r) {
    if (!tty::active_tty) {
        flush();
        return;
    }

    util::lock_guard in_guard{tty::active_tty->in_lock};

    while (true) {
        uint8_t status = io::readb(kb::KBD_PS2_STATUS);
        if ((status & (1 << 0)) == 0) {
            break;
        }

        if (status & (1 << 5)) {
            continue;
        }

        char *seq;
        char c = '\0';
        int fun = get_character(&c);
        tty::active_tty->handle_signal(c);

        if (c != '\0') {
            tty::active_tty->in.push(c);
            goto notify_kbd;
        }

        if (fun == -1) {
            continue;
        }

        seq = control_sequence[fun];
        for (size_t i = 0; i < strlen(seq); i++) {
            tty::active_tty->in.push(seq[i]);
        }

        notify_kbd:
            ipc::send(KBD_PRESS);
    }
}

void kb::init() {
    disable();
    flush();

    size_t vector = arch::install_irq(irq_handler);
    arch::route_irq(2, vector);

    enable();
}