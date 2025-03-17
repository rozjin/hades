#include "arch/types.hpp"
#include "driver/keyboard.hpp"
#include "ipc/evtable.hpp"
#include "sys/sched/sched.hpp"
#include "util/lock.hpp"
#include <arch/x86/types.hpp>
#include <cstddef>
#include <driver/tty/tty.hpp>
#include <driver/tty/termios.hpp>
#include <mm/mm.hpp>
#include <util/ring.hpp>

bool ignore_char(tty::termios termios, char c) {
    if (c == '\r' && (termios.c_iflag & IGNCR)) {
        return true;
    }

    return false;
}

char correct_char(tty::termios termios, char c) {
    if (c == '\r' && (termios.c_iflag & ICRNL)) {
        return termios.c_cc[VEOL];
    }

    if (c == termios.c_cc[VEOL] && (termios.c_iflag & INLCR)) {
        return '\r';
    }

    return c;
}

void tty::echo_char(device *tty, char c) {
    if (!(tty->termios.c_lflag & ECHO)) {
        return;
    }

    if (c > '\0' && c < ' ' && c != tty->termios.c_cc[VEOL] && c != '\t') {
        if (!(tty->termios.c_lflag & ECHOCTL)) {
            return;
        }

        char special[] = { '^',  (char) (c + 64) };
        tty->out.push(special[0]);
        tty->out.push(special[1]);

        return;
    }

    tty->out.push(c);
}

bool new_line(tty::termios termios, char c) {
	if(c == termios.c_cc[VEOL] || c == '\t' || c >= ' ') {
		return true;
	}

	for(size_t i = 0; i < NCCS; i++) {
		if(termios.c_cc[i] == c) {
			return false;
		}
	}

	return true;
}

ssize_t tty::device::read_canon(void *buf, size_t len) {
    char *chars = (char *) kmalloc(len);
    char *chars_ptr = chars;

    size_t count = 0;
    util::lock_guard canon_guard{canon_lock};

    acquire_chars:
        util::ring<char> *line_queue;

        if ((line_queue = canon.peek())) {
            for (count = 0; count < len; count++) {
                if (!line_queue->pop(chars_ptr)) {
                    break;
                }

                chars_ptr++;
            }

            if (line_queue->items == 0) {
                canon.pop(&line_queue);
                frg::destruct(memory::mm::heap, line_queue);
            }

            auto copied = arch::copy_to_user(buf, chars, count);
            if (copied < count) {
                kfree(chars);
                return count - copied;
            }

            kfree(chars);
            return count;
        }

        char c, special;
        size_t items = 0;
        line_queue = frg::construct<util::ring<char>>(memory::mm::heap, max_canon_lines);
        canon.push(line_queue);

        while (true) {
            for (;;) {
                if (__atomic_load_n(&in.items, __ATOMIC_RELAXED) > 0) break; 

                auto [evt, _] = kb::wire.wait(evtable::KB_PRESS, true);
                if (evt < 0) {
                    kfree(chars);
                    return -1;
                }
            }

            util::lock_guard in_guard{in_lock};
            while (in.pop(&c)) {
                if (ignore_char(termios, c)) {
                    continue;
                }

                c = correct_char(termios, c);
                if (new_line(termios, c)) {
                    line_queue->push(c);
                    items++;
                    out_lock.lock();
                    echo_char(this, c);
                    out_lock.unlock();

                    if (driver && driver->has_flush)
                        driver->flush(this);
                }

                if (c == termios.c_cc[VEOL] || c == termios.c_cc[VEOF]) {
                    in_guard.~lock_guard();
                    goto acquire_chars;
                }

                if ((termios.c_lflag & ECHOE) && (c == termios.c_cc[VERASE])) {
                    // Print a backspace and ignore the char
                    if (items) {
                        items--;
                        char special2[] = { '\b', ' ', '\b' };

                        out_lock.lock();
                        out.push(special2[0]);
                        out.push(special2[1]);
                        out.push(special2[2]);
                        out_lock.unlock();

                        if (driver && driver->has_flush)
                            driver->flush(this);
                        line_queue->pop_back(&special);
                    }
                }
            }

            in_guard.~lock_guard();
        }

    goto acquire_chars;
}

ssize_t tty::device::read_raw(void *buf, size_t len) {
    cc_t min = termios.c_cc[VMIN];
    cc_t time = termios.c_cc[VTIME];

    char *chars = (char *) kmalloc(len);
    char *chars_ptr = chars;
    size_t count = 0;

    if (min == 0 && time == 0) {
        if (__atomic_load_n(&in.items, __ATOMIC_RELAXED) == 0) {
            kfree(chars);
            return 0;
        }

        util::lock_guard in_guard{in_lock};
        util::lock_guard out_guard{out_lock};
        for (count = 0; count < len; count++) {
            if (!in.pop(chars_ptr)) {
                break;
            }

            if (ignore_char(termios, *chars_ptr)) {
                continue;
            }

            *chars_ptr = correct_char(termios, *chars_ptr);
            echo_char(this, *chars_ptr++);
        }

        out_guard.~lock_guard();
        if (driver && driver->has_flush)
            driver->flush(this);

        auto copied = arch::copy_to_user(buf, chars, count);
        if (copied < count) {
            kfree(chars);
            return count - copied;
        }

        kfree(chars);
        return count;
    } else if (min > 0 && time == 0) {
        for (;;) {
            if (__atomic_load_n(&in.items, __ATOMIC_RELAXED) >= min) break; 

            auto [evt, _] = kb::wire.wait(evtable::KB_PRESS, true);
            if (evt < 0) {
                kfree(chars);
                return -1;
            }
        }

        util::lock_guard in_guard{in_lock};
        util::lock_guard out_guard{out_lock};
        for (count = 0; count < len; count++) {
            in.pop(chars_ptr);
            if (ignore_char(termios, *chars_ptr)) {
                continue;
            }

            *chars_ptr = correct_char(termios, *chars_ptr);
            echo_char(this, *chars_ptr++);
        }

        out_guard.~lock_guard();
        if (driver && driver->has_flush)
            driver->flush(this);

        auto copied = arch::copy_to_user(buf, chars, count);
        if (copied < count) {
            kfree(chars);
            return count - copied;
        }

        kfree(chars);
        return count;
    } else {
        // TODO: time != but min < 0
        kfree(chars);
        return -1;
    }
}