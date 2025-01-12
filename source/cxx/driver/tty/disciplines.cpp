#include "arch/types.hpp"
#include "sys/sched/sched.hpp"
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

int tty::device::wait_for_kbd(util::ring<char> *queue, char *chars, bool check_min, int min) {
    ipc::queue waitq;
    kbd_trigger->add(&waitq);

    for (;;) {
        auto [waker, got_signal] = waitq.block(arch::get_thread());
        if (got_signal) {
            canon_lock.irq_release();
            kfree(chars);

            kbd_trigger->remove(&waitq);
            return -1;
        }

        if (check_min) {
            if (__atomic_load_n(&queue->items, __ATOMIC_RELAXED) >= min) break;
        } else {
            if (__atomic_load_n(&queue->items, __ATOMIC_RELAXED) > 0) break; 
        }
    }

    kbd_trigger->remove(&waitq);
    return 0;
}

ssize_t tty::device::read_canon(void *buf, size_t len) {
    char *chars = (char *) kmalloc(len);

    size_t count = 0;
    canon_lock.irq_acquire();

    acquire_chars:
        util::ring<char> *line_queue;

        if ((line_queue = canon.peek())) {
            for (count = 0; count < len; count++) {
                if (!line_queue->pop(chars)) {
                    break;
                }

                chars++;
            }

            if (line_queue->items == 0) {
                canon.pop(&line_queue);
                frg::destruct(memory::mm::heap, line_queue);
            }

            canon_lock.irq_release();

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
            if (wait_for_kbd(&in, chars) < 0) {
                return -1;
            }

            in_lock.irq_acquire();
            while (in.pop(&c)) {
                if (ignore_char(termios, c)) {
                    continue;
                }

                c = correct_char(termios, c);
                if (new_line(termios, c)) {
                    line_queue->push(c);
                    items++;
                    out_lock.irq_acquire();
                    echo_char(this, c);
                    out_lock.irq_release();

                    if (driver && driver->has_flush)
                        driver->flush(this);
                }

                if (c == termios.c_cc[VEOL] || c == termios.c_cc[VEOF]) {
                    in_lock.irq_release();
                    goto acquire_chars;
                }

                if ((termios.c_lflag & ECHOE) && (c == termios.c_cc[VERASE])) {
                    // Print a backspace and ignore the char
                    if (items) {
                        items--;
                        char special2[] = { '\b', ' ', '\b' };

                        out_lock.irq_acquire();
                        out.push(special2[0]);
                        out.push(special2[1]);
                        out.push(special2[2]);
                        out_lock.irq_release();

                        if (driver && driver->has_flush)
                            driver->flush(this);
                        line_queue->pop_back(&special);
                    }
                }
            }

            in_lock.irq_release();
        }

    goto acquire_chars;
}

ssize_t tty::device::read_raw(void *buf, size_t len) {
    cc_t min = termios.c_cc[VMIN];
    cc_t time = termios.c_cc[VTIME];

    char *chars = (char *) kmalloc(len);
    size_t count = 0;

    if (min == 0 && time == 0) {
        if (__atomic_load_n(&in.items, __ATOMIC_RELAXED) == 0) {
            kfree(chars);
            return 0;
        }

        in_lock.irq_acquire();
        out_lock.irq_acquire();
        for (count = 0; count < len; count++) {
            if (!in.pop(chars)) {
                break;
            }

            if (ignore_char(termios, *chars)) {
                continue;
            }

            *chars = correct_char(termios, *chars);
            echo_char(this, *chars++);
        }

        out_lock.irq_release();
        if (driver && driver->has_flush)
            driver->flush(this);
        in_lock.irq_release();

        auto copied = arch::copy_to_user(buf, chars, count);
        if (copied < count) {
            kfree(chars);
            return count - copied;
        }

        kfree(chars);
        return count;
    } else if (min > 0 && time == 0) {
        if (wait_for_kbd(&in, chars, true, min) < 0) {
            return -1;
        }

        in_lock.irq_acquire();
        out_lock.irq_acquire();
        for (count = 0; count < len; count++) {
            in.pop(chars);
            if (ignore_char(termios, *chars)) {
                continue;
            }

            *chars = correct_char(termios, *chars);
            echo_char(this, *chars++);
        }

        out_lock.irq_release();
        if (driver && driver->has_flush)
            driver->flush(this);
        in_lock.irq_release();

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