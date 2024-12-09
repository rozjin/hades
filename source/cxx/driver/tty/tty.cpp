#include "arch/types.hpp"
#include <cstddef>
#include <sys/sched/signal.hpp>
#include <driver/tty/termios.hpp>
#include <driver/tty/tty.hpp>

#include <fs/dev.hpp>
#include <fs/vfs.hpp>
#include <mm/mm.hpp>

tty::device *tty::active_tty = nullptr;
void tty::self::init() {
    auto self = frg::construct<tty::self>(memory::mm::heap);
    vfs::devfs::add("/dev/tty", self);
}

ssize_t tty::self::on_open(vfs::fd *fd, ssize_t flags) {
    if (arch::get_process() && !arch::get_process()->sess->tty) {
        arch::set_errno(ENODEV);
        return -1;
    }

    fd->desc->node = arch::get_process()->sess->tty->file;
    return 0;
}

void tty::device::handle_signal(char c) {
    if (termios.c_lflag & ISIG) {
        if (termios.c_cc[VINTR] == c) {
            sched::signal::send_group(nullptr, fg, SIGINT);
        } else if (termios.c_cc[VQUIT] == c) {
            sched::signal::send_group(nullptr, fg, SIGTERM);
        } else if (termios.c_cc[VSUSP] == c) {
            sched::signal::send_group(nullptr, fg, SIGTSTP);
        }
    }
}

void tty::device::set_active() {
    active_tty = this;
}

ssize_t tty::device::on_open(vfs::fd *fd, ssize_t flags) {
    if (__atomic_fetch_add(&ref, 1, __ATOMIC_RELAXED) == 0) {
        if (driver && driver->has_connect) {
            if (driver->connect(this) == -1) {
                return -1;
            }
        }
    }

    if ((sess == nullptr) && (!((flags & O_NOCTTY) == O_NOCTTY)) &&
        (arch::get_process() && arch::get_process()->group->pgid == arch::get_process()->sess->leader_pgid)) {
        sess = arch::get_process()->sess;
        fg = arch::get_process()->group;
    }

    return 0;
}

ssize_t tty::device::on_close(vfs::fd *fd, ssize_t flags) {
    if (__atomic_sub_fetch(&ref, 1, __ATOMIC_RELAXED) == 0) {
        if (driver && driver->has_disconnect) {
            driver->disconnect(this);
        }
    }

    return 0;
}

ssize_t tty::device::read(void *buf, size_t count, size_t offset) {
    // TODO: orphans
    if (arch::get_process() && arch::get_process()->sess == sess) {
        if (arch::get_process()->group != fg) {
            if (sched::signal::is_ignored(arch::get_process(), SIGTTIN)
                || sched::signal::is_blocked(arch::get_thread(), SIGTTIN)) {
                arch::set_errno(EIO);
                return -1;
            }

            sched::signal::send_group(nullptr, arch::get_process()->group, SIGTTIN);
            arch::set_errno(EINTR);
            return -1;
        }
    }

    if (termios.c_lflag & ICANON) {
        return read_canon(buf, count);
    } else {
        return read_raw(buf, count);
    }

    return 0;
}

ssize_t tty::device::write(void *buf, size_t count, size_t offset) {
    // TODO: orphans
    if (arch::get_process() && arch::get_process()->sess == sess) {
        if (arch::get_process()->group != fg && (termios.c_cflag & TOSTOP)) {
            if (sched::signal::is_ignored(arch::get_process(), SIGTTOU)
                || sched::signal::is_blocked(arch::get_thread(), SIGTTOU)) {
                arch::set_errno(EIO);
                return -1;
            }

            sched::signal::send_group(nullptr, arch::get_process()->group, SIGTTOU);
            arch::set_errno(EINTR);
            return -1;
        }
    }

    // TODO: nonblock support in vfs
    out_lock.irq_acquire();

    char *chars = (char *) kmalloc(count);
    auto not_copied = arch::copy_from_user(chars, buf, count);
    if (not_copied) {
        kfree(chars);
        out_lock.irq_release();
        return count - not_copied;
    }

    size_t bytes = 0;
    for (bytes = 0; bytes < count; bytes++) {
        if (!out.push(*chars++)) {
            out_lock.irq_release();
            driver->flush(this);
            out_lock.irq_acquire();
        }
    }

    out_lock.irq_release();
    driver->flush(this);

    kfree(chars);
    return bytes;
}

ssize_t tty::device::ioctl(size_t req, void *buf) {
    lock.irq_acquire();
    switch (req) {
        case TIOCGPGRP: {
            if (arch::get_process()->sess != sess) {
                arch::set_errno(ENOTTY);
                lock.irq_release();
                return -1;
            }

            pid_t *pgrp = (pid_t *) buf;
            *pgrp = fg->pgid;
            lock.irq_release();
            return 0;
        }

        case TIOCSPGRP: {
            if (arch::get_process()->sess != sess) {
                arch::set_errno(ENOTTY);
                lock.irq_release();
                return -1;
            }

            pid_t pgrp = *(pid_t *) buf;
            sched::process_group *group;

            if (!(group = sess->groups[pgrp])) {
                arch::set_errno(EPERM);
                lock.irq_release();
                return -1;
            }

            fg = group;
            lock.irq_release();
            return 0;
        }

        case TIOCSCTTY: {
            if (sess || (arch::get_process()->sess->leader_pgid != arch::get_process()->group->pgid)) {
                arch::set_errno(EPERM);
                lock.irq_release();
                return -1;
            }

            sess = arch::get_process()->sess;
            fg = arch::get_process()->group;
            lock.irq_release();
            return 0;
        }

        case TCGETS: {
            in_lock.irq_acquire();
            out_lock.irq_acquire();

            tty::termios *attrs = (tty::termios *) buf;
            *attrs = termios;

            out_lock.irq_release();
            in_lock.irq_release();

            lock.irq_release();
            return 0;
        }

        case TCSETSW: {
            while (__atomic_load_n(&out.items, __ATOMIC_RELAXED));

            in_lock.irq_acquire();
            out_lock.irq_acquire();

            tty::termios *attrs = (tty::termios *) buf;
            termios = *attrs;

            out_lock.irq_release();
            in_lock.irq_release();

            lock.irq_release();
            return 0;            
        }

        case TCSETSF: {
            while (__atomic_load_n(&out.items, __ATOMIC_RELAXED));

            in_lock.irq_acquire();
            out_lock.irq_acquire();

            tty::termios *attrs = (tty::termios *) buf;
            termios = *attrs;

            char c;
            while (in.pop(&c));
            out_lock.irq_release();
            in_lock.irq_release();

            lock.irq_release();
            return 0;            
        }
        
        case SET_ACTIVE: {
            set_active();
            lock.irq_release();
            return 0;
        }

        default: {
            if (driver && driver->has_ioctl) {
                auto res = driver->ioctl(this, req, buf);
                lock.irq_release();
                return res;
            } else {
                arch::set_errno(ENOTTY);
                lock.irq_release();
                return -1;
            }
        }
    }
}

void tty::set_active(frg::string_view path, vfs::fd_table *table) {
    auto fd = vfs::open(nullptr, path, table, O_NOCTTY, O_RDONLY);
    if (fd == nullptr) return;

    tty::device *tty = (tty::device *) fd->desc->node->private_data; 
    vfs::close(fd);

    if (tty) {
        active_tty = tty;
    }
}