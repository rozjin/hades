#ifndef PTY_HPP
#define PTY_HPP

#include <fs/dev.hpp>
#include <util/ring.hpp>
#include <cstddef>
#include <driver/tty/tty.hpp>
#include <util/lock.hpp>

namespace tty {
    struct ptm;
    struct pts: driver {
        private:
            device *tty;
            ptm *master;
            winsize size;
        public:
            friend struct ptmx;
            friend struct ptm;

            struct matcher: vfs::devfs::matcher {
                matcher(): vfs::devfs::matcher("true",
                nullptr, "pts", false, 0) {}
            };

            ssize_t ioctl(device *tty, size_t req, void *buf) override; 
            void flush(tty::device *tty) override;
    };

    struct ptm: vfs::devfs::chardev {
        private:
            util::spinlock in_lock;
            util::ring<char> in;
            pts *slave;
        public:
            friend struct ptmx;
            friend struct pts;

            struct matcher: vfs::devfs::matcher {
                matcher(): vfs::devfs::matcher(false,
                nullptr, nullptr, false, 0) {}
            };

            ptm(vfs::devfs::busdev *bus, ssize_t major, ssize_t minor, void *aux): 
                chardev(bus, major, minor, aux),
                in_lock(), in(max_chars) {
                slave = (pts *) aux;
            };
            ssize_t read(void *buf, size_t len, size_t offset) override;
            ssize_t write(void *buf, size_t len, size_t offset) override; 
            ssize_t ioctl(size_t req, void *buf) override;        
    };

    struct ptmx: vfs::devfs::chardev {
        static void init();
        ssize_t on_open(vfs::fd *fd, ssize_t flags) override;

        ptmx(vfs::devfs::busdev *bus, ssize_t major, ssize_t minor, void *aux):
            chardev(bus, major, minor, aux) {}
    };
};

#endif