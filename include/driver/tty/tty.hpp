#ifndef TTY_HPP
#define TTY_HPP

#include "driver/keyboard.hpp"
#include "driver/tty/termios.hpp"
#include "fs/vfs.hpp"
#include "mm/mm.hpp"
#include "sys/sched/wait.hpp"
#include "util/lock.hpp"
#include "util/ring.hpp"
#include <cstddef>
#include <fs/dev.hpp>
#include <sys/sched/sched.hpp>

namespace vt {
    void init(stivale::boot::tags::framebuffer info);
}

namespace tty {
    #define TCGETS 0x5401
    #define TCSETS 0x5402
    #define TCSETSW 0x5303
    #define TCSETSF 0x5304

    #define TIOCGPGRP 0x540f
    #define TIOCSPGRP 0x5410
    #define TIOCGWINSZ 0x5413
    #define TIOCSWINSZ 0x5414
    #define TIOCSCTTY 0x540e
    #define TIOCGSID 0x5429

    #define TIOCGPTN 0x80045430
    #define TIOCSPTLCK 0x40045431

    constexpr size_t max_chars = 8192;
    constexpr size_t max_canon_lines = 256;
    constexpr size_t output_size = 8192;

    constexpr size_t major = 29;

    struct winsize {
        uint16_t ws_row;
        uint16_t ws_col;
        uint16_t ws_xpixel;
        uint16_t ws_ypixel;
    };

    struct device;
    extern device *active_tty;

    struct driver {
        virtual ssize_t connect(device *tty) { return -1; };
        virtual ssize_t ioctl(device *tty, size_t req, void *buf) { return -1; };
        virtual size_t disconnect(device *tty) { return -1; };
        virtual void flush(device *tty) {};

        bool has_connect, has_ioctl, has_disconnect, has_flush;
        driver(): has_connect(false), has_ioctl(false), has_disconnect(false), has_flush(false) {}
    };

    void echo_char(device *tty, char c);
    struct device: vfs::devfs::device {
        private:
            util::lock lock;
            int ref;

            tty::driver *driver;

            sched::session *sess;
            sched::process_group *fg;
            tty::termios termios;

            ipc::trigger *kbd_trigger;
        public:
            friend struct ptmx;
            friend struct pts;
            friend void echo_char(device *tty, char c);
            friend void vt::init(stivale::boot::tags::framebuffer info);
            friend void sched::process::kill(int exit_code);
            friend void kb::irq_handler(arch::irq_regs *r);

            // TODO: change visibility

            util::lock in_lock;
            util::ring<char> in;

            util::lock out_lock;
            util::ring<char> out;

            util::lock canon_lock;
            util::ring<util::ring<char> *> canon;

            device(): termios(), in_lock(), in(max_chars), out_lock(),
                   out(output_size), canon_lock(), canon(max_canon_lines) {
                termios.c_lflag = ECHO | ECHOCTL | ECHOE | ISIG | ICANON | TOSTOP;
                termios.c_iflag = 0;

                termios.c_cc[VEOF] = 4;		// ^D
                termios.c_cc[VERASE] = 8;	// ^H
                termios.c_cc[VINTR] = 3;	// ^C
                termios.c_cc[VKILL] = 21;	// ^U
                termios.c_cc[VSTART] = 17;	// ^Q
                termios.c_cc[VSTOP] = 19;	// ^S
                termios.c_cc[VSUSP] = 26;	// ^Z
                termios.c_cc[VEOL] = '\n';
                termios.c_cc[VQUIT] = 28;

                termios.c_cc[VTIME] = 0;
                termios.c_cc[VMIN] = 1;

                kbd_trigger = frg::construct<ipc::trigger>(memory::mm::heap);
            };

            void handle_signal(char c);

            int wait_for_kbd(util::ring<char> *queue, char *chars, bool check_min = false, int min = 0);
            ssize_t read_canon(void* buf, size_t len);
            ssize_t read_raw(void *buf, size_t len);

            void set_active();

            ssize_t on_open(vfs::fd *fd, ssize_t flags) override;
            ssize_t on_close(vfs::fd *fd, ssize_t flags) override;
            ssize_t read(void *buf, size_t count, size_t offset) override;
            ssize_t write(void *buf, size_t count, size_t offset) override;
            ssize_t ioctl(size_t req, void *buf) override;
    };

    struct self: vfs::devfs::device {
        public:
            static void init();
            ssize_t on_open(vfs::fd *fd, ssize_t flags) override;        
    };

    void set_active(frg::string_view path, vfs::fd_table *table);
};

#endif