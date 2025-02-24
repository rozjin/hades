#ifndef VT_HPP
#define VT_HPP

#include <flanterm/flanterm.hpp>
#include <driver/tty/tty.hpp>
#include <driver/video/fbdev.hpp>
#include <util/stivale.hpp>
#include <cstddef>

namespace vt {
    constexpr size_t vt_ttys = 2;

    constexpr size_t KDSETMODE = 0x4B3A;
    constexpr size_t KDGETMODE = 0x4B3B;
    constexpr size_t KD_TEXT = 0;
    constexpr size_t KD_GRAPHICS = 1;

    constexpr size_t VT_GETMODE = 0x5601;
    constexpr size_t VT_SETMODE = 0x5602;

    constexpr size_t VT_AUTO = 0;
    constexpr size_t VT_PROCESS = 1;
    constexpr size_t VT_ACKACQ = 2;

    struct vt_mode {
        char mode;
        char waitv;
        short relsig;
        short acqsig;
        short frsig;
    };

    void init(stivale::boot::tags::framebuffer info);
    struct driver: tty::driver {
        flanterm_context *ft_ctx;

        bool is_enabled;
        vt_mode mode;

        fb::fb_info *fb;
        fb::fb_info *fb_save;

        ssize_t ioctl(tty::device *tty, size_t req, void *buf) override;
        void flush(tty::device *tty) override;
    };

    struct matcher: vfs::devfs::matcher {
        matcher(): vfs::devfs::matcher(true,
        "tty", nullptr, false, 0) {}
    };
}

#endif