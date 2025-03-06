#ifndef FBDEV_HPP
#define FBDEV_HPP

#include <fs/dev.hpp>
#include <util/stivale.hpp>
#include <cstddef>
#include <cstdint>

namespace vt {
    struct driver;
}

namespace fb {
    // fb_fix_screeninfo.type
    constexpr size_t FB_TYPE_PACKED_PIXELS = 0;

    // fb_fix_screeninfo.visual
    constexpr size_t FB_VISUAL_TRUECOLOR = 2;

    // fb_fix_screeninfo.accel
    constexpr size_t FB_ACCEL_NONE = 0;

    // fbdev ioctls
    constexpr size_t FBIOGET_VSCREENINFO = 0x4600;
    constexpr size_t FBIOPUT_VSCREENINFO = 0x4601;
    constexpr size_t FBIOGET_FSCREENINFO = 0x4602;
    constexpr size_t FBIOGETCMAP = 0x4604;
    constexpr size_t FBIOPUTCMAP = 0x4605;
    constexpr size_t FBIOPAN_DISPLAY = 0x4606;
    constexpr size_t FBIOBLANK = 0x4611;

    struct fb_cmap {
        uint32_t start;
        uint32_t length;
        uint16_t *red;
        uint16_t *grewn;
        uint16_t *blue;
        uint16_t *transp;
    };

    struct fb_bitfield {
        uint32_t offset;
        uint32_t length;
        uint32_t msb_right;
    };

    struct fb_fix_screeninfo {
        uint8_t id[16];
        uint64_t smem_start;
        uint32_t smem_len;
        uint32_t type;
        uint32_t type_aux;
        uint32_t visual;
        uint16_t xpanstep;
        uint16_t ypanstep;
        uint16_t ywrapstep;
        uint32_t line_length;
        uint64_t mmio_start;
        uint32_t mmio_len;
        uint32_t accel;
        uint16_t capabilities;
        uint16_t reserved[2];
    };

    struct fb_var_screeninfo {
        uint32_t xres;
        uint32_t yres;
        uint32_t xres_virtual;
        uint32_t yres_virtual;
        uint32_t xoffset;
        uint32_t yoffset;
        uint32_t bits_per_pixel;
        uint32_t grayscale;
        struct fb_bitfield red;
        struct fb_bitfield green;
        struct fb_bitfield blue;
        struct fb_bitfield transp;
        uint32_t nonstd;
        uint32_t activate;
        uint32_t height;
        uint32_t width;
        uint32_t accel_flags;
        uint32_t pixclock;
        uint32_t left_margin;
        uint32_t right_margin;
        uint32_t upper_margin;
        uint32_t lower_margin;
        uint32_t hsync_len;
        uint32_t vsync_len;
        uint32_t sync;
        uint32_t vmode;
        uint32_t rotate;
        uint32_t colorspace;
        uint32_t reserved[4];
    };

    struct fb_info {
        fb_var_screeninfo *var;
        fb_fix_screeninfo *fix;
    };    

    constexpr size_t major = 29;

    void init(stivale::boot::tags::framebuffer *info);    
    struct device : vfs::devfs::chardev {
        private:
            size_t width;
            size_t height;
            size_t bpp;
            size_t pitch;
            size_t address;

            fb_info linux_compat;
            util::spinlock lock;
        public:
            friend struct vt::driver;
            friend void init(stivale::boot::tags::framebuffer *info);

            ssize_t read(void *buf, size_t count, size_t offset) override;
            ssize_t write(void *buf, size_t count, size_t offset) override; 
            ssize_t ioctl(size_t req, void *buf) override;

            device(vfs::devfs::busdev *bus, ssize_t major, ssize_t minor, void *aux):
                vfs::devfs::chardev(bus, major, minor, aux) {}
//            void *mmap(vfs::node *file, void *addr, size_t len, size_t offset) override;
    };

    struct matcher: vfs::devfs::matcher {
        matcher(): vfs::devfs::matcher(true, false,
            "fb", nullptr, false, 0) {}
    };
}

#endif