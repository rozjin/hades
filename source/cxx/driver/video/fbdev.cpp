#include "driver/dtable.hpp"
#include "fs/dev.hpp"
#include "fs/vfs.hpp"
#include "mm/common.hpp"
#include "mm/mm.hpp"
#include <util/stivale.hpp>
#include <driver/video/fbdev.hpp>

void fb::init(stivale::boot::tags::framebuffer *info) {
    auto device = frg::construct<fb::device>(memory::mm::heap, vfs::devfs::mainbus, dtable::majors::FB, -1, nullptr);

    device->width = info->width;
    device->height = info->height;
    device->bpp = info->bpp;
    device->pitch = info->pitch;
    device->address = info->addr + memory::x86::virtualBase;

    device->major = major;
    device->minor = 0;

    device->linux_compat.fix = frg::construct<fb_fix_screeninfo>(memory::mm::heap);
    device->linux_compat.var = frg::construct<fb_var_screeninfo>(memory::mm::heap);
    
    *device->linux_compat.fix = (fb_fix_screeninfo) {
        .id = { 0 },
        .smem_start = info->addr,
        .smem_len = (uint32_t) info->pitch * info->height,
        .type = FB_TYPE_PACKED_PIXELS,
        .visual = FB_VISUAL_TRUECOLOR,
        .line_length = info->pitch,
        .accel = FB_ACCEL_NONE,
        .capabilities = 0,
        .reserved = { 0 }
    };

    *device->linux_compat.var = (fb_var_screeninfo) {
        .xres = info->width,
        .yres = info->height,

        .xres_virtual = info->width,        
        .yres_virtual = info->height,

        .xoffset = 0,
        .yoffset = 0,
        .bits_per_pixel = info->bpp,
        .grayscale = 0,
        .red = (fb_bitfield) { info->red_mask_shift, info->red_mask_size, 0 },
        .green = (fb_bitfield) { info->green_mask_shift, info->green_mask_size, 0 },
        .blue = (fb_bitfield) { info->blue_mask_shift, info->blue_mask_size, 0 },

        .nonstd = 0,
        .activate = 0,
        .height = (uint32_t) -1,
        .width = (uint32_t) -1,
        .accel_flags = 0,
        .pixclock = 0,
        .left_margin = 0,
        .right_margin = 0,
		.upper_margin = 0,
		.lower_margin = 0,
		.hsync_len = 0,
		.vsync_len = 0,
		.sync = 0,
		.vmode = 0,
		.rotate = 0,
		.colorspace = 0,
		.reserved = { 0 }
    };

    vfs::devfs::append_device(device, dtable::majors::FB);
}

ssize_t fb::device::read(void *buf, size_t count, size_t offset) {
    if (offset + count > linux_compat.fix->smem_len) {
        count = linux_compat.fix->smem_len - offset;
    }

    memcpy(buf, (void *) address, count);
    return count;
}

ssize_t fb::device::write(void *buf, size_t count, size_t offset) {
    if (offset + count > linux_compat.fix->smem_len) {
        count = linux_compat.fix->smem_len - offset;
    }

    memcpy((void *) address, buf, count);
    return count;
}

ssize_t fb::device::ioctl(size_t req, void *buf) {
    switch (req) {
        case FBIOGET_VSCREENINFO:
            memcpy(buf, linux_compat.var, sizeof(fb_var_screeninfo));
            break;
        case FBIOPUT_VSCREENINFO:
            memcpy(linux_compat.var, buf, sizeof(fb_var_screeninfo));
            break;
        case FBIOGET_FSCREENINFO:
            memcpy(buf, linux_compat.fix, sizeof(fb_fix_screeninfo));
            break;
        case FBIOBLANK:
            break;
        default:
            return -1;
    }

    return 0;
}

/*
void *fb::device::mmap(vfs::node *file, void *addr, size_t len, size_t offset) {
    return (void *)(linux_compat.fix->smem_start + offset);
}

*/