#include <cstddef>
#include <driver/video/vt.hpp>
#include <driver/tty/tty.hpp>
#include <flanterm/flanterm.hpp>
#include <flanterm/backends/fb.hpp>
#include <fs/dev.hpp>
#include <mm/common.hpp>
#include <mm/mm.hpp>

void vt::driver::flush(tty::device *tty) {
    tty->out_lock.irq_acquire();

    char c;
    char buf[tty::output_size];
    size_t count = 0;
    while (tty->out.pop(&c)) {
        buf[count] = c;
        count++;
    }

    flanterm_write(ft_ctx, buf, count);
    tty->out_lock.irq_release();
}

ssize_t vt::driver::ioctl(tty::device *tty, size_t req, void *buf) {
    switch (req) {
        case TIOCGWINSZ: {
            tty::winsize *winsz = (tty::winsize *) buf;
            *winsz = (tty::winsize) {
                .ws_row = (uint16_t) ft_ctx->rows,
                .ws_col = (uint16_t) ft_ctx->cols,
                .ws_xpixel = (uint16_t) fb->var->xres,
                .ws_ypixel = (uint16_t) fb->var->yres
            };

            break;
        }

        case KDSETMODE: {
            is_enabled = (uintptr_t) buf;
            if (is_enabled) {
                if (!fb_save) {
                    fb_save = frg::construct<fb::fb_info>(memory::mm::heap);
                    fb_save->var = frg::construct<fb::fb_var_screeninfo>(memory::mm::heap);
                    fb_save->fix = frg::construct<fb::fb_fix_screeninfo>(memory::mm::heap);
                    
                    *fb_save->var = *fb->var;
                    *fb_save->fix = *fb->fix;

                    fb_save->fix->smem_start = (uint64_t) memory::pmm::alloc(fb->fix->smem_len / memory::page_size);
                }

                flanterm_write(ft_ctx, "\e[?251", 6);
                memcpy((void *) fb_save->fix->smem_start, (void *) fb->fix->smem_start, 
                                     fb->fix->smem_len);
            } else {
                if (fb_save) {
                    memcpy((void *) fb->fix->smem_start, (void *) fb_save->fix->smem_start, 
                     fb->fix->smem_len);
                }

                flanterm_write(ft_ctx, "\e[?25h", 6);
            }

            break;
        }

        case KDGETMODE: {
            int *mode = (int *) buf;
            *mode = is_enabled;
            break;
        }

        case VT_GETMODE: {
            auto copied = arch::copy_to_user(buf, &mode, sizeof(mode));
            if (copied < sizeof(mode)) {
                return -1;
            }

            break;
        }

        case VT_SETMODE: {
            auto copied = arch::copy_from_user(&mode, buf, sizeof(mode));
            if (copied < sizeof(mode)) {
                return -1;
            }

            break;
        }

        default: {
            arch::set_errno(ENOSYS);
            return -1;
        }
    }

    return 0;
}

void vt::init(stivale::boot::tags::framebuffer info) {
    vt::driver *driver = frg::construct<vt::driver>(memory::mm::heap);

    driver->has_flush = true;
    driver->has_ioctl = true;

    driver->fb = frg::construct<fb::fb_info>(memory::mm::heap);
    driver->fb->fix = frg::construct<fb::fb_fix_screeninfo>(memory::mm::heap);
    driver->fb->var = frg::construct<fb::fb_var_screeninfo>(memory::mm::heap);

    driver->fb->fix->smem_start = (uint64_t) info.addr + memory::x86::virtualBase;
    driver->fb->fix->line_length = info.pitch;
    driver->fb->var->xres = info.width;
    driver->fb->var->yres = info.height;

    driver->ft_ctx = flanterm_fb_init(
        kmalloc, kfree_sz,
        (uint32_t *) (info.addr + memory::x86::virtualBase),
        info.width, info.height, info.pitch,
        info.red_mask_size, info.red_mask_shift,
        info.green_mask_size, info.green_mask_shift,
        info.red_mask_size, info.red_mask_shift,
        NULL,
        NULL, NULL, 
        NULL, NULL,
        NULL, NULL,
        NULL, 0, 0, 1,
        0, 0,
        0
    );

    for (size_t i = 0; i < vt_ttys; i++) {
        auto tty = frg::construct<tty::device>(memory::mm::heap);
        tty->driver = driver;
        tty->major = tty::major;
        tty->minor = i;

        auto vt_path = vfs::path("tty") + (i + 48);
        vfs::devfs::add(vt_path, tty);
    }
}