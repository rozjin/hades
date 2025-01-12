#include "driver/video/bmp.hpp"
#include "flanterm/backends/fb.hpp"
#include "flanterm/flanterm.hpp"
#include <cstddef>
#include <driver/video/vesa.hpp>

size_t width;
size_t height;
size_t bpp;
size_t pitch;
size_t address;
flanterm_context *ft_ctx;

constexpr uint32_t rgb(size_t r, size_t g, size_t b) {
    return (r << 16) | (g << 8) | b;
}

constexpr auto bg = rgb(65, 74, 76);
constexpr auto fg = rgb(255, 250, 250);

constexpr auto fontHeight = 16;
constexpr auto fontWidth = 8;
constexpr auto fontSize = fontWidth * fontHeight;

bool video::vesa::disabled = false;
void video::vesa::init(stivale::boot::tags::framebuffer fbinfo) {
    width = fbinfo.width;
    height = fbinfo.height;
    bpp = fbinfo.bpp;
    pitch = fbinfo.pitch;
    address = fbinfo.addr + memory::x86::virtualBase;

    ft_ctx = flanterm_fb_init(
        NULL,
        NULL,
        (uint32_t *) address,
        width, height, pitch,
        fbinfo.red_mask_size, fbinfo.red_mask_shift,
        fbinfo.green_mask_size, fbinfo.green_mask_shift,
        fbinfo.blue_mask_size, fbinfo.blue_mask_shift,
        NULL, 
        NULL, NULL,
        NULL, NULL,
        NULL, NULL,
        NULL, 0, 0, 1,
        0, 0,
        0        
    );
}

void video::vesa::write_log(char c) {
    if (disabled) return;
    flanterm_write(ft_ctx, &c, 1);
}

size_t abs(int32_t n) {
    return (size_t) ((n > 0) ? n : -n);
}

void video::vesa::display_bmp(void *buf, size_t size) {
    bmp::file_header *header = (bmp::file_header *) buf;
    bmp::info_header *info = (bmp::info_header *) ((char *) buf + sizeof(bmp::file_header));
    char *image = (char *) buf + header->pixel_off;

    size_t rowSize = ((info->bpp * info->width + 31) / 32) * 4;
    auto flipped = info->height < 0;

    size_t y = (height / 2) - (info->height / 2);
    size_t x = (width / 2) - (info->width / 2);

    memset((void *) address, 0, pitch * height);
    for (size_t yp = 0; yp < abs(info->height); yp++) {
        char *image_row = image + (flipped ? yp : (info->height - yp)) * rowSize;
        uint32_t *fb_row = ((uint32_t *) address) + ((yp + y) * width) + x;

        for (uint32_t xp = 0; xp < (uint32_t) info->width; xp++) {
            uint32_t b = image_row[0] & 0xFF;
            uint32_t g = image_row[1] & 0xFF;
            uint32_t r = image_row[2] & 0xFF;

            uint32_t rgb = (r << 16) | (g << 8) | (b) | (0xFF << 24);

            *(fb_row + xp) = rgb;
            image_row += info->bpp / 8;
        }
    } 
}