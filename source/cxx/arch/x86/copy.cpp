#include <arch/types.hpp>
#include <arch/x86/smp.hpp>
#include <arch/x86/types.hpp>
#include <cstddef>

inline void do_copy_user(void *dst, const void *src, size_t length) {
    /*int d0, d1;
    asm volatile(
        "0: rep; movsq\n"
        "   movq %3, %0\n"
        "1: rep; movsb\n"
        "2: \n"

        ".section .fixup, \"ax\"\n"
        "3: leaq 0(%3, %0, 8), %0\n"
        "   jmp 2b\n"
        ".previous\n"

        ".section .ex_table, \"a\"\n"
        ".align 8\n"
        ".quad 0b, 3b\n"
        ".quad 1b, 2b\n"
        ".previous"
        
        : "=&c"(length), "=&D"(d0), "=&S"(d1)
        : "r"(length % 8), "0"(length / 8), "1"(dst), "2"(src)
        : "memory"
    );
    */

   memcpy(dst, src, length);
}

size_t x86::copy_to_user(void *dst, const void *src, size_t length) {
    uintptr_t dstptr = (uintptr_t) dst;

    uint64_t cs = 0;
    asm volatile("mov %%cs, %0"
        : "=r"(cs));
    if (!(cs & 0x3)) {
        goto do_copy;
    }

    if (dstptr >= 0x7fffffffffff || dstptr + length >= 0x7fffffffffff) {
        set_errno(EFAULT);
        return length;
    }

    do_copy:
        do_copy_user(dst, src, length);
        // if (length) set_errno(EFAULT);

    return length;
}

size_t x86::copy_from_user(void *dst, const void *src, size_t length) {
    uintptr_t srcptr = (uintptr_t) src;

    uint64_t cs = 0;
    asm volatile("mov %%cs, %0"
        : "=r"(cs));
    if (!(cs & 0x3)) {
        goto do_copy;
    }

    if (srcptr >= 0x7fffffffffff || srcptr + length >= 0x7fffffffffff) {
        set_errno(EFAULT);
        return length;
    }

    do_copy:
        do_copy_user(dst, src, length);
        // if (length) set_errno(EFAULT);

    return length;
}

size_t arch::copy_from_user(void *dst, const void *src, size_t length) {
    return x86::copy_from_user(dst, src, length);
}

size_t arch::copy_to_user(void *dst, const void *src, size_t length) {
    return x86::copy_to_user(dst, src, length);
}