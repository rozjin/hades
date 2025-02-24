#include <cstddef>
#include <cstdint>
#include <util/log/panic.hpp>

constexpr size_t STACK_CHK_GUARD = 0x595e9fbd94fda766;
extern "C" {
    uintptr_t __stack_chk_guard = STACK_CHK_GUARD;

    void __stack_chk_fail(void) {
        panic("Stack smashing detected");
    }
}