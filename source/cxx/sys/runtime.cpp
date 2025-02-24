#include <cstddef>
#include <frg/allocation.hpp>
#include <frg/macros.hpp>
#include <mm/mm.hpp>
#include <sys/runtime.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>

static log::subsystem logger = log::make_subsystem("FRG");
extern "C" {
	void FRG_INTF(log)(const char *cstring) {
        kmsg(logger, cstring);
    }

	void FRG_INTF(panic)(const char *cstring) {
        panic("[FRG | PANIC]: ", cstring);
    }

    void __cxa_pure_virtual() {
        panic("pure virtual");
    }

    int __cxa_atexit(void (*f)(void *), void *objptr, void *dso) {
        return 0;
    }

    namespace __cxxabiv1 {
        __extension__ typedef int __guard __attribute__((mode(__DI__)));
        int __cxa_guard_acquire (__guard *g) {
            while(__atomic_test_and_set(g, __ATOMIC_ACQUIRE));
            return 1;
        }

        void __cxa_guard_release (__guard *g) {
            __atomic_clear(g, __ATOMIC_RELEASE);
        }

        void __cxa_guard_abort (__guard *g) {
            panic("cxa guard failed!");
        }
    }
}

void operator delete(void *ptr) {
    kfree(ptr);
}

void operator delete(void *ptr, size_t _) {
    kfree(ptr);
}

void *operator new(size_t size) {
    return kmalloc(size);
}
