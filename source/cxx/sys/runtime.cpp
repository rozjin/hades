#include <cstddef>
#include <frg/allocation.hpp>
#include <frg/macros.hpp>
#include <mm/mm.hpp>
#include <sys/runtime.hpp>
#include <util/log/log.hpp>
#include <util/log/panic.hpp>
#include <new>

static log::subsystem logger = log::make_subsystem("FRG");
extern "C" {
	void FRG_INTF(log)(const char *cstring) {
        kmsg(logger, cstring);
    }

	void FRG_INTF(panic)(const char *cstring) {
        panic("[FRG | PANIC]: ", cstring);
    }

    static constexpr size_t ATEXIT_MAX_FUNCS = 128;
    atexit_func_entry __atexit_funcs[ATEXIT_MAX_FUNCS];

    size_t __atexit_func_count = 0;
    void *__dso_handle = 0;

    int __cxa_atexit(void (*f)(void *), void *objptr, void *dso) {
        if (__atexit_func_count >= ATEXIT_MAX_FUNCS) return -1;

        __atexit_funcs[__atexit_func_count].destructor_func = f;
        __atexit_funcs[__atexit_func_count].obj = objptr;
        __atexit_funcs[__atexit_func_count].dso_handle = dso;
        __atexit_func_count++;

        return 0;
    }

    void __cxa_finalize(void *f) {
        size_t i = __atexit_func_count;
        if (!f) {
            while (i--) {
                if (__atexit_funcs[i].destructor_func) {
                    (*__atexit_funcs[i].destructor_func)(__atexit_funcs[i].obj);
                }
            }

            return;
        }

        while (i--) {
            if (__atexit_funcs[i].destructor_func == f) {
                (*__atexit_funcs[i].destructor_func)(__atexit_funcs[i].obj);
                __atexit_funcs[i].destructor_func = 0;
            }
        }
    }

    void __cxa_pure_virtual() {
        panic("pure virtual");
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
