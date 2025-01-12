#ifndef LOCK_HPP
#define LOCK_HPP

#include <arch/types.hpp>

namespace util {
    class lock {
        private:
            volatile bool _lock;
            bool interrupts;
        public:
            void acquire() {
                while(__atomic_test_and_set(&this->_lock, __ATOMIC_ACQUIRE));
            }
            
            void irq_acquire() {
                interrupts = arch::get_irq_state();
                arch::irq_off();
                while(__atomic_test_and_set(&this->_lock, __ATOMIC_ACQUIRE));
            }

            void release() {
                __atomic_clear(&this->_lock, __ATOMIC_RELEASE);
            }

            void irq_release() {
                __atomic_clear(&this->_lock, __ATOMIC_RELEASE);
                if (interrupts) {
                    arch::irq_on();
                } else {
                    arch::irq_off();
                }
            }

            void await() {
                acquire();
                release();
            }

            lock() : _lock(0), interrupts(false) { }

            lock(const lock &other) = delete;

            ~lock() {
                this->release();
            }
    };
};

#endif