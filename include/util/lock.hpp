#ifndef LOCK_HPP
#define LOCK_HPP

#include <arch/types.hpp>

namespace util {
    class spinlock {
        private:
            volatile bool _lock;
            bool interrupts;
        public:            
            void lock() {
                interrupts = arch::get_irq_state();
                arch::irq_off();
                while(__atomic_test_and_set(&this->_lock, __ATOMIC_ACQUIRE));
            }

            void lock_noirq() {
                while(__atomic_test_and_set(&this->_lock, __ATOMIC_ACQUIRE));
            }

            void unlock_noirq() {
                __atomic_clear(&this->_lock, __ATOMIC_RELEASE);
            }

            void await() {
                lock();
                unlock();
            }

            void unlock() {
                __atomic_clear(&this->_lock, __ATOMIC_RELEASE);
                if (interrupts) {
                    arch::irq_on();
                } else {
                    arch::irq_off();
                }
            }

            spinlock() : _lock(0), interrupts(false) {}
            spinlock(const spinlock &other) = delete;
            ~spinlock() {
                if (this->_lock)
                    this->unlock();
            }
    };

    struct lock_guard {
        lock_guard(util::spinlock &spinlock)
        : spinlock{&spinlock}, locked{false} {
            lock();
        }

        lock_guard(const lock_guard &) = delete;
        lock_guard &operator= (const lock_guard &) = delete;

        ~lock_guard() {
            if(locked)
                unlock();
        }

    private:
        util::spinlock *spinlock;
        bool locked;

        void lock() {
            spinlock->lock();
            locked = true;
        }

        void unlock() {
            spinlock->unlock();
            locked = false;
        }
    };
};

#endif