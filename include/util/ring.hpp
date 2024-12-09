#ifndef RING_HPP
#define RING_HPP

#include <cstddef>
#include <mm/mm.hpp>
#include <util/string.hpp>

namespace util {
    template <typename T>
    class ring {
        private:
            T *data;
            size_t size;
            int head;
            int tail;
        public:
            size_t items;

            ring(size_t size);

            bool push(T obj);
            bool pop(T *ptr);
            bool pop_back(T *ptr);
            T peek();
    };
}

template <typename T>
util::ring<T>::ring(size_t size) {
    this->data = (T *) kmalloc(sizeof(T) * size);
    this->size = size;
    this->head = -1;
    this->tail = -1;
    this->items = 0;
}

template<typename T>
bool util::ring<T>::push(T obj) {
    if ((head == 0 && (size_t) tail == (size - 1)) || (head == (tail + 1))) {
        return false;
    }

    if (head == -1) {
        head = 0;
        tail = 0;
    } else {
        if ((size_t) tail == (size - 1)) {
            tail = 0;
        } else {
            tail++;
        }
    }

    data[tail] = obj;
    __atomic_add_fetch(&items, 1, __ATOMIC_RELAXED);
    return true;
}

template <typename T>
bool util::ring<T>::pop(T *ptr) {
    if (head == -1) {
        return false;
    }

    T res = data[head];
    __atomic_sub_fetch(&items, 1, __ATOMIC_RELAXED);
    if (head == tail) {
        head = -1;
        tail = -1;
    } else {
        if ((size_t) head == (size - 1)) {
            head = 0;
        } else {
            head++;
        }
    }

    memcpy(ptr, &res, sizeof(T));
    return true;
} 

template <typename T>
bool util::ring<T>::pop_back(T *ptr) {
    if (head == tail) {
        return false;
    }

    if (tail == 0) {
        tail = size - 1;
    } else {
        tail--;
    }

    T res = data[tail];
    __atomic_sub_fetch(&items, 1, __ATOMIC_RELAXED);

    memcpy(ptr, &res, sizeof(T));
    return true;
}

template <typename T>
T util::ring<T>::peek() {
    if (head == -1) {
        return nullptr;
    }

    return data[head];
}

#endif