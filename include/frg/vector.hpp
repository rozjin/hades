#ifndef FRG_VECTOR_HPP
#define FRG_VECTOR_HPP

#include <cstddef>
#include <stddef.h>
#include <utility>

#include <frg/macros.hpp>

namespace frg FRG_VISIBILITY {

template <typename T, typename Allocator> class vector {
public:
  using value_type = T;
  using reference = value_type &;

  friend void swap(vector &a, vector &b) {
    using std::swap;
    swap(a._allocator, b._allocator);
    swap(a._elements, b._elements);
    swap(a._size, b._size);
    swap(a._capacity, b._capacity);
  }

  vector(Allocator allocator = Allocator());

  vector(const vector &other) : vector(other._allocator) {
    auto other_size = other.size();
    _ensure_capacity(other_size);
    for (size_t i = 0; i < other_size; i++)
      new (&_elements[i]) T(other[i]);
    _size = other_size;
  }

  vector(vector &&other) : vector(other._allocator) { swap(*this, other); }

  ~vector();

  vector &operator=(vector other) {
    swap(*this, other);
    return *this;
  }

  T &push(const T &element);

  T &push(T &&element);

  size_t append(const T &element);

  size_t append(T &&element);

  T &push_back(const T &element) { return push(element); }

  T &push_back(T &&element) { return push(std::move(element)); }

  template <typename... Args> T &emplace_back(Args &&...args);

  T pop();

  template <typename... Args> void resize(size_t new_size, Args &&...args);

  T *data() { return _elements; }

  const T *data() const { return _elements; }

  size_t size() const { return _size; }

  bool empty() const { return size() == 0; }

  void clear() { _size = 0; }

  void erase() {
    for (size_t i = 0; i < _size; i++)
      _elements[i].~T();
    _size = 0;
  }

  T *erase(const T *pos) {
    auto const result = _elements + (pos - _elements);
    auto const endIter = end();
    for (auto p = result; p != endIter;) {
      auto &lhs = *p;
      ++p;
      lhs = std::move(*p);
    }

    --_size;
    return result;
  }

  T *erase(const T value) {
    T *pos = nullptr;
    for (size_t i = 0; i < _size; i++) {
      if (_elements[i] == value) {
        pos = _elements + i;
        break;
      }
    }

    if (pos == nullptr)
      return nullptr;

    auto const result = _elements + (pos - _elements);
    auto const endIter = end();
    for (auto p = result; p != endIter;) {
      auto &lhs = *p;
      ++p;
      lhs = std::move(*p);
    }

    --_size;
    return result;
  }

  T *erase(const T *first, const T *last) {
    auto const result = _elements + (first - _elements);
    if (first == last)
      return result;

    auto writeIter = result;
    auto readIter = _elements + (last - _elements);

    for (auto const endIter = end(); readIter != endIter;
         ++writeIter, ++readIter) {
      *writeIter = std::move(*readIter);
    }

    _size = (writeIter - _elements);
    return result;
  }

  T *begin() { return _elements; }

  const T *begin() const { return _elements; }

  T *end() { return _elements + _size; }

  const T *end() const { return _elements + _size; }

  T &front() { return _elements[0]; }
  const T &front() const { return _elements[0]; }

  T &back() { return _elements[_size - 1]; }
  const T &back() const { return _elements[_size - 1]; }

  const T &operator[](size_t index) const { return _elements[index]; }
  T &operator[](size_t index) { return _elements[index]; }

private:
  void _ensure_capacity(size_t capacity);

  Allocator _allocator;
  T *_elements;
  size_t _size;
  size_t _capacity;
};

template <typename T, typename Allocator>
vector<T, Allocator>::vector(Allocator allocator)
    : _allocator{std::move(allocator)}, _elements{nullptr}, _size{0},
      _capacity{0} {}

template <typename T, typename Allocator> vector<T, Allocator>::~vector() {
  for (size_t i = 0; i < _size; i++)
    _elements[i].~T();
  _allocator.free(_elements);
}

template <typename T, typename Allocator>
T &vector<T, Allocator>::push(const T &element) {
  _ensure_capacity(_size + 1);
  T *pointer = new (&_elements[_size]) T(element);
  _size++;
  return *pointer;
}

template <typename T, typename Allocator>
T &vector<T, Allocator>::push(T &&element) {
  _ensure_capacity(_size + 1);
  T *pointer = new (&_elements[_size]) T(std::move(element));
  _size++;
  return *pointer;
}

template <typename T, typename Allocator>
size_t vector<T, Allocator>::append(const T &element) {
  _ensure_capacity(_size + 1);
  new (&_elements[_size]) T(element);
  return _size++;
}

template <typename T, typename Allocator>
size_t vector<T, Allocator>::append(T &&element) {
  _ensure_capacity(_size + 1);
  new (&_elements[_size]) T(std::move(element));
  return _size++;
}

template <typename T, typename Allocator>
template <typename... Args>
T &vector<T, Allocator>::emplace_back(Args &&...args) {
  _ensure_capacity(_size + 1);
  T *pointer = new (&_elements[_size]) T(std::forward<Args>(args)...);
  _size++;
  return *pointer;
}

template <typename T, typename Allocator>
template <typename... Args>
void vector<T, Allocator>::resize(size_t new_size, Args &&...args) {
  _ensure_capacity(new_size);
  if (new_size < _size) {
    for (size_t i = new_size; i < _size; i++)
      _elements[i].~T();
  } else {
    for (size_t i = _size; i < new_size; i++)
      new (&_elements[i]) T(std::forward<Args>(args)...);
  }
  _size = new_size;
}

template <typename T, typename Allocator>
void vector<T, Allocator>::_ensure_capacity(size_t capacity) {
  if (capacity <= _capacity)
    return;

  size_t new_capacity = capacity * 2;
  T *new_array = (T *)_allocator.allocate(sizeof(T) * new_capacity);
  for (size_t i = 0; i < _capacity; i++)
    new (&new_array[i]) T(std::move(_elements[i]));

  for (size_t i = 0; i < _size; i++)
    _elements[i].~T();
  _allocator.free(_elements);

  _elements = new_array;
  _capacity = new_capacity;
}

template <typename T, typename Allocator> T vector<T, Allocator>::pop() {
  _size--;
  T element = std::move(_elements[_size]);
  _elements[_size].~T();
  return element;
}

} // namespace frg FRG_VISIBILITY

#endif // FRG_VECTOR_HPP
