/*             Author: Benjamin David Lunt
 *                     Forever Young Software
 *                     Copyright (c) 1984-2022
 *  
 *  This code is donated to the Freeware communitee.  You have the
 *   right to use it for learning purposes only.  You may not modify it
 *   for redistribution for any other purpose unless you have written
 *   permission from the author.
 *
 *  You may modify and use it in your own projects as long as they are
 *   for non-profit only and if distributed, have these same requirements.
 *  Any project for profit that uses this code must have written 
 *   permission from the author.
 *
 *  For more information:
 *    http://www.fysnet.net/osdesign_book_series.htm
 *  Contact:
 *    fys [at] fysnet [dot] net
 *
 * Last update:  4 May 2022 (May the 4th be with you!)
 *  (What is the core temperature of a Tauntaun?  --  Luke warm)
 *
 */


#include <mm/pmm.hpp>
#include <mm/mm.hpp>

#include <util/string.hpp>
#include <util/lock.hpp>

#define ALLOC_MIN  (65536 + sizeof(memory_bucket) + sizeof(memory_pebble))
// magic value for a tag
#define MALLOC_MAGIC_BUCKET 'BUCK'
#define MALLOC_MAGIC_PEBBLE 'ROCK'

// local flags for a bucket (only applies to this bucket)
#define BUCKET_FLAG_FIRST   (0 <<  0)  // if clear, use first find method
#define BUCKET_FLAG_BEST    (1 <<  0)  // if set, use best fit method

// local flags for a pebble
#define PEBBLE_FLAG_FREE    (0 <<  0)  // if set, is in use, if clear, free for use
#define PEBBLE_FLAG_IN_USE  (1 <<  0)  //  ...


#define PEBBLE_MIN_ALIGN 64  // minimum power of 2 to align the next pebble (1 or a power of 2)
#define PEBBLE_MIN_SIZE  64  // a pebble must be at least this size
#if PEBBLE_MIN_SIZE > PEBBLE_MIN_ALIGN
  #error "PEBBLE_MIN_ALIGN must be at least PEBBLE_MIN_SIZE"
#endif

// macro to see if the free chunk is large enough to split
//                                 if ceil(current pebble size, 64)              >   new pebble size with a remainder < (sizeof(PEBBLE) + PEBBLE_MIN_SIZE)
#define SPLIT_PEBBLE(s0, s1) ((((s0) + PEBBLE_MIN_ALIGN - 1) & ~PEBBLE_MIN_SIZE) > ((s1) + sizeof(memory_pebble) + PEBBLE_MIN_SIZE))

#define PEBBLE_IS_FREE(p) (((p)->lflags & PEBBLE_FLAG_IN_USE) == PEBBLE_FLAG_FREE)

#define UPDATE_NODE(p0, p1)    \
 {                             \
    (p0)->next = (p1)->next;   \
    (p1)->next = (p0);         \
    (p0)->prev = (p1);         \
    if ((p0)->next)            \
      (p0)->next->prev = (p0); \
}

util::lock mm_lock{};
static void *kernel_heap = nullptr;

struct memory_pebble;
struct memory_bucket;

struct [[gnu::packed]] memory_bucket {
    uint32_t magic;     //  a bucket full of pebbles
    uint32_t lflags;    //  local flags for this bucket
    size_t size;      //  count of 4096 pages used for this bucket
    size_t largest;   //  largest free block in this bucket

  // linked list of buckets
    memory_bucket *prev;
    memory_bucket *next;

    memory_pebble *first;
};


struct [[gnu::packed]] memory_pebble {
    uint32_t magic;         // a pebble in a bucket
    uint32_t lflags;        // local flags for this pebble
    uint32_t sflags;        // sent flags for this pebble
    uint32_t padding;       // padding/alignment
    size_t size;          // count of bytes requested
    
    memory_bucket *parent; // parent bucket of this pebble

  // linked list of pebbles
    memory_pebble *prev;
    memory_pebble *next;
};

memory_bucket* create_bucket(size_t size);
memory_pebble *place_pebble(struct memory_bucket *bucket, struct memory_pebble *pebble);
memory_pebble *split_pebble(struct memory_pebble *pebble, size_t size);

// allocates a linear block of memory, in 'size' bytes, and creates
//  a Bucket for this block, with one (free) Pebble.
memory_bucket* create_bucket(size_t size) {  
  // size must be a even number of pages
  size = (size + (memory::page_size - 1)) & ~(memory::page_size - 1);

  memory_bucket* bucket = (memory_bucket* ) memory::pmm::alloc(size / memory::page_size);
  if (bucket != NULL) {
    bucket->magic = MALLOC_MAGIC_BUCKET;
    bucket->lflags = BUCKET_FLAG_FIRST;
    bucket->size = size / memory::page_size;  // count of pages used
    bucket->largest = size - sizeof(memory_bucket) - sizeof(memory_pebble);

    bucket->prev = NULL;  // these will be assigned by the insert_bucket() call
    bucket->next = NULL;
    
    memory_pebble* first = (memory_pebble* ) ((uint8_t *) bucket + sizeof(memory_bucket));
    bucket->first = first;

    first->magic = MALLOC_MAGIC_PEBBLE;
    first->sflags = 0;
    first->lflags = PEBBLE_FLAG_FREE;
    first->padding = 0;
    first->size = bucket->largest;

    first->parent = bucket;
    first->prev = NULL;
    first->next = NULL;
  }

  return bucket;
}

void memory::mm::init() {
    memory_bucket* bucket = create_bucket(page_size * 4);
    kernel_heap = bucket;
}

// insert a bucket at destination
void insert_bucket(memory_bucket* bucket, void *destination) {
  memory_bucket* dest = (memory_bucket* ) destination;

  if (bucket && dest)
    UPDATE_NODE(bucket, dest);
}

// remove a bucket
void remove_bucket(memory_bucket* bucket) {

  // don't remove the initial bucket
  if (bucket && (bucket != kernel_heap)) {
    if (bucket->prev)
      bucket->prev->next = bucket->next;
    if (bucket->next)
        bucket->next->prev = bucket->prev;
    memory::pmm::free(bucket);
  }
}

// run through the bucket and get the (possibly) new largest size
size_t bucket_update_largest(memory_bucket* bucket) {
  memory_pebble* p = bucket->first;
  size_t ret = 0;

  while (p != NULL) {
    if (p->size > ret)
      ret = p->size;
    p = p->next;
  }

  // update the value
  bucket->largest = ret;

  return ret;
}

// this takes an already created pebble and tries to place it in a bucket
// it is assumed that the caller has already checked that this bucket
//  isn't full and can hold the pebble, though we check nyway.
memory_pebble* place_pebble(memory_bucket *bucket, memory_pebble* pebble) {
  memory_pebble* start = bucket->first;
  memory_pebble* best = NULL;
  size_t best_size = -1;
  
  if (bucket->lflags & BUCKET_FLAG_BEST) {
    // -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // BEST FIT method
    // scroll through all the pebbles until we find a free one
    //  large enough to insert our pebble, but the least sized free
    //  entry that satisfies our request.
    while (start != NULL) {
      if (PEBBLE_IS_FREE(start) && (start->size <= pebble->size)) {
        if (start->size < best_size) {
          best = start;
          best_size = start->size;
        }
      }
      start = start->next;
    }
    // did we find one? Do we need to split it?
    if (best != NULL) {
      split_pebble(best, pebble->size);
      best->sflags = pebble->sflags;
      best->lflags = pebble->lflags;
    }
    start = best;
  } else {
    // -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    // FIRST FOUND method
    // scroll through the pebbles until we find a free one
    //  large enough to insert our pebble in.  First one found, we use.
    while (start != NULL) {
      if (PEBBLE_IS_FREE(start) && (start->size >= pebble->size)) {
        // we found one to use.  Do we need to split it?
        split_pebble(start, pebble->size);
        start->sflags = pebble->sflags;
        start->lflags = pebble->lflags;
        break;
      }
      start = start->next;
    }
  }

  return start;
}

// if the current pebble is large enough, will split a pebble into two
// else it returns NULL
memory_pebble* split_pebble(memory_pebble* pebble, size_t size) {
  memory_pebble* new_pebble = NULL;
  size_t new_size;
  
  if (SPLIT_PEBBLE(pebble->size, size)) {
    new_size = (size + (PEBBLE_MIN_ALIGN - 1)) & ~(PEBBLE_MIN_ALIGN - 1);
    new_pebble = (memory_pebble* ) ((uint8_t *) pebble + sizeof(memory_pebble) + new_size);
    memcpy(new_pebble, pebble, sizeof(memory_pebble));
    new_pebble->size = pebble->size - new_size - sizeof(memory_pebble);
    new_pebble->prev = pebble;
    pebble->size = new_size;
    pebble->next = new_pebble;
  }

  return new_pebble;
}

// if this pebble is empty *and* if present, the next one is empty,
//  then absorb the next one, into this one.
memory_pebble* absorb_next(memory_pebble* pebble) {
  if (pebble && pebble->next) {
    if (PEBBLE_IS_FREE(pebble) && PEBBLE_IS_FREE(pebble->next)) {
      if (pebble->parent->first == pebble->next)  // don't "delete" the Bucket->first pebble before we update it
        pebble->parent->first = pebble;
      pebble->size += pebble->next->size + sizeof(memory_pebble);
      pebble->next = pebble->next->next;
      if (pebble->next)
        pebble->next->prev = pebble;
      bucket_update_largest(pebble->parent);
    }
  }
  return pebble;
}

// if this pebble is empty, *and* if present the last one is empty,
//  then let the last one absorb this one.
memory_pebble* melt_prev(memory_pebble* pebble) {
  if (pebble && pebble->prev) {
    if (PEBBLE_IS_FREE(pebble) && PEBBLE_IS_FREE(pebble->prev)) {
      if (pebble->parent->first == pebble)  // don't "delete" the Bucket->first pebble before we update it
        pebble->parent->first = pebble->prev;
      pebble->prev->size += pebble->size + sizeof(memory_pebble);
      pebble->prev->next = pebble->next;
      if (pebble->next)
        pebble->next->prev = pebble->prev;
      pebble = pebble->prev;
      bucket_update_largest(pebble->parent);
    }
  }
  return pebble;
}

// shrink the pebble from the current size to a new smaller size
//  if the size is now small enough to split the pebble, we do it
memory_pebble* shrink_pebble(memory_pebble* pebble, size_t size) {
  memory_pebble* ret = NULL;

  if (pebble) {
    split_pebble(pebble, size);
    ret = pebble;
  }

  return ret;
}

void *kmalloc(size_t size) {
  void *ret = NULL;

  // minimum amount of memory we allocate to the caller
  if (size < PEBBLE_MIN_SIZE)
    size = PEBBLE_MIN_SIZE;

  memory_pebble pebble;
  pebble.magic = MALLOC_MAGIC_PEBBLE;
  pebble.sflags = 0;
  pebble.lflags = PEBBLE_FLAG_IN_USE;
  pebble.padding = 0;
  pebble.size = (size + (PEBBLE_MIN_ALIGN - 1)) & ~(PEBBLE_MIN_ALIGN - 1);

  mm_lock.irq_acquire();

  memory_bucket* bucket = (memory_bucket* ) kernel_heap;
  while (bucket != NULL) {
    if (bucket->largest >= pebble.size) {
      ret = place_pebble(bucket, &pebble);
      bucket_update_largest(bucket);
      if (ret != NULL)
        ret = (uint8_t *) ret + sizeof(memory_pebble);
      break;
    }
    bucket = bucket->next;
  }

  // if ret == NULL, we didn't find a bucket large enough, or with enough empty space.
  //  so allocate another bucket
  if (ret == NULL) {
    size_t new_size = pebble.size + (sizeof(memory_bucket) + sizeof(memory_pebble));
    bucket = create_bucket(new_size);
    if (bucket) {
      insert_bucket(bucket, kernel_heap);
      ret = place_pebble(bucket, &pebble);
      bucket_update_largest(bucket);
      if (ret != NULL)
        ret = (uint8_t *) ret + sizeof(memory_pebble);
    }
  }

  mm_lock.irq_release();

  // if we are to clear the memory, do it now
  if (ret)
    memset(ret, 0, size);
  
  return ret;
}

void *krealloc(void *ptr, size_t size) {
  memory_pebble* pebble;
  void *ret = NULL;
  
  if (size == 0) {
    kfree(ptr);
    return NULL;
  }
  
  if (ptr == NULL)
    return kmalloc(size);

  mm_lock.irq_acquire();

  pebble = (memory_pebble* ) ((uint8_t *) ptr - sizeof(memory_pebble));

  mm_lock.irq_release();

    if (size <= pebble->size)
        ret = shrink_pebble(pebble, size);
    else {
        ret = kmalloc(size);
        if (ret)
            memcpy(ret, ptr, size);
        kfree(ptr);
    }

  return ret;
}

// free a pebble, possibly merging it with a neighbor(s), and possible removing this
//  now empty Bucket.
void kfree(void *ptr) {
  if (ptr == NULL)
    return;

  mm_lock.irq_acquire();

  memory_pebble* pebble = (memory_pebble* ) ((uint8_t *) ptr - sizeof(memory_pebble));
  
  // check that it actually is a pebble
  if (pebble->magic != MALLOC_MAGIC_PEBBLE) {
    mm_lock.irq_release();
    return;
  }
  
  // mark it as free
  pebble->lflags = PEBBLE_FLAG_FREE;
  
  // see if we can absorb any of the neighbors
  pebble = melt_prev(pebble);
  absorb_next(pebble);

  // if this empties the bucket, shall we remove the bucket?
  memory_bucket* bucket = pebble->parent;
  if (PEBBLE_IS_FREE(bucket->first) && (bucket->first->prev == NULL) && (bucket->first->next == NULL))
    remove_bucket(bucket);
  else
    bucket_update_largest(bucket);
  
  mm_lock.irq_release();
}
