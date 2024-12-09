#include "frg/rbtree.hpp"
#include "frg/utility.hpp"
#include <mm/common.hpp>
#include <util/log/log.hpp>
#include <cstddef>
#include <cstdint>
#include <mm/mm.hpp>
#include <mm/pmm.hpp>
#include <util/lock.hpp>
#include <util/string.hpp>
#include <util/log/panic.hpp>

util::lock mm_lock{};

#define LIBALLOC_MAGIC	0xdeadbeef
#define MAXCOMPLETE		5
#define MAXEXP	32
#define MINEXP	8

#define MODE_BEST			0
#define MODE_INSTANT		1

#define MODE	MODE_BEST

struct boundary_tag {
	unsigned int magic;			//< It's a kind of ...
    size_t size; 			//< Requested size.
    size_t real_size;		//< Actual size.
	int index;					//< Location in the page table.

	boundary_tag *split_left;	//< Linked-list info for broken pages.
	boundary_tag *split_right;	//< The same.

	boundary_tag *next;	//< Linked list info.
	boundary_tag *prev;	//< Linked list info.
};

boundary_tag* l_freePages[MAXEXP];		//< Allowing for 2^MAXEXP blocks
size_t 				 l_completePages[MAXEXP];	//< Allowing for 2^MAXEXP blocks

static int l_initialized = 0;			//< Flag to indicate initialization.
static int l_pageSize  = 4096;			//< Individual page size
static int l_pageCount = 16;			//< Minimum number of pages to allocate.

static inline int getexp( unsigned int size ) {
	if ( size < (1<<MINEXP) ) {
		return -1;	// Smaller than the quantum.
	}

	int shift = MINEXP;
	while ( shift < MAXEXP ) {
		if ( (1<<shift) > size ) break;
		shift += 1;
	}

	return shift - 1;
}

static inline void insert_tag(boundary_tag *tag, int index ) {
	int realIndex;

	if ( index < 0 ) {
		realIndex = getexp( tag->real_size - sizeof(boundary_tag) );
		if ( realIndex < MINEXP ) realIndex = MINEXP;
	} else
		realIndex = index;

	tag->index = realIndex;
	if ( l_freePages[ realIndex ] != NULL ) {
		l_freePages[ realIndex ]->prev = tag;
		tag->next = l_freePages[ realIndex ];
	}

	l_freePages[ realIndex ] = tag;
}


static inline void remove_tag(boundary_tag *tag ) {
	if ( l_freePages[ tag->index ] == tag ) l_freePages[ tag->index ] = tag->next;
	if ( tag->prev != NULL ) tag->prev->next = tag->next;
	if ( tag->next != NULL ) tag->next->prev = tag->prev;
	tag->next = NULL;
	tag->prev = NULL;
	tag->index = -1;
}

static inline boundary_tag* melt_left(boundary_tag *tag ) {
	boundary_tag *left = tag->split_left;
	left->real_size   += tag->real_size;
	left->split_right  = tag->split_right;
	if ( tag->split_right != NULL ) tag->split_right->split_left = left;

	return left;
}


static inline boundary_tag* absorb_right(boundary_tag *tag ) {
	boundary_tag *right = tag->split_right;
    remove_tag( right );		// Remove right from free pages.
    tag->real_size   += right->real_size;
    tag->split_right  = right->split_right;
    if ( right->split_right != NULL )
                right->split_right->split_left = tag;
	return tag;
}

static inline boundary_tag* split_tag( boundary_tag* tag ) {
	unsigned int remainder = tag->real_size - sizeof(boundary_tag) - tag->size;

	boundary_tag *new_tag = (boundary_tag*)((uintptr_t) tag + sizeof(boundary_tag) + tag->size);

    new_tag->magic = LIBALLOC_MAGIC;
    new_tag->real_size = remainder;
    new_tag->next = NULL;
    new_tag->prev = NULL;
    new_tag->split_left = tag;
    new_tag->split_right = tag->split_right;

    if (new_tag->split_right != NULL) new_tag->split_right->split_left = new_tag;
    tag->split_right = new_tag;
    tag->real_size -= new_tag->real_size;
    insert_tag( new_tag, -1 );

	return new_tag;
}

static boundary_tag* allocate_new_tag( unsigned int size ) {
	unsigned int pages;
	unsigned int usage;
	boundary_tag *tag;

    // This is how much space is required.
    usage  = size + sizeof(boundary_tag);

            // Perfect amount of space
    pages = usage / l_pageSize;
    if ( (usage % l_pageSize) != 0 ) pages += 1;

    // Make sure it's >= the minimum size.
    if ( pages < l_pageCount ) pages = l_pageCount;

    tag = (boundary_tag*) memory::pmm::alloc(pages);

    if ( tag == NULL ) return NULL;	// uh oh, we ran out of memory.

    tag->magic 		= LIBALLOC_MAGIC;
    tag->size 		= size;
    tag->real_size 	= pages * l_pageSize;
    tag->index 		= -1;

    tag->next		= NULL;
    tag->prev		= NULL;
    tag->split_left 	= NULL;
    tag->split_right 	= NULL;

    return tag;
}

void *liballoc_malloc(size_t size) {
	int index;
	void *ptr;
	boundary_tag *tag = NULL;

	mm_lock.irq_acquire();

    if ( l_initialized == 0 ) {
        for ( index = 0; index < MAXEXP; index++ ) {
            l_freePages[index] = NULL;
            l_completePages[index] = 0;
        }
        l_initialized = 1;
    }

    index = getexp( size ) + MODE;
    if ( index < MINEXP ) index = MINEXP;


// Find one big enough.
    tag = l_freePages[ index ];				// Start at the front of the list.
    while ( tag != NULL ) {
            // If there's enough space in this tag.
        if ( (tag->real_size - sizeof(boundary_tag))
                        >= (size + sizeof(boundary_tag) ) ) {
            break;
        }

        tag = tag->next;
    }


    // No page found. Make one.
    if ( tag == NULL ) {
        if ( (tag = allocate_new_tag( size )) == NULL ) {
            mm_lock.irq_release();;
            return NULL;
        }

        index = getexp( tag->real_size - sizeof(boundary_tag) );
    } else {
        remove_tag( tag );

        if ( (tag->split_left == NULL) && (tag->split_right == NULL) )
            l_completePages[ index ] -= 1;
    }

    // We have a free page.  Remove it from the free pages list.

    tag->size = size;

    // Removed... see if we can re-use the excess space.

    unsigned int remainder = tag->real_size - size - sizeof( boundary_tag ) * 2; // Support a new tag + remainder

    if ( ((int)(remainder) > 0) /*&& ( (tag->real_size - remainder) >= (1<<MINEXP))*/ ) {
        int childIndex = getexp( remainder );

        if ( childIndex >= 0 ) {
            split_tag( tag );
        }
    }

	ptr = (void*)((uintptr_t) tag + sizeof( boundary_tag ) );

	mm_lock.irq_release();
	return ptr;
}

void liballoc_free(void *ptr) {
	int index;
	boundary_tag *tag;

	if ( ptr == NULL ) return;

	mm_lock.irq_acquire();

    tag = (boundary_tag*)((uintptr_t)ptr - sizeof( boundary_tag ));

    if ( tag->magic != LIBALLOC_MAGIC ) {
        mm_lock.irq_release();		// release the lock
        return;
    }

    // MELT LEFT...
    while ( (tag->split_left != NULL) && (tag->split_left->index >= 0) ) {
        tag = melt_left( tag );
        remove_tag( tag );
    }

    // MELT RIGHT...
    while ( (tag->split_right != NULL) && (tag->split_right->index >= 0) ) {
        tag = absorb_right( tag );
    }


    // Where is it going back to?
    index = getexp( tag->real_size - sizeof(boundary_tag) );
    if ( index < MINEXP ) index = MINEXP;

    // A whole, empty block?
    if ( (tag->split_left == NULL) && (tag->split_right == NULL) ) {
        if ( l_completePages[ index ] == MAXCOMPLETE ) {
            // Too many standing by to keep. Free this one.
            unsigned int pages = tag->real_size / l_pageSize;

            if ( (tag->real_size % l_pageSize) != 0 ) pages += 1;
            if ( pages < l_pageCount ) pages = l_pageCount;

            memory::pmm::free(tag);
            mm_lock.irq_release();
            return;
        }
        l_completePages[ index ] += 1;	// Increase the count of complete pages.
    }

	// ..........
	insert_tag( tag, index );
	mm_lock.irq_release();
}

void* liballoc_calloc(size_t nobj, size_t size) {
    int real_size;
    void *p;

    real_size = nobj * size;    
    p = liballoc_malloc( real_size );
    memset( p, 0, real_size );

    return p;
}

void* liballoc_realloc(void *p, size_t size) {
	void *ptr;
	struct boundary_tag *tag;
	int real_size;
	
	if ( size == 0 ) {
		liballoc_free( p );
		return NULL;
	}

	if ( p == NULL ) return liballoc_malloc( size );
	mm_lock.irq_acquire();

    tag = (struct boundary_tag*)((uintptr_t)p - sizeof( struct boundary_tag ));
    real_size = tag->size;

	mm_lock.irq_release();

	if ( real_size > size ) real_size = size;

	ptr = liballoc_malloc( size );
	memcpy( ptr, p, real_size );
	liballoc_free( p );

	return ptr;
}

namespace memory::mm::allocator {
    void *malloc(size_t req_size) {
        return liballoc_malloc(req_size);
    }

    void free(void *ptr) {
        return liballoc_free(ptr);
    }

    void *calloc(size_t nr_items, size_t size) {
        return liballoc_calloc(nr_items, size);
    }
}