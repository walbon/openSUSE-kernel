/*
 *  Generic cache management functions. Everything is arch-specific,  
 *  but this header exists to make sure the defines/functions can be
 *  used in a generic way.
 *
 *  2000-11-13  Arjan van de Ven   <arjan@fenrus.demon.nl>
 *
 */

#ifndef _LINUX_PREFETCH_H
#define _LINUX_PREFETCH_H

#include <linux/types.h>
#include <asm/processor.h>
#include <asm/cache.h>

/*
	prefetch(x) attempts to pre-emptively get the memory pointed to
	by address "x" into the CPU L1 cache. 
	prefetch(x) should not cause any kind of exception, prefetch(0) is
	specifically ok.

	prefetch() should be defined by the architecture, if not, the 
	#define below provides a no-op define.	
	
	There are 3 prefetch() macros:
	
	prefetch(x)  	- prefetches the cacheline at "x" for read
	prefetchw(x)	- prefetches the cacheline at "x" for write
	spin_lock_prefetch(x) - prefetches the spinlock *x for taking
	
	there is also PREFETCH_STRIDE which is the architecure-prefered 
	"lookahead" size for prefetching streamed operations.
	
*/

#ifndef ARCH_HAS_PREFETCH
#define prefetch(x) __builtin_prefetch(x)
#endif

#ifndef ARCH_HAS_PREFETCHW
#define prefetchw(x) __builtin_prefetch(x,1)
#endif

#ifndef ARCH_HAS_SPINLOCK_PREFETCH
#define spin_lock_prefetch(x) prefetchw(x)
#endif

#ifndef PREFETCH_STRIDE
#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)
#endif

/*
 * Prefetch for list pointer chasing. The architecture defines this
 * if it believes list prefetches are a good idea on the particular CPU.
 */
#include <linux/prefetch_config.h>
#ifdef LIST_PREFETCH_NONE	/* No prefetching for lists */
#define list_prefetch(x) ((void)0)
#define list_prefetch_nonnull(x) ((void)0)
#elif defined(LIST_PREFETCH)	/* Do prefetching of list elements */
#define	list_prefetch(x) prefetch(x)
#ifdef LIST_PREFETCH_UNCOND		/* Never mind about a NULL prefetch */
#define	list_prefetch_nonnull(x) prefetch(x)
#elif defined(LIST_PREFETCH_BRANCH)	/* Avoid NULL prefetch (TLB miss ...) */
#define	list_prefetch_nonnull(x) if (likely(x)) prefetch(x)
#elif defined(LIST_PREFETCH_CMOV)	/* Avoid NULL prefetch hoping compiler will use cond move instead of branch */
#define	list_prefetch_nonnull(x) prefetch((void*)(x)?: (void*)&(x))
#elif defined(LIST_PREFETCH_NEVERNULL)	/* NULL prefetch, branch or cond move are all too expensive */
#define list_prefetch_nonnull(x) ((void)0)
#else
#error LIST_PREFETCH_UNCOND, _BRANCH, _CMOV, or _NEVERNULL needs to be defined
#endif
#else
#warn LIST_PREFETCH_NONE or LIST_PREFETCH needs to be defined. Defaulting to unconditional prefetch.
define list_prefetch(x) prefetch(x)
define list_prefetch_nonnull(x) prefetch(x)
#endif

static inline void prefetch_range(void *addr, size_t len)
{
#ifdef ARCH_HAS_PREFETCH
	char *cp;
	char *end = addr + len;

	for (cp = addr; cp < end; cp += PREFETCH_STRIDE)
		prefetch(cp);
#endif
}

#endif
