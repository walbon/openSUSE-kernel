/** linux/prefetch_config.h
 * used by linux/prefetch.h
 *
 * The list of rules that determines whether list_prefetch should do
 * prefetching at all LIST_PREFETCH_NONE vs. LIST_PREFETCH.
 * This defermines the behavior of list_prefetch(x).
 *
 * If it does prefetching (LIST_PREFETCH defined), is can also decide
 * whether null pointers should be tested for and treated special with
 * list_prefetch_nonnull(x):
 * Always prefetch unconditionally (LIST_PREFETCH_UNCOND)
 * prefetching only nonnull ptr with a branch (LIST_PREFETCH_BRANCH)
 * prefetching only nonnull ptr with a cond move (LIST_PREFETCH_CMOV)
 * if there's a risk for NULL ptr, don't prefetch (LIST_PREFETCH_NEVERNULL)
 */

#ifndef _LINUX_PREFETCH_CONFIG_H
#define _LINUX_PREFETCH_CONFIG_H

//#include <linux/autoconf.h>

/* The rules here can become rather complex and be optimized for CPU types
 * testing the CONFIG_Mxxx symboles.
 */

#ifdef __i386__
# define LIST_PREFETCH
# define LIST_PREFETCH_BRANCH
#elif defined(__x86_64__)
# define LIST_PREFETCH_NONE
//#define LIST_PREFETCH_BRANCH
#else
# define LIST_PREFETCH
# define LIST_PREFETCH_CMOV
#endif

#endif
