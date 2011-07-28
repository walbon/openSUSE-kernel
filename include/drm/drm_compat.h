/*
 * some compat hacks for drm-3.0 backports
 */

#ifndef __DRM_COMPAT_H
#define __DRM_COMPAT_H

#define FBINFO_CAN_FORCE_OUTPUT		0

#define in_dbg_master()		0

#define dma_set_coherent_mask(x, y) \
	((x)->coherent_dma_mask = (y))

#define noop_llseek		NULL

#define alloc_workqueue(name, flags, number) \
	create_singlethread_workqueue(name)

#include <linux/vmalloc.h>
static inline void *vzalloc(size_t size)
{
	void *p = vmalloc(size);
	if (p)
		memset(p, 0, size);
	return p;
}

#include <linux/kref.h>
static inline int kref_sub(struct kref *kref, unsigned int count,
			   void (*release) (struct kref *kref))
{
	if (atomic_sub_and_test((int) count, &kref->refcount)) {
		release(kref);
		return 1;
	}
	return 0;
}

#define acpi_os_ioremap(x, y)	ioremap(x, y)

#define abs64(x) ({				\
		s64 __x = (x);			\
		(__x < 0) ? -__x : __x;		\
	})

/* XXX */
#define flush_work_sync(x)	flush_work(x)

#define console_lock()		acquire_console_sem()
#define console_unlock()	release_console_sem()

#ifndef round_up
/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#endif

#define of_machine_is_compatible(x)	machine_is_compatible(x)

#endif /* __DRM_COMPAT_H */
