/*
 * address space "slices" (meta-segments) support
 *
 * Copyright (C) 2007 Benjamin Herrenschmidt, IBM Corporation.
 *
 * Based on hugetlb implementation
 *
 * Copyright (C) 2003 David Gibson, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#undef DEBUG

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <asm/mman.h>
#include <asm/mmu.h>
#include <asm/spu.h>

static DEFINE_SPINLOCK(slice_convert_lock);
#ifndef CONFIG_BIGMEM

#else
/*
 * One bit per slice. We have lower slices which cover 256MB segments
 * upto 4G range. That gets us 16 low slices. For the rest we track slices
 * in 1TB size.
 */
struct slice_mask {
	u64 low_slices;
	DECLARE_BITMAP(high_slices, SLICE_NUM_HIGH);
};
#endif

#ifdef DEBUG
int _slice_debug = 1;

static void slice_print_mask(const char *label, struct slice_mask mask)
{
#ifndef CONFIG_BIGMEM
	char	*p, buf[16 + 3 + 16 + 1];
	int	i;

#endif
	if (!_slice_debug)
		return;
#ifndef CONFIG_BIGMEM
	p = buf;
	for (i = 0; i < SLICE_NUM_LOW; i++)
		*(p++) = (mask.low_slices & (1 << i)) ? '1' : '0';
	*(p++) = ' ';
	*(p++) = '-';
	*(p++) = ' ';
	for (i = 0; i < SLICE_NUM_HIGH; i++)
		*(p++) = (mask.high_slices & (1 << i)) ? '1' : '0';
	*(p++) = 0;

	printk(KERN_DEBUG "%s:%s\n", label, buf);
#else
	pr_devel("%s low_slice: %*pbl\n", label, (int)SLICE_NUM_LOW, &mask.low_slices);
	pr_devel("%s high_slice: %*pbl\n", label, (int)SLICE_NUM_HIGH, mask.high_slices);
#endif
}

#ifndef CONFIG_BIGMEM
#define slice_dbg(fmt...) do { if (_slice_debug) pr_debug(fmt); } while(0)
#else
#define slice_dbg(fmt...) do { if (_slice_debug) pr_devel(fmt); } while (0)
#endif

#else

static void slice_print_mask(const char *label, struct slice_mask mask) {}
#define slice_dbg(fmt...)

#endif

#ifndef CONFIG_BIGMEM
static struct slice_mask slice_range_to_mask(unsigned long start,
					     unsigned long len)
#else
static void slice_range_to_mask(unsigned long start, unsigned long len,
				struct slice_mask *ret)
#endif
{
	unsigned long end = start + len - 1;
#ifndef CONFIG_BIGMEM
	struct slice_mask ret = { 0, 0 };
#else

	ret->low_slices = 0;
	bitmap_zero(ret->high_slices, SLICE_NUM_HIGH);
#endif

	if (start < SLICE_LOW_TOP) {
#ifndef CONFIG_BIGMEM
		unsigned long mend = min(end, SLICE_LOW_TOP);
		unsigned long mstart = min(start, SLICE_LOW_TOP);
#else
		unsigned long mend = min(end, (SLICE_LOW_TOP - 1));
#endif

#ifndef CONFIG_BIGMEM
		ret.low_slices = (1u << (GET_LOW_SLICE_INDEX(mend) + 1))
			- (1u << GET_LOW_SLICE_INDEX(mstart));
#else
		ret->low_slices = (1u << (GET_LOW_SLICE_INDEX(mend) + 1))
			- (1u << GET_LOW_SLICE_INDEX(start));
#endif
	}

#ifndef CONFIG_BIGMEM
	if ((start + len) > SLICE_LOW_TOP)
		ret.high_slices = (1u << (GET_HIGH_SLICE_INDEX(end) + 1))
			- (1u << GET_HIGH_SLICE_INDEX(start));
#else
	if ((start + len) > SLICE_LOW_TOP) {
		unsigned long start_index = GET_HIGH_SLICE_INDEX(start);
		unsigned long align_end = ALIGN(end, (1UL << SLICE_HIGH_SHIFT));
		unsigned long count = GET_HIGH_SLICE_INDEX(align_end) - start_index;
#endif

#ifndef CONFIG_BIGMEM
	return ret;
#else
		bitmap_set(ret->high_slices, start_index, count);
	}
#endif
}

static int slice_area_is_free(struct mm_struct *mm, unsigned long addr,
			      unsigned long len)
{
	struct vm_area_struct *vma;

	if ((mm->task_size - len) < addr)
		return 0;
	vma = find_vma(mm, addr);
	return (!vma || (addr + len) <= vma->vm_start);
}

static int slice_low_has_vma(struct mm_struct *mm, unsigned long slice)
{
	return !slice_area_is_free(mm, slice << SLICE_LOW_SHIFT,
				   1ul << SLICE_LOW_SHIFT);
}

static int slice_high_has_vma(struct mm_struct *mm, unsigned long slice)
{
	unsigned long start = slice << SLICE_HIGH_SHIFT;
	unsigned long end = start + (1ul << SLICE_HIGH_SHIFT);

	/* Hack, so that each addresses is controlled by exactly one
	 * of the high or low area bitmaps, the first high area starts
	 * at 4GB, not 0 */
	if (start == 0)
		start = SLICE_LOW_TOP;

	return !slice_area_is_free(mm, start, end - start);
}

#ifndef CONFIG_BIGMEM
static struct slice_mask slice_mask_for_free(struct mm_struct *mm)
#else
static void slice_mask_for_free(struct mm_struct *mm, struct slice_mask *ret)
#endif
{
#ifndef CONFIG_BIGMEM
	struct slice_mask ret = { 0, 0 };
#endif
	unsigned long i;

#ifdef CONFIG_BIGMEM
	ret->low_slices = 0;
	bitmap_zero(ret->high_slices, SLICE_NUM_HIGH);

#endif
	for (i = 0; i < SLICE_NUM_LOW; i++)
		if (!slice_low_has_vma(mm, i))
#ifndef CONFIG_BIGMEM
			ret.low_slices |= 1u << i;
#else
			ret->low_slices |= 1u << i;
#endif

	if (mm->task_size <= SLICE_LOW_TOP)
#ifndef CONFIG_BIGMEM
		return ret;
#else
		return;
#endif

	for (i = 0; i < SLICE_NUM_HIGH; i++)
		if (!slice_high_has_vma(mm, i))
#ifndef CONFIG_BIGMEM
			ret.high_slices |= 1u << i;

	return ret;
#else
			__set_bit(i, ret->high_slices);
#endif
}

#ifndef CONFIG_BIGMEM
static struct slice_mask slice_mask_for_size(struct mm_struct *mm, int psize)
#else
static void slice_mask_for_size(struct mm_struct *mm, int psize, struct slice_mask *ret)
#endif
{
#ifndef CONFIG_BIGMEM
	struct slice_mask ret = { 0, 0 };
#else
	unsigned char *hpsizes;
	int index, mask_index;
#endif
	unsigned long i;
#ifndef CONFIG_BIGMEM
	u64 psizes;
#else
	u64 lpsizes;
#endif

#ifndef CONFIG_BIGMEM
	psizes = mm->context.low_slices_psize;
	for (i = 0; i < SLICE_NUM_LOW; i++)
		if (((psizes >> (i * 4)) & 0xf) == psize)
			ret.low_slices |= 1u << i;
#else
	ret->low_slices = 0;
	bitmap_zero(ret->high_slices, SLICE_NUM_HIGH);
#endif

#ifndef CONFIG_BIGMEM
	psizes = mm->context.high_slices_psize;
	for (i = 0; i < SLICE_NUM_HIGH; i++)
		if (((psizes >> (i * 4)) & 0xf) == psize)
			ret.high_slices |= 1u << i;
#else
	lpsizes = mm->context.low_slices_psize;
	for (i = 0; i < SLICE_NUM_LOW; i++)
		if (((lpsizes >> (i * 4)) & 0xf) == psize)
			ret->low_slices |= 1u << i;
#endif

#ifndef CONFIG_BIGMEM
	return ret;
#else
	hpsizes = mm->context.high_slices_psize;
	for (i = 0; i < SLICE_NUM_HIGH; i++) {
		mask_index = i & 0x1;
		index = i >> 1;
		if (((hpsizes[index] >> (mask_index * 4)) & 0xf) == psize)
			__set_bit(i, ret->high_slices);
	}
#endif
}

static int slice_check_fit(struct slice_mask mask, struct slice_mask available)
{
#ifdef CONFIG_BIGMEM
	DECLARE_BITMAP(result, SLICE_NUM_HIGH);

	bitmap_and(result, mask.high_slices,
		   available.high_slices, SLICE_NUM_HIGH);

#endif
	return (mask.low_slices & available.low_slices) == mask.low_slices &&
#ifndef CONFIG_BIGMEM
		(mask.high_slices & available.high_slices) == mask.high_slices;
#else
		bitmap_equal(result, mask.high_slices, SLICE_NUM_HIGH);
#endif
}

static void slice_flush_segments(void *parm)
{
	struct mm_struct *mm = parm;
	unsigned long flags;

	if (mm != current->active_mm)
		return;

	/* update the paca copy of the context struct */
	get_paca()->context = current->active_mm->context;

	local_irq_save(flags);
	slb_flush_and_rebolt();
	local_irq_restore(flags);
}

static void slice_convert(struct mm_struct *mm, struct slice_mask mask, int psize)
{
#ifdef CONFIG_BIGMEM
	int index, mask_index;
#endif
	/* Write the new slice psize bits */
#ifndef CONFIG_BIGMEM
	u64 lpsizes, hpsizes;
#else
	unsigned char *hpsizes;
	u64 lpsizes;
#endif
	unsigned long i, flags;

	slice_dbg("slice_convert(mm=%p, psize=%d)\n", mm, psize);
	slice_print_mask(" mask", mask);

	/* We need to use a spinlock here to protect against
	 * concurrent 64k -> 4k demotion ...
	 */
	spin_lock_irqsave(&slice_convert_lock, flags);

	lpsizes = mm->context.low_slices_psize;
	for (i = 0; i < SLICE_NUM_LOW; i++)
		if (mask.low_slices & (1u << i))
			lpsizes = (lpsizes & ~(0xful << (i * 4))) |
				(((unsigned long)psize) << (i * 4));

#ifndef CONFIG_BIGMEM
	hpsizes = mm->context.high_slices_psize;
	for (i = 0; i < SLICE_NUM_HIGH; i++)
		if (mask.high_slices & (1u << i))
			hpsizes = (hpsizes & ~(0xful << (i * 4))) |
				(((unsigned long)psize) << (i * 4));

#else
	/* Assign the value back */
#endif
	mm->context.low_slices_psize = lpsizes;
#ifndef CONFIG_BIGMEM
	mm->context.high_slices_psize = hpsizes;
#else

	hpsizes = mm->context.high_slices_psize;
	for (i = 0; i < SLICE_NUM_HIGH; i++) {
		mask_index = i & 0x1;
		index = i >> 1;
		if (test_bit(i, mask.high_slices))
			hpsizes[index] = (hpsizes[index] &
					  ~(0xf << (mask_index * 4))) |
				(((unsigned long)psize) << (mask_index * 4));
	}
#endif

	slice_dbg(" lsps=%lx, hsps=%lx\n",
#ifndef CONFIG_BIGMEM
		  mm->context.low_slices_psize,
		  mm->context.high_slices_psize);
#else
		  (unsigned long)mm->context.low_slices_psize,
		  (unsigned long)mm->context.high_slices_psize);
#endif

	spin_unlock_irqrestore(&slice_convert_lock, flags);

#ifdef CONFIG_SPU_BASE
	spu_flush_all_slbs(mm);
#endif
}

static unsigned long slice_find_area_bottomup(struct mm_struct *mm,
					      unsigned long len,
					      struct slice_mask available,
					      int psize, int use_cache)
{
	struct vm_area_struct *vma;
	unsigned long start_addr, addr;
	struct slice_mask mask;
	int pshift = max_t(int, mmu_psize_defs[psize].shift, PAGE_SHIFT);

	if (use_cache) {
		if (len <= mm->cached_hole_size) {
			start_addr = addr = TASK_UNMAPPED_BASE;
			mm->cached_hole_size = 0;
		} else
			start_addr = addr = mm->free_area_cache;
	} else
		start_addr = addr = TASK_UNMAPPED_BASE;

full_search:
	for (;;) {
		addr = _ALIGN_UP(addr, 1ul << pshift);
		if ((TASK_SIZE - len) < addr)
			break;
		vma = find_vma(mm, addr);
		BUG_ON(vma && (addr >= vma->vm_end));

#ifndef CONFIG_BIGMEM
		mask = slice_range_to_mask(addr, len);
#else
		slice_range_to_mask(addr, len, &mask);
#endif
		if (!slice_check_fit(mask, available)) {
			if (addr < SLICE_LOW_TOP)
				addr = _ALIGN_UP(addr + 1,  1ul << SLICE_LOW_SHIFT);
			else
				addr = _ALIGN_UP(addr + 1,  1ul << SLICE_HIGH_SHIFT);
			continue;
		}
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
			if (use_cache)
				mm->free_area_cache = addr + len;
			return addr;
		}
		if (use_cache && (addr + mm->cached_hole_size) < vma->vm_start)
		        mm->cached_hole_size = vma->vm_start - addr;
		addr = vma->vm_end;
	}

	/* Make sure we didn't miss any holes */
	if (use_cache && start_addr != TASK_UNMAPPED_BASE) {
		start_addr = addr = TASK_UNMAPPED_BASE;
		mm->cached_hole_size = 0;
		goto full_search;
	}
	return -ENOMEM;
}

static unsigned long slice_find_area_topdown(struct mm_struct *mm,
					     unsigned long len,
					     struct slice_mask available,
					     int psize, int use_cache)
{
	struct vm_area_struct *vma;
	unsigned long addr;
	struct slice_mask mask;
	int pshift = max_t(int, mmu_psize_defs[psize].shift, PAGE_SHIFT);

	/* check if free_area_cache is useful for us */
	if (use_cache) {
		if (len <= mm->cached_hole_size) {
			mm->cached_hole_size = 0;
			mm->free_area_cache = mm->mmap_base;
		}

		/* either no address requested or can't fit in requested
		 * address hole
		 */
		addr = mm->free_area_cache;

		/* make sure it can fit in the remaining address space */
		if (addr > len) {
			addr = _ALIGN_DOWN(addr - len, 1ul << pshift);
#ifndef CONFIG_BIGMEM
			mask = slice_range_to_mask(addr, len);
#else
			slice_range_to_mask(addr, len, &mask);
#endif
			if (slice_check_fit(mask, available) &&
			    slice_area_is_free(mm, addr, len))
					/* remember the address as a hint for
					 * next time
					 */
					return (mm->free_area_cache = addr);
		}
	}

	addr = mm->mmap_base;
	while (addr > len) {
		/* Go down by chunk size */
		addr = _ALIGN_DOWN(addr - len, 1ul << pshift);

		/* Check for hit with different page size */
#ifndef CONFIG_BIGMEM
		mask = slice_range_to_mask(addr, len);
#else
		slice_range_to_mask(addr, len, &mask);
#endif
		if (!slice_check_fit(mask, available)) {
			if (addr < SLICE_LOW_TOP)
				addr = _ALIGN_DOWN(addr, 1ul << SLICE_LOW_SHIFT);
			else if (addr < (1ul << SLICE_HIGH_SHIFT))
				addr = SLICE_LOW_TOP;
			else
				addr = _ALIGN_DOWN(addr, 1ul << SLICE_HIGH_SHIFT);
			continue;
		}

		/*
		 * Lookup failure means no vma is above this address,
		 * else if new region fits below vma->vm_start,
		 * return with success:
		 */
		vma = find_vma(mm, addr);
		if (!vma || (addr + len) <= vma->vm_start) {
			/* remember the address as a hint for next time */
			if (use_cache)
				mm->free_area_cache = addr;
			return addr;
		}

		/* remember the largest hole we saw so far */
		if (use_cache && (addr + mm->cached_hole_size) < vma->vm_start)
		        mm->cached_hole_size = vma->vm_start - addr;

		/* try just below the current vma->vm_start */
		addr = vma->vm_start;
	}

	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	addr = slice_find_area_bottomup(mm, len, available, psize, 0);

	/*
	 * Restore the topdown base:
	 */
	if (use_cache) {
		mm->free_area_cache = mm->mmap_base;
		mm->cached_hole_size = ~0UL;
	}

	return addr;
}


static unsigned long slice_find_area(struct mm_struct *mm, unsigned long len,
				     struct slice_mask mask, int psize,
				     int topdown, int use_cache)
{
	if (topdown)
		return slice_find_area_topdown(mm, len, mask, psize, use_cache);
	else
		return slice_find_area_bottomup(mm, len, mask, psize, use_cache);
}

#ifndef CONFIG_BIGMEM
#define or_mask(dst, src)	do {			\
	(dst).low_slices |= (src).low_slices;		\
	(dst).high_slices |= (src).high_slices;		\
} while (0)
#else
static inline void slice_or_mask(struct slice_mask *dst, struct slice_mask *src)
{
	DECLARE_BITMAP(result, SLICE_NUM_HIGH);
#endif

#ifndef CONFIG_BIGMEM
#define andnot_mask(dst, src)	do {			\
	(dst).low_slices &= ~(src).low_slices;		\
	(dst).high_slices &= ~(src).high_slices;	\
} while (0)
#else
	dst->low_slices |= src->low_slices;
	bitmap_or(result, dst->high_slices, src->high_slices, SLICE_NUM_HIGH);
	bitmap_copy(dst->high_slices, result, SLICE_NUM_HIGH);
}

static inline void slice_andnot_mask(struct slice_mask *dst, struct slice_mask *src)
{
	DECLARE_BITMAP(result, SLICE_NUM_HIGH);

	dst->low_slices &= ~src->low_slices;

	bitmap_andnot(result, dst->high_slices, src->high_slices, SLICE_NUM_HIGH);
	bitmap_copy(dst->high_slices, result, SLICE_NUM_HIGH);
}
#endif

#ifdef CONFIG_PPC_64K_PAGES
#define MMU_PAGE_BASE	MMU_PAGE_64K
#else
#define MMU_PAGE_BASE	MMU_PAGE_4K
#endif

unsigned long slice_get_unmapped_area(unsigned long addr, unsigned long len,
				      unsigned long flags, unsigned int psize,
				      int topdown, int use_cache)
{
#ifndef CONFIG_BIGMEM
	struct slice_mask mask = {0, 0};
#else
	struct slice_mask mask;
#endif
	struct slice_mask good_mask;
#ifndef CONFIG_BIGMEM
	struct slice_mask potential_mask = {0,0} /* silence stupid warning */;
	struct slice_mask compat_mask = {0, 0};
#else
	struct slice_mask potential_mask;
	struct slice_mask compat_mask;
#endif
	int fixed = (flags & MAP_FIXED);
	int pshift = max_t(int, mmu_psize_defs[psize].shift, PAGE_SHIFT);
	struct mm_struct *mm = current->mm;
	unsigned long newaddr;

#ifdef CONFIG_BIGMEM
	/*
	 * init different masks
	 */
	mask.low_slices = 0;
	bitmap_zero(mask.high_slices, SLICE_NUM_HIGH);

	/* silence stupid warning */;
	potential_mask.low_slices = 0;
	bitmap_zero(potential_mask.high_slices, SLICE_NUM_HIGH);

	compat_mask.low_slices = 0;
	bitmap_zero(compat_mask.high_slices, SLICE_NUM_HIGH);

#endif
	/* Sanity checks */
	BUG_ON(mm->task_size == 0);

	slice_dbg("slice_get_unmapped_area(mm=%p, psize=%d...\n", mm, psize);
	slice_dbg(" addr=%lx, len=%lx, flags=%lx, topdown=%d, use_cache=%d\n",
		  addr, len, flags, topdown, use_cache);

	if (len > mm->task_size)
		return -ENOMEM;
	if (len & ((1ul << pshift) - 1))
		return -EINVAL;
	if (fixed && (addr & ((1ul << pshift) - 1)))
		return -EINVAL;
	if (fixed && addr > (mm->task_size - len))
		return -ENOMEM;

	/* If hint, make sure it matches our alignment restrictions */
	if (!fixed && addr) {
		addr = _ALIGN_UP(addr, 1ul << pshift);
		slice_dbg(" aligned addr=%lx\n", addr);
		/* Ignore hint if it's too large or overlaps a VMA */
		if (addr > mm->task_size - len ||
		    !slice_area_is_free(mm, addr, len))
			addr = 0;
	}

	/* First make up a "good" mask of slices that have the right size
	 * already
	 */
#ifndef CONFIG_BIGMEM
	good_mask = slice_mask_for_size(mm, psize);
#else
	slice_mask_for_size(mm, psize, &good_mask);
#endif
	slice_print_mask(" good_mask", good_mask);

	/*
	 * Here "good" means slices that are already the right page size,
	 * "compat" means slices that have a compatible page size (i.e.
	 * 4k in a 64k pagesize kernel), and "free" means slices without
	 * any VMAs.
	 *
	 * If MAP_FIXED:
	 *	check if fits in good | compat => OK
	 *	check if fits in good | compat | free => convert free
	 *	else bad
	 * If have hint:
	 *	check if hint fits in good => OK
	 *	check if hint fits in good | free => convert free
	 * Otherwise:
	 *	search in good, found => OK
	 *	search in good | free, found => convert free
	 *	search in good | compat | free, found => convert free.
	 */

#ifdef CONFIG_PPC_64K_PAGES
	/* If we support combo pages, we can allow 64k pages in 4k slices */
	if (psize == MMU_PAGE_64K) {
#ifndef CONFIG_BIGMEM
		compat_mask = slice_mask_for_size(mm, MMU_PAGE_4K);
#else
		slice_mask_for_size(mm, MMU_PAGE_4K, &compat_mask);
#endif
		if (fixed)
#ifndef CONFIG_BIGMEM
			or_mask(good_mask, compat_mask);
#else
			slice_or_mask(&good_mask, &compat_mask);
#endif
	}
#endif

	/* First check hint if it's valid or if we have MAP_FIXED */
	if (addr != 0 || fixed) {
		/* Build a mask for the requested range */
#ifndef CONFIG_BIGMEM
		mask = slice_range_to_mask(addr, len);
#else
		slice_range_to_mask(addr, len, &mask);
#endif
		slice_print_mask(" mask", mask);

		/* Check if we fit in the good mask. If we do, we just return,
		 * nothing else to do
		 */
		if (slice_check_fit(mask, good_mask)) {
			slice_dbg(" fits good !\n");
			return addr;
		}
	} else {
		/* Now let's see if we can find something in the existing
		 * slices for that size
		 */
		newaddr = slice_find_area(mm, len, good_mask, psize, topdown,
					  use_cache);
		if (newaddr != -ENOMEM) {
			/* Found within the good mask, we don't have to setup,
			 * we thus return directly
			 */
			slice_dbg(" found area at 0x%lx\n", newaddr);
			return newaddr;
		}
	}

	/* We don't fit in the good mask, check what other slices are
	 * empty and thus can be converted
	 */
#ifndef CONFIG_BIGMEM
	potential_mask = slice_mask_for_free(mm);
	or_mask(potential_mask, good_mask);
#else
	slice_mask_for_free(mm, &potential_mask);
	slice_or_mask(&potential_mask, &good_mask);
#endif
	slice_print_mask(" potential", potential_mask);

	if ((addr != 0 || fixed) && slice_check_fit(mask, potential_mask)) {
		slice_dbg(" fits potential !\n");
		goto convert;
	}

	/* If we have MAP_FIXED and failed the above steps, then error out */
	if (fixed)
		return -EBUSY;

	slice_dbg(" search...\n");

	/* If we had a hint that didn't work out, see if we can fit
	 * anywhere in the good area.
	 */
	if (addr) {
		addr = slice_find_area(mm, len, good_mask, psize, topdown,
				       use_cache);
		if (addr != -ENOMEM) {
			slice_dbg(" found area at 0x%lx\n", addr);
			return addr;
		}
	}

	/* Now let's see if we can find something in the existing slices
	 * for that size plus free slices
	 */
	addr = slice_find_area(mm, len, potential_mask, psize, topdown,
			       use_cache);

#ifdef CONFIG_PPC_64K_PAGES
	if (addr == -ENOMEM && psize == MMU_PAGE_64K) {
		/* retry the search with 4k-page slices included */
#ifndef CONFIG_BIGMEM
		or_mask(potential_mask, compat_mask);
#else
		slice_or_mask(&potential_mask, &compat_mask);
#endif
		addr = slice_find_area(mm, len, potential_mask, psize,
				       topdown, use_cache);
	}
#endif

	if (addr == -ENOMEM)
		return -ENOMEM;

#ifndef CONFIG_BIGMEM
	mask = slice_range_to_mask(addr, len);
#else
	slice_range_to_mask(addr, len, &mask);
#endif
	slice_dbg(" found potential area at 0x%lx\n", addr);
	slice_print_mask(" mask", mask);

 convert:
#ifndef CONFIG_BIGMEM
	andnot_mask(mask, good_mask);
	andnot_mask(mask, compat_mask);
	if (mask.low_slices || mask.high_slices) {
#else
	slice_andnot_mask(&mask, &good_mask);
	slice_andnot_mask(&mask, &compat_mask);
	if (mask.low_slices || !bitmap_empty(mask.high_slices, SLICE_NUM_HIGH)) {
#endif
		slice_convert(mm, mask, psize);
		if (psize > MMU_PAGE_BASE)
			on_each_cpu(slice_flush_segments, mm, 1);
	}
	return addr;

}
EXPORT_SYMBOL_GPL(slice_get_unmapped_area);

unsigned long arch_get_unmapped_area(struct file *filp,
				     unsigned long addr,
				     unsigned long len,
				     unsigned long pgoff,
				     unsigned long flags)
{
	return slice_get_unmapped_area(addr, len, flags,
				       current->mm->context.user_psize,
				       0, 1);
}

unsigned long arch_get_unmapped_area_topdown(struct file *filp,
					     const unsigned long addr0,
					     const unsigned long len,
					     const unsigned long pgoff,
					     const unsigned long flags)
{
	return slice_get_unmapped_area(addr0, len, flags,
				       current->mm->context.user_psize,
				       1, 1);
}

unsigned int get_slice_psize(struct mm_struct *mm, unsigned long addr)
{
#ifndef CONFIG_BIGMEM
	u64 psizes;
	int index;
#else
	unsigned char *hpsizes;
	int index, mask_index;
#endif

	if (addr < SLICE_LOW_TOP) {
#ifndef CONFIG_BIGMEM
		psizes = mm->context.low_slices_psize;
#else
		u64 lpsizes;
		lpsizes = mm->context.low_slices_psize;
#endif
		index = GET_LOW_SLICE_INDEX(addr);
#ifndef CONFIG_BIGMEM
	} else {
		psizes = mm->context.high_slices_psize;
		index = GET_HIGH_SLICE_INDEX(addr);
#else
		return (lpsizes >> (index * 4)) & 0xf;
#endif
	}
#ifndef CONFIG_BIGMEM

	return (psizes >> (index * 4)) & 0xf;
#else
	hpsizes = mm->context.high_slices_psize;
	index = GET_HIGH_SLICE_INDEX(addr);
	mask_index = index & 0x1;
	return (hpsizes[index >> 1] >> (mask_index * 4)) & 0xf;
#endif
}
EXPORT_SYMBOL_GPL(get_slice_psize);

/*
 * This is called by hash_page when it needs to do a lazy conversion of
 * an address space from real 64K pages to combo 4K pages (typically
 * when hitting a non cacheable mapping on a processor or hypervisor
 * that won't allow them for 64K pages).
 *
 * This is also called in init_new_context() to change back the user
 * psize from whatever the parent context had it set to
 * N.B. This may be called before mm->context.id has been set.
 *
 * This function will only change the content of the {low,high)_slice_psize
 * masks, it will not flush SLBs as this shall be handled lazily by the
 * caller.
 */
void slice_set_user_psize(struct mm_struct *mm, unsigned int psize)
{
#ifndef CONFIG_BIGMEM
	unsigned long flags, lpsizes, hpsizes;
#else
	int index, mask_index;
	unsigned char *hpsizes;
	unsigned long flags, lpsizes;
#endif
	unsigned int old_psize;
	int i;

	slice_dbg("slice_set_user_psize(mm=%p, psize=%d)\n", mm, psize);

	spin_lock_irqsave(&slice_convert_lock, flags);

	old_psize = mm->context.user_psize;
	slice_dbg(" old_psize=%d\n", old_psize);
	if (old_psize == psize)
		goto bail;

	mm->context.user_psize = psize;
	wmb();

	lpsizes = mm->context.low_slices_psize;
	for (i = 0; i < SLICE_NUM_LOW; i++)
		if (((lpsizes >> (i * 4)) & 0xf) == old_psize)
			lpsizes = (lpsizes & ~(0xful << (i * 4))) |
				(((unsigned long)psize) << (i * 4));
#ifdef CONFIG_BIGMEM
	/* Assign the value back */
	mm->context.low_slices_psize = lpsizes;
#endif

	hpsizes = mm->context.high_slices_psize;
#ifndef CONFIG_BIGMEM
	for (i = 0; i < SLICE_NUM_HIGH; i++)
		if (((hpsizes >> (i * 4)) & 0xf) == old_psize)
			hpsizes = (hpsizes & ~(0xful << (i * 4))) |
				(((unsigned long)psize) << (i * 4));
#else
	for (i = 0; i < SLICE_NUM_HIGH; i++) {
		mask_index = i & 0x1;
		index = i >> 1;
		if (((hpsizes[index] >> (mask_index * 4)) & 0xf) == old_psize)
			hpsizes[index] = (hpsizes[index] &
					  ~(0xf << (mask_index * 4))) |
				(((unsigned long)psize) << (mask_index * 4));
	}


#endif

#ifndef CONFIG_BIGMEM
	mm->context.low_slices_psize = lpsizes;
	mm->context.high_slices_psize = hpsizes;
#endif

	slice_dbg(" lsps=%lx, hsps=%lx\n",
#ifndef CONFIG_BIGMEM
		  mm->context.low_slices_psize,
		  mm->context.high_slices_psize);
#else
		  (unsigned long)mm->context.low_slices_psize,
		  (unsigned long)mm->context.high_slices_psize);
#endif

 bail:
	spin_unlock_irqrestore(&slice_convert_lock, flags);
}

void slice_set_psize(struct mm_struct *mm, unsigned long address,
		     unsigned int psize)
{
#ifdef CONFIG_BIGMEM
	unsigned char *hpsizes;
#endif
	unsigned long i, flags;
#ifndef CONFIG_BIGMEM
	u64 *p;
#else
	u64 *lpsizes;
#endif

	spin_lock_irqsave(&slice_convert_lock, flags);
	if (address < SLICE_LOW_TOP) {
		i = GET_LOW_SLICE_INDEX(address);
#ifndef CONFIG_BIGMEM
		p = &mm->context.low_slices_psize;
#else
		lpsizes = &mm->context.low_slices_psize;
		*lpsizes = (*lpsizes & ~(0xful << (i * 4))) |
			((unsigned long) psize << (i * 4));
#endif
	} else {
#ifdef CONFIG_BIGMEM
		int index, mask_index;
#endif
		i = GET_HIGH_SLICE_INDEX(address);
#ifndef CONFIG_BIGMEM
		p = &mm->context.high_slices_psize;
#else
		hpsizes = mm->context.high_slices_psize;
		mask_index = i & 0x1;
		index = i >> 1;
		hpsizes[index] = (hpsizes[index] &
				  ~(0xf << (mask_index * 4))) |
			(((unsigned long)psize) << (mask_index * 4));
#endif
	}
#ifndef CONFIG_BIGMEM
	*p = (*p & ~(0xful << (i * 4))) | ((unsigned long) psize << (i * 4));
#else

#endif
	spin_unlock_irqrestore(&slice_convert_lock, flags);

#ifdef CONFIG_SPU_BASE
	spu_flush_all_slbs(mm);
#endif
}

void slice_set_range_psize(struct mm_struct *mm, unsigned long start,
			   unsigned long len, unsigned int psize)
{
#ifndef CONFIG_BIGMEM
	struct slice_mask mask = slice_range_to_mask(start, len);
#else
	struct slice_mask mask;
#endif

#ifdef CONFIG_BIGMEM
	slice_range_to_mask(start, len, &mask);
#endif
	slice_convert(mm, mask, psize);
}

/*
 * is_hugepage_only_range() is used by generic code to verify wether
 * a normal mmap mapping (non hugetlbfs) is valid on a given area.
 *
 * until the generic code provides a more generic hook and/or starts
 * calling arch get_unmapped_area for MAP_FIXED (which our implementation
 * here knows how to deal with), we hijack it to keep standard mappings
 * away from us.
 *
 * because of that generic code limitation, MAP_FIXED mapping cannot
 * "convert" back a slice with no VMAs to the standard page size, only
 * get_unmapped_area() can. It would be possible to fix it here but I
 * prefer working on fixing the generic code instead.
 *
 * WARNING: This will not work if hugetlbfs isn't enabled since the
 * generic code will redefine that function as 0 in that. This is ok
 * for now as we only use slices with hugetlbfs enabled. This should
 * be fixed as the generic code gets fixed.
 */
int is_hugepage_only_range(struct mm_struct *mm, unsigned long addr,
			   unsigned long len)
{
	struct slice_mask mask, available;
	unsigned int psize = mm->context.user_psize;

#ifndef CONFIG_BIGMEM
	mask = slice_range_to_mask(addr, len);
	available = slice_mask_for_size(mm, psize);
#else
	slice_range_to_mask(addr, len, &mask);
	slice_mask_for_size(mm, psize, &available);
#endif
#ifdef CONFIG_PPC_64K_PAGES
	/* We need to account for 4k slices too */
	if (psize == MMU_PAGE_64K) {
		struct slice_mask compat_mask;
#ifndef CONFIG_BIGMEM
		compat_mask = slice_mask_for_size(mm, MMU_PAGE_4K);
		or_mask(available, compat_mask);
#else
		slice_mask_for_size(mm, MMU_PAGE_4K, &compat_mask);
		slice_or_mask(&available, &compat_mask);
#endif
	}
#endif

#if 0 /* too verbose */
	slice_dbg("is_hugepage_only_range(mm=%p, addr=%lx, len=%lx)\n",
		 mm, addr, len);
	slice_print_mask(" mask", mask);
	slice_print_mask(" available", available);
#endif
	return !slice_check_fit(mask, available);
}

