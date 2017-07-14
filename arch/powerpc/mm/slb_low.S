/*
 * Low-level SLB routines
 *
 * Copyright (C) 2004 David Gibson <dwg@au.ibm.com>, IBM
 *
 * Based on earlier C version:
 * Dave Engebretsen and Mike Corrigan {engebret|mikejc}@us.ibm.com
 *    Copyright (c) 2001 Dave Engebretsen
 * Copyright (C) 2002 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include <asm/processor.h>
#include <asm/ppc_asm.h>
#include <asm/asm-offsets.h>
#include <asm/cputable.h>
#include <asm/page.h>
#include <asm/mmu.h>
#include <asm/pgtable.h>
#include <asm/firmware.h>

#ifdef CONFIG_BIGMEM
/*
 * This macro generates asm code to compute the VSID scramble
 * function.  Used in slb_allocate() and do_stab_bolted.  The function
 * computed is: (protovsid*VSID_MULTIPLIER) % VSID_MODULUS
 *
 *	rt = register containing the proto-VSID and into which the
 *		VSID will be stored
 *	rx = scratch register (clobbered)
 *	rf = flags
 *
 *	- rt and rx must be different registers
 *	- The answer will end up in the low VSID_BITS bits of rt.  The higher
 *	  bits may contain other garbage, so you may need to mask the
 *	  result.
 */
#define ASM_VSID_SCRAMBLE(rt, rx, rf, size)				\
	lis	rx,VSID_MULTIPLIER_##size@h;				\
	ori	rx,rx,VSID_MULTIPLIER_##size@l;				\
	mulld	rt,rt,rx;		/* rt = rt * MULTIPLIER */	\
/*									\
 * powermac get slb fault before feature fixup, so make 65 bit part     \
 * the default part of feature fixup					\
 */									\
BEGIN_MMU_FTR_SECTION							\
	srdi	rx,rt,VSID_BITS_65_##size;				\
	clrldi	rt,rt,(64-VSID_BITS_65_##size);				\
	add	rt,rt,rx;						\
	addi	rx,rt,1;						\
	srdi	rx,rx,VSID_BITS_65_##size;				\
	add	rt,rt,rx;						\
	rldimi	rf,rt,SLB_VSID_SHIFT_##size,(64 - (SLB_VSID_SHIFT_##size + VSID_BITS_65_##size)); \
MMU_FTR_SECTION_ELSE							\
	srdi	rx,rt,VSID_BITS_##size;					\
	clrldi	rt,rt,(64-VSID_BITS_##size);				\
	add	rt,rt,rx;		/* add high and low bits */	\
	addi	rx,rt,1;						\
	srdi	rx,rx,VSID_BITS_##size;	/* extract 2^VSID_BITS bit */	\
	add	rt,rt,rx;						\
	rldimi	rf,rt,SLB_VSID_SHIFT_##size,(64 - (SLB_VSID_SHIFT_##size + VSID_BITS_##size)); \
ALT_MMU_FTR_SECTION_END_IFCLR(MMU_FTR_68_BIT_VA)


#endif
/* void slb_allocate_realmode(unsigned long ea);
 *
 * Create an SLB entry for the given EA (user or kernel).
 * 	r3 = faulting address, r13 = PACA
 *	r9, r10, r11 are clobbered by this function
 * No other registers are examined or changed.
 */
_GLOBAL(slb_allocate_realmode)
#ifndef CONFIG_BIGMEM
	/* r3 = faulting address */
#else
	/*
	 * check for bad kernel/user address
	 * (ea & ~REGION_MASK) >= PGTABLE_RANGE
	 */
	rldicr. r9,r3,4,(63 - PGTABLE_EADDR_SIZE - 4)
	bne-	8f
#endif

	srdi	r9,r3,60		/* get region */
#ifndef CONFIG_BIGMEM
	srdi	r10,r3,28		/* get esid */
#else
	srdi	r10,r3,SID_SHIFT	/* get esid */
#endif
	cmpldi	cr7,r9,0xc		/* cmp PAGE_OFFSET for later use */

	/* r3 = address, r10 = esid, cr7 = <> PAGE_OFFSET */
	blt	cr7,0f			/* user or kernel? */

#ifndef CONFIG_BIGMEM
	/* kernel address: proto-VSID = ESID */
	/* WARNING - MAGIC: we don't use the VSID 0xfffffffff, but
	 * this code will generate the protoVSID 0xfffffffff for the
	 * top segment.  That's ok, the scramble below will translate
	 * it to VSID 0, which is reserved as a bad VSID - one which
	 * will never have any pages in it.  */

#endif
	/* Check if hitting the linear mapping or some other kernel space
	*/
	bne	cr7,1f

	/* Linear mapping encoding bits, the "li" instruction below will
	 * be patched by the kernel at boot
	 */
_GLOBAL(slb_miss_kernel_load_linear)
	li	r11,0
#ifdef CONFIG_BIGMEM
	/*
	 * context = (ea >> 60) - (0xc - 1)
	 * r9 = region id.
	 */
	subi	r9,r9,KERNEL_REGION_CONTEXT_OFFSET

#endif
BEGIN_FTR_SECTION
	b	slb_finish_load
END_MMU_FTR_SECTION_IFCLR(MMU_FTR_1T_SEGMENT)
	b	slb_finish_load_1T

1:
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	/* Check virtual memmap region. To be patches at kernel boot */
	cmpldi	cr0,r9,0xf
	bne	1f
_GLOBAL(slb_miss_kernel_load_vmemmap)
	li	r11,0
	b	6f
1:
#endif /* CONFIG_SPARSEMEM_VMEMMAP */

	/* vmalloc mapping gets the encoding from the PACA as the mapping
	 * can be demoted from 64K -> 4K dynamically on some machines
	 */
	clrldi	r11,r10,48
	cmpldi	r11,(VMALLOC_SIZE >> 28) - 1
	bgt	5f
	lhz	r11,PACAVMALLOCSLLP(r13)
	b	6f
5:
	/* IO mapping */
	_GLOBAL(slb_miss_kernel_load_io)
	li	r11,0
6:
#ifdef CONFIG_BIGMEM
	/*
	 * context = (ea >> 60) - (0xc - 1)
	 * r9 = region id.
	 */
	subi	r9,r9,KERNEL_REGION_CONTEXT_OFFSET

#endif
BEGIN_FTR_SECTION
	b	slb_finish_load
END_MMU_FTR_SECTION_IFCLR(MMU_FTR_1T_SEGMENT)
	b	slb_finish_load_1T

#ifndef CONFIG_BIGMEM
0:	/* user address: proto-VSID = context << 15 | ESID. First check
	 * if the address is within the boundaries of the user region
	 */
	srdi.	r9,r10,USER_ESID_BITS
	bne-	8f			/* invalid ea bits set */

#else
0:	/*.
	 * For userspace addresses, make sure this is region 0.
	.*/
	cmpdi	r9, 0
	bne	8f
#endif

	/* when using slices, we extract the psize off the slice bitmaps
	 * and then we need to get the sllp encoding off the mmu_psize_defs
	 * array.
	 *
	 * XXX This is a bit inefficient especially for the normal case,
	 * so we should try to implement a fast path for the standard page
	 * size using the old sllp value so we avoid the array. We cannot
	 * really do dynamic patching unfortunately as processes might flip
	 * between 4k and 64k standard page size
	 */
#ifdef CONFIG_PPC_MM_SLICES
#ifdef CONFIG_BIGMEM
	/* r10 have esid */
#endif
	cmpldi	r10,16
#ifndef CONFIG_BIGMEM

	/* Get the slice index * 4 in r11 and matching slice size mask in r9 */
	ld	r9,PACALOWSLICESPSIZE(r13)
	sldi	r11,r10,2
#else
	/* below SLICE_LOW_TOP */
#endif
	blt	5f
#ifndef CONFIG_BIGMEM
	ld	r9,PACAHIGHSLICEPSIZE(r13)
	srdi	r11,r10,(SLICE_HIGH_SHIFT - SLICE_LOW_SHIFT - 2)
	andi.	r11,r11,0x3c
#else
	/*
	 * Handle hpsizes,
	 * r9 is get_paca()->context.high_slices_psize[index], r11 is mask_index
	 */
	srdi    r11,r10,(SLICE_HIGH_SHIFT - SLICE_LOW_SHIFT + 1) /* index */
	addi	r9,r11,PACAHIGHSLICEPSIZE
	lbzx	r9,r13,r9		/* r9 is hpsizes[r11] */
	/* r11 = (r10 >> (SLICE_HIGH_SHIFT - SLICE_LOW_SHIFT)) & 0x1 */
	rldicl	r11,r10,(64 - (SLICE_HIGH_SHIFT - SLICE_LOW_SHIFT)),63
	b	6f
#endif

#ifndef CONFIG_BIGMEM
5:	/* Extract the psize and multiply to get an array offset */
#else
5:
	/*
	 * Handle lpsizes
	 * r9 is get_paca()->context.low_slices_psize, r11 is index
	 */
	ld	r9,PACALOWSLICESPSIZE(r13)
	mr	r11,r10
6:
	sldi	r11,r11,2  /* index * 4 */
	/* Extract the psize and multiply to get an array offset */
#endif
	srd	r9,r9,r11
	andi.	r9,r9,0xf
	mulli	r9,r9,MMUPSIZEDEFSIZE

	/* Now get to the array and obtain the sllp
	 */
	ld	r11,PACATOC(r13)
	ld	r11,mmu_psize_defs@got(r11)
	add	r11,r11,r9
	ld	r11,MMUPSIZESLLP(r11)
	ori	r11,r11,SLB_VSID_USER
#else
	/* paca context sllp already contains the SLB_VSID_USER bits */
	lhz	r11,PACACONTEXTSLLP(r13)
#endif /* CONFIG_PPC_MM_SLICES */

	ld	r9,PACACONTEXTID(r13)
BEGIN_FTR_SECTION
	cmpldi	r10,0x1000
#ifndef CONFIG_BIGMEM
END_MMU_FTR_SECTION_IFSET(MMU_FTR_1T_SEGMENT)
	rldimi	r10,r9,USER_ESID_BITS,0
BEGIN_FTR_SECTION
#endif
	bge	slb_finish_load_1T
END_MMU_FTR_SECTION_IFSET(MMU_FTR_1T_SEGMENT)
	b	slb_finish_load

8:	/* invalid EA */
	li	r10,0			/* BAD_VSID */
#ifdef CONFIG_BIGMEM
	li	r9,0			/* BAD_VSID */
#endif
	li	r11,SLB_VSID_USER	/* flags don't much matter */
	b	slb_finish_load

#ifdef __DISABLED__

/* void slb_allocate_user(unsigned long ea);
 *
 * Create an SLB entry for the given EA (user or kernel).
 * 	r3 = faulting address, r13 = PACA
 *	r9, r10, r11 are clobbered by this function
 * No other registers are examined or changed.
 *
 * It is called with translation enabled in order to be able to walk the
 * page tables. This is not currently used.
 */
_GLOBAL(slb_allocate_user)
	/* r3 = faulting address */
	srdi	r10,r3,28		/* get esid */

	crset	4*cr7+lt		/* set "user" flag for later */

	/* check if we fit in the range covered by the pagetables*/
	srdi.	r9,r3,PGTABLE_EADDR_SIZE
	crnot	4*cr0+eq,4*cr0+eq
	beqlr

	/* now we need to get to the page tables in order to get the page
	 * size encoding from the PMD. In the future, we'll be able to deal
	 * with 1T segments too by getting the encoding from the PGD instead
	 */
	ld	r9,PACAPGDIR(r13)
	cmpldi	cr0,r9,0
	beqlr
	rlwinm	r11,r10,8,25,28
	ldx	r9,r9,r11		/* get pgd_t */
	cmpldi	cr0,r9,0
	beqlr
	rlwinm	r11,r10,3,17,28
	ldx	r9,r9,r11		/* get pmd_t */
	cmpldi	cr0,r9,0
	beqlr

	/* build vsid flags */
	andi.	r11,r9,SLB_VSID_LLP
	ori	r11,r11,SLB_VSID_USER

	/* get context to calculate proto-VSID */
	ld	r9,PACACONTEXTID(r13)
#ifndef CONFIG_BIGMEM
	rldimi	r10,r9,USER_ESID_BITS,0

#endif
	/* fall through slb_finish_load */

#endif /* __DISABLED__ */


/*
 * Finish loading of an SLB entry and return
 *
#ifndef CONFIG_BIGMEM
 * r3 = EA, r10 = proto-VSID, r11 = flags, clobbers r9, cr7 = <> PAGE_OFFSET
#else
 * r3 = EA, r9 = context, r10 = ESID, r11 = flags, clobbers r9, cr7 = <> PAGE_OFFSET
#endif
 */
slb_finish_load:
#ifndef CONFIG_BIGMEM
	ASM_VSID_SCRAMBLE(r10,r9,256M)
	rldimi	r11,r10,SLB_VSID_SHIFT,16	/* combine VSID and flags */

#else
	rldimi  r10,r9,ESID_BITS,0
	ASM_VSID_SCRAMBLE(r10,r9,r11,256M)
#endif
	/* r3 = EA, r11 = VSID data */
	/*
	 * Find a slot, round robin. Previously we tried to find a
	 * free slot first but that took too long. Unfortunately we
 	 * dont have any LRU information to help us choose a slot.
 	 */
#ifdef CONFIG_PPC_ISERIES
BEGIN_FW_FTR_SECTION
	/*
	 * On iSeries, the "bolted" stack segment can be cast out on
	 * shared processor switch so we need to check for a miss on
	 * it and restore it to the right slot.
	 */
	ld	r9,PACAKSAVE(r13)
	clrrdi	r9,r9,28
	clrrdi	r3,r3,28
	li	r10,SLB_NUM_BOLTED-1	/* Stack goes in last bolted slot */
	cmpld	r9,r3
	beq	3f
END_FW_FTR_SECTION_IFSET(FW_FEATURE_ISERIES)
#endif /* CONFIG_PPC_ISERIES */

7:	ld	r10,PACASTABRR(r13)
	addi	r10,r10,1
	/* This gets soft patched on boot. */
_GLOBAL(slb_compare_rr_to_size)
	cmpldi	r10,0

	blt+	4f
	li	r10,SLB_NUM_BOLTED

4:
	std	r10,PACASTABRR(r13)

3:
	rldimi	r3,r10,0,36		/* r3= EA[0:35] | entry */
	oris	r10,r3,SLB_ESID_V@h	/* r3 |= SLB_ESID_V */

	/* r3 = ESID data, r11 = VSID data */

	/*
	 * No need for an isync before or after this slbmte. The exception
	 * we enter with and the rfid we exit with are context synchronizing.
	 */
	slbmte	r11,r10

	/* we're done for kernel addresses */
	crclr	4*cr0+eq		/* set result to "success" */
	bgelr	cr7

	/* Update the slb cache */
	lhz	r3,PACASLBCACHEPTR(r13)	/* offset = paca->slb_cache_ptr */
	cmpldi	r3,SLB_CACHE_ENTRIES
	bge	1f

	/* still room in the slb cache */
#ifndef CONFIG_BIGMEM
	sldi	r11,r3,1		/* r11 = offset * sizeof(u16) */
	rldicl	r10,r10,36,28		/* get low 16 bits of the ESID */
	add	r11,r11,r13		/* r11 = (u16 *)paca + offset */
	sth	r10,PACASLBCACHE(r11)	/* paca->slb_cache[offset] = esid */
#else
	sldi	r11,r3,2		/* r11 = offset * sizeof(u32) */
	srdi    r10,r10,28		/* get the 36 bits of the ESID */
	add	r11,r11,r13		/* r11 = (u32 *)paca + offset */
	stw	r10,PACASLBCACHE(r11)	/* paca->slb_cache[offset] = esid */
#endif
	addi	r3,r3,1			/* offset++ */
	b	2f
1:					/* offset >= SLB_CACHE_ENTRIES */
	li	r3,SLB_CACHE_ENTRIES+1
2:
	sth	r3,PACASLBCACHEPTR(r13)	/* paca->slb_cache_ptr = offset */
	crclr	4*cr0+eq		/* set result to "success" */
	blr

/*
 * Finish loading of a 1T SLB entry (for the kernel linear mapping) and return.
 * We assume legacy iSeries will never have 1T segments.
 *
#ifndef CONFIG_BIGMEM
 * r3 = EA, r10 = proto-VSID, r11 = flags, clobbers r9
#else
 * r3 = EA, r9 = context, r10 = ESID(256MB), r11 = flags, clobbers r9
#endif
 */
slb_finish_load_1T:
#ifndef CONFIG_BIGMEM
	srdi	r10,r10,40-28		/* get 1T ESID */
	ASM_VSID_SCRAMBLE(r10,r9,1T)
	rldimi	r11,r10,SLB_VSID_SHIFT_1T,16	/* combine VSID and flags */
#else
	srdi	r10,r10,(SID_SHIFT_1T - SID_SHIFT)	/* get 1T ESID */
	rldimi  r10,r9,ESID_BITS_1T,0
	ASM_VSID_SCRAMBLE(r10,r9,r11,1T)

#endif
	li	r10,MMU_SEGSIZE_1T
	rldimi	r11,r10,SLB_VSID_SSIZE_SHIFT,0	/* insert segment size */

	/* r3 = EA, r11 = VSID data */
	clrrdi	r3,r3,SID_SHIFT_1T	/* clear out non-ESID bits */
	b	7b

