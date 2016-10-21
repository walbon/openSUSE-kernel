/*
 * native hashtable management.
 *
 * SMP scalability work:
 *    Copyright (C) 2001 Anton Blanchard <anton@au.ibm.com>, IBM
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#undef DEBUG_LOW

#include <linux/spinlock.h>
#include <linux/bitops.h>
#include <linux/threads.h>
#include <linux/smp.h>

#include <asm/abs_addr.h>
#include <asm/machdep.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include <asm/cputable.h>
#include <asm/udbg.h>
#include <asm/kexec.h>
#include <asm/ppc-opcode.h>

#ifdef DEBUG_LOW
#define DBG_LOW(fmt...) udbg_printf(fmt)
#else
#define DBG_LOW(fmt...)
#endif

#define HPTE_LOCK_BIT 3

static DEFINE_RAW_SPINLOCK(native_tlbie_lock);

#ifndef CONFIG_BIGMEM
static inline void __tlbie(unsigned long va, int psize, int ssize)
#else
static inline void __tlbie(unsigned long vpn, int psize, int ssize)
#endif
{
#ifdef CONFIG_BIGMEM
	unsigned long va;
#endif
	unsigned int penc;

#ifndef CONFIG_BIGMEM
	/* clear top 16 bits, non SLS segment */
#else
	/*
	 * We need 14 to 65 bits of va for a tlibe of 4K page
	 * With vpn we ignore the lower VPN_SHIFT bits already.
	 * And top two bits are already ignored because we can
	 * only accomadate 76 bits in a 64 bit vpn with a VPN_SHIFT
	 * of 12.
	 */
	va = vpn << VPN_SHIFT;
	/*
	 * clear top 16 bits of 64bit va, non SLS segment
	 * Older versions of the architecture (2.02 and earler) require the
	 * masking of the top 16 bits.
	 */
#endif
	va &= ~(0xffffULL << 48);

	switch (psize) {
	case MMU_PAGE_4K:
#ifndef CONFIG_BIGMEM
		va &= ~0xffful;
#endif
		va |= ssize << 8;
		asm volatile(ASM_FTR_IFCLR("tlbie %0,0", PPC_TLBIE(%1,%0), %2)
			     : : "r" (va), "r"(0), "i" (CPU_FTR_HVMODE_206)
			     : "memory");
		break;
	default:
#ifdef CONFIG_BIGMEM
		/* We need 14 to 14 + i bits of va */
#endif
		penc = mmu_psize_defs[psize].penc;
		va &= ~((1ul << mmu_psize_defs[psize].shift) - 1);
		va |= penc << 12;
		va |= ssize << 8;
		va |= 1; /* L */
		asm volatile(ASM_FTR_IFCLR("tlbie %0,1", PPC_TLBIE(%1,%0), %2)
			     : : "r" (va), "r"(0), "i" (CPU_FTR_HVMODE_206)
			     : "memory");
		break;
	}
}

#ifndef CONFIG_BIGMEM
static inline void __tlbiel(unsigned long va, int psize, int ssize)
#else
static inline void __tlbiel(unsigned long vpn, int psize, int ssize)
#endif
{
#ifdef CONFIG_BIGMEM
	unsigned long va;
#endif
	unsigned int penc;

#ifndef CONFIG_BIGMEM
	/* clear top 16 bits, non SLS segment */
#else
	/* VPN_SHIFT can be atmost 12 */
	va = vpn << VPN_SHIFT;
	/*
	 * clear top 16 bits of 64 bit va, non SLS segment
	 * Older versions of the architecture (2.02 and earler) require the
	 * masking of the top 16 bits.
	 */
#endif
	va &= ~(0xffffULL << 48);

	switch (psize) {
	case MMU_PAGE_4K:
#ifndef CONFIG_BIGMEM
		va &= ~0xffful;
#endif
		va |= ssize << 8;
		asm volatile(".long 0x7c000224 | (%0 << 11) | (0 << 21)"
			     : : "r"(va) : "memory");
		break;
	default:
#ifdef CONFIG_BIGMEM
		/* We need 14 to 14 + i bits of va */
#endif
		penc = mmu_psize_defs[psize].penc;
		va &= ~((1ul << mmu_psize_defs[psize].shift) - 1);
		va |= penc << 12;
		va |= ssize << 8;
		va |= 1; /* L */
		asm volatile(".long 0x7c000224 | (%0 << 11) | (1 << 21)"
			     : : "r"(va) : "memory");
		break;
	}

}

#ifndef CONFIG_BIGMEM
static inline void tlbie(unsigned long va, int psize, int ssize, int local)
#else
static inline void tlbie(unsigned long vpn, int psize, int ssize, int local)
#endif
{
	unsigned int use_local = local && mmu_has_feature(MMU_FTR_TLBIEL);
	int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);

	if (use_local)
		use_local = mmu_psize_defs[psize].tlbiel;
	if (lock_tlbie && !use_local)
		raw_spin_lock(&native_tlbie_lock);
	asm volatile("ptesync": : :"memory");
	if (use_local) {
#ifndef CONFIG_BIGMEM
		__tlbiel(va, psize, ssize);
#else
		__tlbiel(vpn, psize, ssize);
#endif
		asm volatile("ptesync": : :"memory");
	} else {
#ifndef CONFIG_BIGMEM
		__tlbie(va, psize, ssize);
#else
		__tlbie(vpn, psize, ssize);
#endif
		asm volatile("eieio; tlbsync; ptesync": : :"memory");
	}
	if (lock_tlbie && !use_local)
		raw_spin_unlock(&native_tlbie_lock);
}

static inline void native_lock_hpte(struct hash_pte *hptep)
{
	unsigned long *word = &hptep->v;

	while (1) {
		if (!test_and_set_bit_lock(HPTE_LOCK_BIT, word))
			break;
		while(test_bit(HPTE_LOCK_BIT, word))
			cpu_relax();
	}
}

static inline void native_unlock_hpte(struct hash_pte *hptep)
{
	unsigned long *word = &hptep->v;

	clear_bit_unlock(HPTE_LOCK_BIT, word);
}

#ifndef CONFIG_BIGMEM
static long native_hpte_insert(unsigned long hpte_group, unsigned long va,
#else
static long native_hpte_insert(unsigned long hpte_group, unsigned long vpn,
#endif
			unsigned long pa, unsigned long rflags,
			unsigned long vflags, int psize, int ssize)
{
	struct hash_pte *hptep = htab_address + hpte_group;
	unsigned long hpte_v, hpte_r;
	int i;

	if (!(vflags & HPTE_V_BOLTED)) {
#ifndef CONFIG_BIGMEM
		DBG_LOW("    insert(group=%lx, va=%016lx, pa=%016lx,"
#else
		DBG_LOW("    insert(group=%lx, vpn=%016lx, pa=%016lx,"
#endif
			" rflags=%lx, vflags=%lx, psize=%d)\n",
#ifndef CONFIG_BIGMEM
			hpte_group, va, pa, rflags, vflags, psize);
#else
			hpte_group, vpn, pa, rflags, vflags, psize);
#endif
	}

	for (i = 0; i < HPTES_PER_GROUP; i++) {
		if (! (hptep->v & HPTE_V_VALID)) {
			/* retry with lock held */
			native_lock_hpte(hptep);
			if (! (hptep->v & HPTE_V_VALID))
				break;
			native_unlock_hpte(hptep);
		}

		hptep++;
	}

	if (i == HPTES_PER_GROUP)
		return -1;

#ifndef CONFIG_BIGMEM
	hpte_v = hpte_encode_v(va, psize, ssize) | vflags | HPTE_V_VALID;
#else
	hpte_v = hpte_encode_v(vpn, psize, ssize) | vflags | HPTE_V_VALID;
#endif
	hpte_r = hpte_encode_r(pa, psize) | rflags;

	if (!(vflags & HPTE_V_BOLTED)) {
		DBG_LOW(" i=%x hpte_v=%016lx, hpte_r=%016lx\n",
			i, hpte_v, hpte_r);
	}

	hptep->r = hpte_r;
	/* Guarantee the second dword is visible before the valid bit */
	eieio();
	/*
	 * Now set the first dword including the valid bit
	 * NOTE: this also unlocks the hpte
	 */
	hptep->v = hpte_v;

	__asm__ __volatile__ ("ptesync" : : : "memory");

	return i | (!!(vflags & HPTE_V_SECONDARY) << 3);
}

static long native_hpte_remove(unsigned long hpte_group)
{
	struct hash_pte *hptep;
	int i;
	int slot_offset;
	unsigned long hpte_v;

	DBG_LOW("    remove(group=%lx)\n", hpte_group);

	/* pick a random entry to start at */
	slot_offset = mftb() & 0x7;

	for (i = 0; i < HPTES_PER_GROUP; i++) {
		hptep = htab_address + hpte_group + slot_offset;
		hpte_v = hptep->v;

		if ((hpte_v & HPTE_V_VALID) && !(hpte_v & HPTE_V_BOLTED)) {
			/* retry with lock held */
			native_lock_hpte(hptep);
			hpte_v = hptep->v;
			if ((hpte_v & HPTE_V_VALID)
			    && !(hpte_v & HPTE_V_BOLTED))
				break;
			native_unlock_hpte(hptep);
		}

		slot_offset++;
		slot_offset &= 0x7;
	}

	if (i == HPTES_PER_GROUP)
		return -1;

	/* Invalidate the hpte. NOTE: this also unlocks it */
	hptep->v = 0;

	return i;
}

static long native_hpte_updatepp(unsigned long slot, unsigned long newpp,
#ifndef CONFIG_BIGMEM
				 unsigned long va, int psize, int ssize,
#else
				 unsigned long vpn, int psize, int ssize,
#endif
				 int local)
{
	struct hash_pte *hptep = htab_address + slot;
	unsigned long hpte_v, want_v;
	int ret = 0;

#ifndef CONFIG_BIGMEM
	want_v = hpte_encode_v(va, psize, ssize);
#else
	want_v = hpte_encode_v(vpn, psize, ssize);
#endif

#ifndef CONFIG_BIGMEM
	DBG_LOW("    update(va=%016lx, avpnv=%016lx, hash=%016lx, newpp=%x)",
		va, want_v & HPTE_V_AVPN, slot, newpp);
#else
	DBG_LOW("    update(vpn=%016lx, avpnv=%016lx, group=%lx, newpp=%lx)",
		vpn, want_v & HPTE_V_AVPN, slot, newpp);
#endif

	native_lock_hpte(hptep);

	hpte_v = hptep->v;

	/* Even if we miss, we need to invalidate the TLB */
	if (!HPTE_V_COMPARE(hpte_v, want_v) || !(hpte_v & HPTE_V_VALID)) {
		DBG_LOW(" -> miss\n");
		ret = -1;
	} else {
		DBG_LOW(" -> hit\n");
		/* Update the HPTE */
		hptep->r = (hptep->r & ~(HPTE_R_PP | HPTE_R_N)) |
			(newpp & (HPTE_R_PP | HPTE_R_N | HPTE_R_C));
	}
	native_unlock_hpte(hptep);

	/* Ensure it is out of the tlb too. */
#ifndef CONFIG_BIGMEM
	tlbie(va, psize, ssize, local);
#else
	tlbie(vpn, psize, ssize, local);
#endif

	return ret;
}

#ifndef CONFIG_BIGMEM
static long native_hpte_find(unsigned long va, int psize, int ssize)
#else
static long native_hpte_find(unsigned long vpn, int psize, int ssize)
#endif
{
	struct hash_pte *hptep;
	unsigned long hash;
	unsigned long i;
	long slot;
	unsigned long want_v, hpte_v;

#ifndef CONFIG_BIGMEM
	hash = hpt_hash(va, mmu_psize_defs[psize].shift, ssize);
	want_v = hpte_encode_v(va, psize, ssize);
#else
	hash = hpt_hash(vpn, mmu_psize_defs[psize].shift, ssize);
	want_v = hpte_encode_v(vpn, psize, ssize);
#endif

	/* Bolted mappings are only ever in the primary group */
	slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
	for (i = 0; i < HPTES_PER_GROUP; i++) {
		hptep = htab_address + slot;
		hpte_v = hptep->v;

		if (HPTE_V_COMPARE(hpte_v, want_v) && (hpte_v & HPTE_V_VALID))
			/* HPTE matches */
			return slot;
		++slot;
	}

	return -1;
}

/*
 * Update the page protection bits. Intended to be used to create
 * guard pages for kernel data structures on pages which are bolted
 * in the HPT. Assumes pages being operated on will not be stolen.
 *
 * No need to lock here because we should be the only user.
 */
static void native_hpte_updateboltedpp(unsigned long newpp, unsigned long ea,
				       int psize, int ssize)
{
#ifndef CONFIG_BIGMEM
	unsigned long vsid, va;
#else
	unsigned long vpn;
	unsigned long vsid;
#endif
	long slot;
	struct hash_pte *hptep;

	vsid = get_kernel_vsid(ea, ssize);
#ifndef CONFIG_BIGMEM
	va = hpt_va(ea, vsid, ssize);
#else
	vpn = hpt_vpn(ea, vsid, ssize);
#endif

#ifndef CONFIG_BIGMEM
	slot = native_hpte_find(va, psize, ssize);
#else
	slot = native_hpte_find(vpn, psize, ssize);
#endif
	if (slot == -1)
		panic("could not find page to bolt\n");
	hptep = htab_address + slot;

	/* Update the HPTE */
	hptep->r = (hptep->r & ~(HPTE_R_PP | HPTE_R_N)) |
		(newpp & (HPTE_R_PP | HPTE_R_N));

	/* Ensure it is out of the tlb too. */
#ifndef CONFIG_BIGMEM
	tlbie(va, psize, ssize, 0);
#else
	tlbie(vpn, psize, ssize, 0);
#endif
}

#ifndef CONFIG_BIGMEM
static void native_hpte_invalidate(unsigned long slot, unsigned long va,
#else
static void native_hpte_invalidate(unsigned long slot, unsigned long vpn,
#endif
				   int psize, int ssize, int local)
{
	struct hash_pte *hptep = htab_address + slot;
	unsigned long hpte_v;
	unsigned long want_v;
	unsigned long flags;

	local_irq_save(flags);

#ifndef CONFIG_BIGMEM
	DBG_LOW("    invalidate(va=%016lx, hash: %x)\n", va, slot);
#else
	DBG_LOW("    invalidate(vpn=%016lx, hash: %lx)\n", vpn, slot);
#endif

#ifndef CONFIG_BIGMEM
	want_v = hpte_encode_v(va, psize, ssize);
#else
	want_v = hpte_encode_v(vpn, psize, ssize);
#endif
	native_lock_hpte(hptep);
	hpte_v = hptep->v;

	/* Even if we miss, we need to invalidate the TLB */
	if (!HPTE_V_COMPARE(hpte_v, want_v) || !(hpte_v & HPTE_V_VALID))
		native_unlock_hpte(hptep);
	else
		/* Invalidate the hpte. NOTE: this also unlocks it */
		hptep->v = 0;

	/* Invalidate the TLB */
#ifndef CONFIG_BIGMEM
	tlbie(va, psize, ssize, local);
#else
	tlbie(vpn, psize, ssize, local);
#endif

	local_irq_restore(flags);
}

#define LP_SHIFT	12
#define LP_BITS		8
#define LP_MASK(i)	((0xFF >> (i)) << LP_SHIFT)

static void hpte_decode(struct hash_pte *hpte, unsigned long slot,
#ifndef CONFIG_BIGMEM
			int *psize, int *ssize, unsigned long *va)
#else
			int *psize, int *ssize, unsigned long *vpn)
#endif
{
#ifdef CONFIG_BIGMEM
	unsigned long avpn, pteg, vpi;
#endif
	unsigned long hpte_r = hpte->r;
	unsigned long hpte_v = hpte->v;
#ifndef CONFIG_BIGMEM
	unsigned long avpn;
#else
	unsigned long vsid, seg_off;
#endif
	int i, size, shift, penc;

	if (!(hpte_v & HPTE_V_LARGE))
		size = MMU_PAGE_4K;
	else {
		for (i = 0; i < LP_BITS; i++) {
			if ((hpte_r & LP_MASK(i+1)) == LP_MASK(i+1))
				break;
		}
		penc = LP_MASK(i+1) >> LP_SHIFT;
		for (size = 0; size < MMU_PAGE_COUNT; size++) {

			/* 4K pages are not represented by LP */
			if (size == MMU_PAGE_4K)
				continue;

			/* valid entries have a shift value */
			if (!mmu_psize_defs[size].shift)
				continue;

			if (penc == mmu_psize_defs[size].penc)
				break;
		}
	}

	/* This works for all page sizes, and for 256M and 1T segments */
#ifdef CONFIG_BIGMEM
	*ssize = hpte_v >> HPTE_V_SSIZE_SHIFT;
#endif
	shift = mmu_psize_defs[size].shift;
#ifndef CONFIG_BIGMEM
	avpn = (HPTE_V_AVPN_VAL(hpte_v) & ~mmu_psize_defs[size].avpnm) << 23;
#endif

#ifndef CONFIG_BIGMEM
	if (shift < 23) {
		unsigned long vpi, vsid, pteg;
#else
	avpn = (HPTE_V_AVPN_VAL(hpte_v) & ~mmu_psize_defs[size].avpnm);
	pteg = slot / HPTES_PER_GROUP;
	if (hpte_v & HPTE_V_SECONDARY)
		pteg = ~pteg;
#endif

#ifndef CONFIG_BIGMEM
		pteg = slot / HPTES_PER_GROUP;
		if (hpte_v & HPTE_V_SECONDARY)
			pteg = ~pteg;
		switch (hpte_v >> HPTE_V_SSIZE_SHIFT) {
		case MMU_SEGSIZE_256M:
			vpi = ((avpn >> 28) ^ pteg) & htab_hash_mask;
			break;
		case MMU_SEGSIZE_1T:
			vsid = avpn >> 40;
#else
	switch (*ssize) {
	case MMU_SEGSIZE_256M:
		/* We only have 28 - 23 bits of seg_off in avpn */
		seg_off = (avpn & 0x1f) << 23;
		vsid    =  avpn >> 5;
		/* We can find more bits from the pteg value */
		if (shift < 23) {
			vpi = (vsid ^ pteg) & htab_hash_mask;
			seg_off |= vpi << shift;
		}
		*vpn = vsid << (SID_SHIFT - VPN_SHIFT) | seg_off >> VPN_SHIFT;
	case MMU_SEGSIZE_1T:
		/* We only have 40 - 23 bits of seg_off in avpn */
		seg_off = (avpn & 0x1ffff) << 23;
		vsid    = avpn >> 17;
		if (shift < 23) {
#endif
			vpi = (vsid ^ (vsid << 25) ^ pteg) & htab_hash_mask;
#ifndef CONFIG_BIGMEM
			break;
		default:
			avpn = vpi = size = 0;
#else
			seg_off |= vpi << shift;
#endif
		}
#ifndef CONFIG_BIGMEM
		avpn |= (vpi << mmu_psize_defs[size].shift);
#else
		*vpn = vsid << (SID_SHIFT_1T - VPN_SHIFT) | seg_off >> VPN_SHIFT;
	default:
		*vpn = size = 0;
#endif
	}
#ifndef CONFIG_BIGMEM

	*va = avpn;
#endif
	*psize = size;
#ifndef CONFIG_BIGMEM
	*ssize = hpte_v >> HPTE_V_SSIZE_SHIFT;
#endif
}

/*
 * clear all mappings on kexec.  All cpus are in real mode (or they will
 * be when they isi), and we are the only one left.  We rely on our kernel
 * mapping being 0xC0's and the hardware ignoring those two real bits.
 *
 * TODO: add batching support when enabled.  remember, no dynamic memory here,
 * athough there is the control page available...
 */
static void native_hpte_clear(void)
{
#ifdef CONFIG_BIGMEM
	unsigned long vpn = 0;
#endif
	unsigned long slot, slots, flags;
	struct hash_pte *hptep = htab_address;
#ifndef CONFIG_BIGMEM
	unsigned long hpte_v, va;
#else
	unsigned long hpte_v;
#endif
	unsigned long pteg_count;
	int psize, ssize;

	pteg_count = htab_hash_mask + 1;

	local_irq_save(flags);

	/* we take the tlbie lock and hold it.  Some hardware will
	 * deadlock if we try to tlbie from two processors at once.
	 */
	raw_spin_lock(&native_tlbie_lock);

	slots = pteg_count * HPTES_PER_GROUP;

	for (slot = 0; slot < slots; slot++, hptep++) {
		/*
		 * we could lock the pte here, but we are the only cpu
		 * running,  right?  and for crash dump, we probably
		 * don't want to wait for a maybe bad cpu.
		 */
		hpte_v = hptep->v;

		/*
		 * Call __tlbie() here rather than tlbie() since we
		 * already hold the native_tlbie_lock.
		 */
		if (hpte_v & HPTE_V_VALID) {
#ifndef CONFIG_BIGMEM
			hpte_decode(hptep, slot, &psize, &ssize, &va);
#else
			hpte_decode(hptep, slot, &psize, &ssize, &vpn);
#endif
			hptep->v = 0;
#ifndef CONFIG_BIGMEM
			__tlbie(va, psize, ssize);
#else
			__tlbie(vpn, psize, ssize);
#endif
		}
	}

	asm volatile("eieio; tlbsync; ptesync":::"memory");
	raw_spin_unlock(&native_tlbie_lock);
	local_irq_restore(flags);
}

/*
 * Batched hash table flush, we batch the tlbie's to avoid taking/releasing
 * the lock all the time
 */
static void native_flush_hash_range(unsigned long number, int local)
{
#ifndef CONFIG_BIGMEM
	unsigned long va, hash, index, hidx, shift, slot;
#else
	unsigned long vpn;
	unsigned long hash, index, hidx, shift, slot;
#endif
	struct hash_pte *hptep;
	unsigned long hpte_v;
	unsigned long want_v;
	unsigned long flags;
	real_pte_t pte;
	struct ppc64_tlb_batch *batch = &__get_cpu_var(ppc64_tlb_batch);
	unsigned long psize = batch->psize;
	int ssize = batch->ssize;
	int i;

	local_irq_save(flags);

	for (i = 0; i < number; i++) {
#ifndef CONFIG_BIGMEM
		va = batch->vaddr[i];
#else
		vpn = batch->vpn[i];
#endif
		pte = batch->pte[i];

#ifndef CONFIG_BIGMEM
		pte_iterate_hashed_subpages(pte, psize, va, index, shift) {
			hash = hpt_hash(va, shift, ssize);
#else
		pte_iterate_hashed_subpages(pte, psize, vpn, index, shift) {
			hash = hpt_hash(vpn, shift, ssize);
#endif
			hidx = __rpte_to_hidx(pte, index);
			if (hidx & _PTEIDX_SECONDARY)
				hash = ~hash;
			slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
			slot += hidx & _PTEIDX_GROUP_IX;
			hptep = htab_address + slot;
#ifndef CONFIG_BIGMEM
			want_v = hpte_encode_v(va, psize, ssize);
#else
			want_v = hpte_encode_v(vpn, psize, ssize);
#endif
			native_lock_hpte(hptep);
			hpte_v = hptep->v;
			if (!HPTE_V_COMPARE(hpte_v, want_v) ||
			    !(hpte_v & HPTE_V_VALID))
				native_unlock_hpte(hptep);
			else
				hptep->v = 0;
		} pte_iterate_hashed_end();
	}

	if (mmu_has_feature(MMU_FTR_TLBIEL) &&
	    mmu_psize_defs[psize].tlbiel && local) {
		asm volatile("ptesync":::"memory");
		for (i = 0; i < number; i++) {
#ifndef CONFIG_BIGMEM
			va = batch->vaddr[i];
#else
			vpn = batch->vpn[i];
#endif
			pte = batch->pte[i];

#ifndef CONFIG_BIGMEM
			pte_iterate_hashed_subpages(pte, psize, va, index,
						    shift) {
				__tlbiel(va, psize, ssize);
#else
			pte_iterate_hashed_subpages(pte, psize,
						    vpn, index, shift) {
				__tlbiel(vpn, psize, ssize);
#endif
			} pte_iterate_hashed_end();
		}
		asm volatile("ptesync":::"memory");
	} else {
		int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);

		if (lock_tlbie)
			raw_spin_lock(&native_tlbie_lock);

		asm volatile("ptesync":::"memory");
		for (i = 0; i < number; i++) {
#ifndef CONFIG_BIGMEM
			va = batch->vaddr[i];
#else
			vpn = batch->vpn[i];
#endif
			pte = batch->pte[i];

#ifndef CONFIG_BIGMEM
			pte_iterate_hashed_subpages(pte, psize, va, index,
						    shift) {
				__tlbie(va, psize, ssize);
#else
			pte_iterate_hashed_subpages(pte, psize,
						    vpn, index, shift) {
				__tlbie(vpn, psize, ssize);
#endif
			} pte_iterate_hashed_end();
		}
		asm volatile("eieio; tlbsync; ptesync":::"memory");

		if (lock_tlbie)
			raw_spin_unlock(&native_tlbie_lock);
	}

	local_irq_restore(flags);
}

#ifdef CONFIG_PPC_PSERIES
/* Disable TLB batching on nighthawk */
static inline int tlb_batching_enabled(void)
{
	struct device_node *root = of_find_node_by_path("/");
	int enabled = 1;

	if (root) {
		const char *model = of_get_property(root, "model", NULL);
		if (model && !strcmp(model, "IBM,9076-N81"))
			enabled = 0;
		of_node_put(root);
	}

	return enabled;
}
#else
static inline int tlb_batching_enabled(void)
{
	return 1;
}
#endif

void __init hpte_init_native(void)
{
	ppc_md.hpte_invalidate	= native_hpte_invalidate;
	ppc_md.hpte_updatepp	= native_hpte_updatepp;
	ppc_md.hpte_updateboltedpp = native_hpte_updateboltedpp;
	ppc_md.hpte_insert	= native_hpte_insert;
	ppc_md.hpte_remove	= native_hpte_remove;
	ppc_md.hpte_clear_all	= native_hpte_clear;
	if (tlb_batching_enabled())
		ppc_md.flush_hash_range = native_flush_hash_range;
}
