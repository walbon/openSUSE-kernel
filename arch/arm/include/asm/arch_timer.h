#ifndef __ASMARM_ARCH_TIMER_H
#define __ASMARM_ARCH_TIMER_H

#include <asm/barrier.h>
#include <asm/errno.h>
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/types.h>

#include <clocksource/arm_arch_timer.h>

#ifdef CONFIG_ARM_ARCH_TIMER
int arch_timer_arch_init(void);

extern bool arm_arch_timer_reread;

/*
 * These register accessors are marked inline so the compiler can
 * nicely work out which register we want, and chuck away the rest of
 * the code. At least it does so with a recent GCC (4.6.3).
 */
static __always_inline
void arch_timer_reg_write_cp15(int access, enum arch_timer_reg reg, u32 val)
{
	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mcr p15, 0, %0, c14, c2, 1" : : "r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("mcr p15, 0, %0, c14, c2, 0" : : "r" (val));
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mcr p15, 0, %0, c14, c3, 1" : : "r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("mcr p15, 0, %0, c14, c3, 0" : : "r" (val));
			break;
		}
	}

	isb();
}

static __always_inline
u32 arch_timer_reg_read_cp15_raw(int access, enum arch_timer_reg reg)
{
	u32 val = 0;

	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mrc p15, 0, %0, c14, c2, 1" : "=r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("mrc p15, 0, %0, c14, c2, 0" : "=r" (val));
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mrc p15, 0, %0, c14, c3, 1" : "=r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("mrc p15, 0, %0, c14, c3, 0" : "=r" (val));
			break;
		}
	}

	return val;
}

static __always_inline
u32 arch_timer_reg_tval_reread(int access, enum arch_timer_reg reg)
{
	u32 val, val_new;
	int timeout = 200;

	do {
		if (access == ARCH_TIMER_PHYS_ACCESS) {
			asm volatile("mrc p15, 0, %0, c14, c2, 0;"
				     "mrc p15, 0, %1, c14, c2, 0"
				     : "=r" (val), "=r" (val_new));
		} else if (access == ARCH_TIMER_VIRT_ACCESS) {
			asm volatile("mrc p15, 0, %0, c14, c3, 0;"
				     "mrc p15, 0, %1, c14, c3, 0"
				     : "=r" (val), "=r" (val_new));
		}
		timeout--;
	} while (val != val_new && timeout);

	WARN_ON_ONCE(!timeout);
	return val;
}

static __always_inline
u32 arch_timer_reg_read_cp15(int access, enum arch_timer_reg reg)
{
	if (arm_arch_timer_reread && reg == ARCH_TIMER_REG_TVAL)
		return arch_timer_reg_tval_reread(access, reg);

	return arch_timer_reg_read_cp15_raw(access, reg);
}

static inline u32 arch_timer_get_cntfrq(void)
{
	u32 val;
	asm volatile("mrc p15, 0, %0, c14, c0, 0" : "=r" (val));
	return val;
}

static __always_inline u64 arch_counter_get_cnt(int opcode, bool reread)
{
	u64 val, val_new;
	int timeout = 200;

	isb();

	if (reread) {
		do {
			asm volatile("mrrc p15, %2, %Q0, %R0, c14;"
				     "mrrc p15, %2, %Q1, %R1, c14"
				     : "=r" (val), "=r" (val_new)
				     : "i" (opcode));
			timeout--;
		} while (val != val_new && timeout);

		BUG_ON(!timeout);
	} else {
		asm volatile("mrrc p15, %1, %Q0, %R0, c14" : "=r" (val)
			     : "i" (opcode));
	}

	return val;
}

static inline u64 arch_counter_get_cntpct(void)
{
	return arch_counter_get_cnt(0, arm_arch_timer_reread);
}

static inline u64 arch_counter_get_cntvct(void)
{
	return arch_counter_get_cnt(1, arm_arch_timer_reread);
}

static inline u32 arch_timer_get_cntkctl(void)
{
	u32 cntkctl;
	asm volatile("mrc p15, 0, %0, c14, c1, 0" : "=r" (cntkctl));
	return cntkctl;
}

static inline void arch_timer_set_cntkctl(u32 cntkctl)
{
	asm volatile("mcr p15, 0, %0, c14, c1, 0" : : "r" (cntkctl));
}

#endif

#endif
