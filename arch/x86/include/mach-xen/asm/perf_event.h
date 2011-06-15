#ifndef _ASM_X86_PERF_EVENT_H
#define _ASM_X86_PERF_EVENT_H

#ifdef CONFIG_PERF_EVENTS

/*
 * Abuse bit 3 of the cpu eflags register to indicate proper PEBS IP fixups.
 * This flag is otherwise unused and ABI specified to be 0, so nobody should
 * care what we do with it.
 */
#define PERF_EFLAGS_EXACT	(1UL << 3)

#endif

static inline void init_hw_perf_events(void) {}

#endif /* _ASM_X86_PERF_EVENT_H */
