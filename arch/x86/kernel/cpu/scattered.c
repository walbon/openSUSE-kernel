/*
 *	Routines to identify additional cpu features that are scattered in
 *	cpuid space.
 */
#include <linux/cpu.h>

#include <asm/pat.h>
#include <asm/processor.h>

#include <asm/apic.h>

struct cpuid_bit {
	u16 feature;
	u8 reg;
	u8 bit;
	u32 level;
	u32 sub_leaf;
};

void init_scattered_cpuid_features(struct cpuinfo_x86 *c)
{
	u32 max_level;
	u32 regs[4];
	const struct cpuid_bit *cb;

	static const struct cpuid_bit cpuid_bits[] = {
		{ X86_FEATURE_DTHERM,		CPUID_EAX, 0, 0x00000006, 0 },
		{ X86_FEATURE_IDA,		CPUID_EAX, 1, 0x00000006, 0 },
		{ X86_FEATURE_ARAT,		CPUID_EAX, 2, 0x00000006, 0 },
		{ X86_FEATURE_PLN,		CPUID_EAX, 4, 0x00000006, 0 },
		{ X86_FEATURE_PTS,		CPUID_EAX, 6, 0x00000006, 0 },
		{ X86_FEATURE_HWP,		CPUID_EAX, 7, 0x00000006, 0 },
		{ X86_FEATURE_HWP_NOTIFY,	CPUID_EAX, 8, 0x00000006, 0 },
		{ X86_FEATURE_HWP_ACT_WINDOW,	CPUID_EAX, 9, 0x00000006, 0 },
		{ X86_FEATURE_HWP_EPP,		CPUID_EAX,10, 0x00000006, 0 },
		{ X86_FEATURE_HWP_PKG_REQ,	CPUID_EAX,11, 0x00000006, 0 },
		{ X86_FEATURE_INTEL_PT,		CPUID_EBX,25, 0x00000007, 0 },
		{ X86_FEATURE_AVX512_4VNNIW,	CPUID_EDX, 2, 0x00000007, 0 },
		{ X86_FEATURE_AVX512_4FMAPS,	CPUID_EDX, 3, 0x00000007, 0 },
		{ X86_FEATURE_APERFMPERF,	CPUID_ECX, 0, 0x00000006, 0 },
		{ X86_FEATURE_EPB,		CPUID_ECX, 3, 0x00000006, 0 },
		{ X86_FEATURE_HW_PSTATE,	CPUID_EDX, 7, 0x80000007, 0 },
		{ X86_FEATURE_CPB,		CPUID_EDX, 9, 0x80000007, 0 },
		{ X86_FEATURE_PROC_FEEDBACK,	CPUID_EDX,11, 0x80000007, 0 },
		{ X86_FEATURE_NPT,		CPUID_EDX, 0, 0x8000000a, 0 },
		{ X86_FEATURE_LBRV,		CPUID_EDX, 1, 0x8000000a, 0 },
		{ X86_FEATURE_SVML,		CPUID_EDX, 2, 0x8000000a, 0 },
		{ X86_FEATURE_NRIPS,		CPUID_EDX, 3, 0x8000000a, 0 },
		{ X86_FEATURE_TSCRATEMSR,	CPUID_EDX, 4, 0x8000000a, 0 },
		{ X86_FEATURE_VMCBCLEAN,	CPUID_EDX, 5, 0x8000000a, 0 },
		{ X86_FEATURE_FLUSHBYASID,	CPUID_EDX, 6, 0x8000000a, 0 },
		{ X86_FEATURE_DECODEASSISTS,	CPUID_EDX, 7, 0x8000000a, 0 },
		{ X86_FEATURE_PAUSEFILTER,	CPUID_EDX,10, 0x8000000a, 0 },
		{ X86_FEATURE_PFTHRESHOLD,	CPUID_EDX,12, 0x8000000a, 0 },
		{ X86_FEATURE_AVIC,		CPUID_EDX,13, 0x8000000a, 0 },
		{ 0, 0, 0, 0, 0 }
	};

	for (cb = cpuid_bits; cb->feature; cb++) {

		/* Verify that the level is valid */
		max_level = cpuid_eax(cb->level & 0xffff0000);
		if (max_level < cb->level ||
		    max_level > (cb->level | 0xffff))
			continue;

		cpuid_count(cb->level, cb->sub_leaf, &regs[CPUID_EAX],
			    &regs[CPUID_EBX], &regs[CPUID_ECX],
			    &regs[CPUID_EDX]);

		if (regs[cb->reg] & (1 << cb->bit))
			set_cpu_cap(c, cb->feature);
	}
}
