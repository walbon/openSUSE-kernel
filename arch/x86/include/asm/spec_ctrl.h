#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <linux/stringify.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/alternative-asm.h>

#ifdef __ASSEMBLY__

.macro __ENABLE_IBRS_CLOBBER
	movl $MSR_IA32_SPEC_CTRL, %ecx
	xorl %edx, %edx
	movl $FEATURE_ENABLE_IBRS, %eax
	wrmsr
.endm

.macro ENABLE_IBRS_CLOBBER
	ALTERNATIVE "jmp .Lend_\@", "", X86_FEATURE_SPEC_CTRL
	__ENABLE_IBRS_CLOBBER
.Lend_\@:
.endm


.macro ENABLE_IBRS
	ALTERNATIVE "jmp .Lend_\@", "", X86_FEATURE_SPEC_CTRL
	pushq %rax
	pushq %rcx
	pushq %rdx
	__ENABLE_IBRS_CLOBBER
	popq %rdx
	popq %rcx
	popq %rax
.Lend_\@:
.endm


.macro DISABLE_IBRS
	ALTERNATIVE "jmp .Lend_\@", "", X86_FEATURE_SPEC_CTRL
	pushq %rax
	pushq %rcx
	pushq %rdx
	movl $MSR_IA32_SPEC_CTRL, %ecx
	xorl %edx, %edx
	xorl %eax, %eax
	wrmsr
	popq %rdx
	popq %rcx
	popq %rax
.Lend_\@:
.endm

.macro STUFF_RSB
	ALTERNATIVE "call stuff_rsb", "", X86_FEATURE_SMEP
.endm

#else /* __ASSEMBLY__ */
void x86_enable_ibrs(void);
void x86_disable_ibrs(void);

static inline void x86_ibp_barrier(void)
{
	if (static_cpu_has(X86_FEATURE_SPEC_CTRL))
		native_wrmsrl(MSR_IA32_PRED_CMD, FEATURE_SET_IBPB);
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
