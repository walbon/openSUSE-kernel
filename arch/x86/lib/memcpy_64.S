/* Copyright 2002 Andi Kleen */

#include <linux/linkage.h>

#include <asm/cpufeature.h>
#include <asm/dwarf2.h>
#include <asm/alternative-asm.h>

/*
 * memcpy - Copy a memory block.
 *
 * Input:
 *  rdi destination
 *  rsi source
 *  rdx count
 *
 * Output:
 * rax original destination
 */

/*
 * memcpy_c() - fast string ops (REP MOVSQ) based variant.
 *
 * This gets patched over the unrolled variant (below) via the
 * alternative instructions framework:
 */
	.section .altinstr_replacement, "ax", @progbits
.Lmemcpy_c:
	movq %rdi, %rax

	movl %edx, %ecx
	shrl $3, %ecx
	andl $7, %edx
	rep movsq
	movl %edx, %ecx
	rep movsb
	ret
.Lmemcpy_e:
	.previous

/*
 * memcpy_c_e() - enhanced fast string memcpy. This is faster and simpler than
 * memcpy_c. Use memcpy_c_e when possible.
 *
 * This gets patched over the unrolled variant (below) via the
 * alternative instructions framework:
 */
	.section .altinstr_replacement, "ax", @progbits
.Lmemcpy_c_e:
	movq %rdi, %rax

	movl %edx, %ecx
	rep movsb
	ret
.Lmemcpy_e_e:
	.previous

ENTRY(__memcpy)
ENTRY(memcpy)
	CFI_STARTPROC

	/*
	 * Put the number of full 64-byte blocks into %ecx.
	 * Tail portion is handled at the end:
	 */
	movq %rdi, %rax
	movl %edx, %ecx
	shrl   $6, %ecx
	jz .Lhandle_tail

	.p2align 4
.Lloop_64:
	/*
	 * We decrement the loop index here - and the zero-flag is
	 * checked at the end of the loop (instructions inbetween do
	 * not change the zero flag):
	 */
	decl %ecx

	/*
	 * Move in blocks of 4x16 bytes:
	 */
	movq 0*8(%rsi),		%r11
	movq 1*8(%rsi),		%r8
	movq %r11,		0*8(%rdi)
	movq %r8,		1*8(%rdi)

	movq 2*8(%rsi),		%r9
	movq 3*8(%rsi),		%r10
	movq %r9,		2*8(%rdi)
	movq %r10,		3*8(%rdi)

	movq 4*8(%rsi),		%r11
	movq 5*8(%rsi),		%r8
	movq %r11,		4*8(%rdi)
	movq %r8,		5*8(%rdi)

	movq 6*8(%rsi),		%r9
	movq 7*8(%rsi),		%r10
	movq %r9,		6*8(%rdi)
	movq %r10,		7*8(%rdi)

	leaq 64(%rsi), %rsi
	leaq 64(%rdi), %rdi

	jnz  .Lloop_64

.Lhandle_tail:
	movl %edx, %ecx
	andl  $63, %ecx
	shrl   $3, %ecx
	jz   .Lhandle_7

	.p2align 4
.Lloop_8:
	decl %ecx
	movq (%rsi),		%r8
	movq %r8,		(%rdi)
	leaq 8(%rdi),		%rdi
	leaq 8(%rsi),		%rsi
	jnz  .Lloop_8

.Lhandle_7:
	movl %edx, %ecx
	andl $7, %ecx
	jz .Lend

	.p2align 4
.Lloop_1:
	movb (%rsi), %r8b
	movb %r8b, (%rdi)
	incq %rdi
	incq %rsi
	decl %ecx
	jnz .Lloop_1

.Lend:
	ret
	CFI_ENDPROC
ENDPROC(memcpy)
ENDPROC(__memcpy)

	/*
	 * Some CPUs are adding enhanced REP MOVSB/STOSB feature
	 * If the feature is supported, memcpy_c_e() is the first choice.
	 * If enhanced rep movsb copy is not available, use fast string copy
	 * memcpy_c() when possible. This is faster and code is simpler than
	 * original memcpy().
	 * Otherwise, original memcpy() is used.
	 * In .altinstructions section, ERMS feature is placed after REG_GOOD
         * feature to implement the right patch order.
	 *
	 * Replace only beginning, memcpy is used to apply alternatives,
	 * so it is silly to overwrite itself with nops - reboot is the
	 * only outcome...
	 */
	.section .altinstructions, "a"
	altinstruction_entry memcpy,.Lmemcpy_c,X86_FEATURE_REP_GOOD,\
			     .Lmemcpy_e-.Lmemcpy_c,.Lmemcpy_e-.Lmemcpy_c
	altinstruction_entry memcpy,.Lmemcpy_c_e,X86_FEATURE_ERMS, \
			     .Lmemcpy_e_e-.Lmemcpy_c_e,.Lmemcpy_e_e-.Lmemcpy_c_e
	.previous
