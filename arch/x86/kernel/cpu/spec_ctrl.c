/*
 * Speculation control stuff
 *
 */

#include <asm/msr.h>
#include <asm/proto.h>
#include <asm/processor.h>
#include <asm/spec_ctrl.h>

void x86_disable_ibrs(void)
{
	if (boot_cpu_has(X86_FEATURE_SPEC_CTRL))
		native_wrmsrl(MSR_IA32_SPEC_CTRL, 0);
}
EXPORT_SYMBOL_GPL(x86_disable_ibrs);

void x86_enable_ibrs(void)
{
	if (boot_cpu_has(X86_FEATURE_SPEC_CTRL))
		native_wrmsrl(MSR_IA32_SPEC_CTRL, FEATURE_ENABLE_IBRS);
}
EXPORT_SYMBOL_GPL(x86_enable_ibrs);

/*
 * Do this indirection as otherwise we'd need to backport the
 * EXPORT_SYMBOL_GPL() for asm stuff.
 */
void stuff_RSB(void)
{
	stuff_rsb();
}
EXPORT_SYMBOL_GPL(stuff_RSB);
