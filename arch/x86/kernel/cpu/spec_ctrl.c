/*
 * Speculation control stuff
 *
 */

#include <asm/msr.h>
#include <asm/proto.h>
#include <asm/processor.h>
#include <asm/spec_ctrl.h>

/*
 * Keep it open for more flags in case needed.
 */
static unsigned int ibrs_state = 0;

unsigned int notrace x86_ibrs_enabled(void)
{
	return ibrs_state;
}
EXPORT_SYMBOL_GPL(x86_ibrs_enabled);

void x86_disable_ibrs(void)
{
	if (x86_ibrs_enabled())
		native_wrmsrl(MSR_IA32_SPEC_CTRL, 0);
}
EXPORT_SYMBOL_GPL(x86_disable_ibrs);

void x86_enable_ibrs(void)
{
	if (x86_ibrs_enabled())
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
