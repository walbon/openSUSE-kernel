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
static unsigned int ibpb_state = 0;

unsigned int notrace x86_ibrs_enabled(void)
{
	return ibrs_state;
}
EXPORT_SYMBOL_GPL(x86_ibrs_enabled);

unsigned int notrace x86_ibpb_enabled(void)
{
	return ibpb_state;
}
EXPORT_SYMBOL_GPL(x86_ibpb_enabled);

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

/*
 * Called after upgrading microcode, check CPUID directly.
 */
void x86_spec_check(void)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
		if (cpuid_edx(7) & BIT(26)) {
			ibrs_state = 1;
			ibpb_state = 1;

			setup_force_cpu_cap(X86_FEATURE_SPEC_CTRL);
		}
	}
}
EXPORT_SYMBOL_GPL(x86_spec_check);
