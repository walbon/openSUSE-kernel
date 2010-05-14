/*
 * A clocksource for Linux running on HyperV.
 *
 *
 * Copyright (C) 2010, Novell, Inc.
 * Author : K. Y. Srinivasan <ksrinivasan@novell.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <linux/version.h>
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/dmi.h>

#define HV_CLOCK_SHIFT	22
/*
 * HyperV defined synthetic CPUID leaves:
 */
#define HV_CPUID_SIGNATURE	0x40000000
#define HV_CPUID_MIN		0x40000005
#define HV_HYPERVISOR_PRESENT_BIT	0x80000000
#define HV_CPUID_FEATURES	0x40000003
#define HV_CPUID_RECOMMENDATIONS	0x40000004

/*
 * HyperV defined synthetic MSRs
 */

#define HV_X64_MSR_TIME_REF_COUNT	0x40000020


static cycle_t read_hv_clock(struct clocksource *arg)
{
	cycle_t current_tick;
	/*
	 * Read the partition counter to get the current tick count. This count
	 * is set to 0 when the partition is created and is incremented in
	 * 100 nanosecond units.
	 */
	rdmsrl(HV_X64_MSR_TIME_REF_COUNT, current_tick);
	return current_tick;
}

static struct clocksource hyperv_cs = {
	.name           = "hyperv_clocksource",
	.rating         = 400, /* use this when running on Hyperv*/
	.read           = read_hv_clock,
	.mask           = CLOCKSOURCE_MASK(64),
	/*
	 * The time ref counter in HyperV is in 100ns units.
	 * The definition of mult is:
	 * mult/2^shift = ns/cyc = 100
	 * mult = (100 << shift)
	 */
	.mult           = (100 << HV_CLOCK_SHIFT),
	.shift          = HV_CLOCK_SHIFT,
};

static const struct dmi_system_id __initconst
hv_timesource_dmi_table[] __maybe_unused  = {
	{
		.ident = "Hyper-V",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Microsoft Corporation"),
			DMI_MATCH(DMI_PRODUCT_NAME, "Virtual Machine"),
			DMI_MATCH(DMI_BOARD_NAME, "Virtual Machine"),
		},
	},
	{ },
};
MODULE_DEVICE_TABLE(dmi, hv_timesource_dmi_table);

static const struct pci_device_id __initconst
hv_timesource_pci_table[] __maybe_unused = {
	{ PCI_DEVICE(0x1414, 0x5353) }, /* VGA compatible controller */
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, hv_timesource_pci_table);


static int __init hv_detect_hyperv(void)
{
	u32 eax, ebx, ecx, edx;
	char hyp_signature[13];

	cpuid(1, &eax, &ebx, &ecx, &edx);

	if (!(ecx & HV_HYPERVISOR_PRESENT_BIT))
		return 1;

	cpuid(HV_CPUID_SIGNATURE, &eax, &ebx, &ecx, &edx);
	*(u32 *)(hyp_signature + 0) = ebx;
	*(u32 *)(hyp_signature + 4) = ecx;
	*(u32 *)(hyp_signature + 8) = edx;

	if ((eax < HV_CPUID_MIN) || (memcmp("Microsoft Hv", hyp_signature, 12)))
		return 1;

	/*
	 * Extract the features, recommendations etc.
	 */
	cpuid(HV_CPUID_FEATURES, &eax, &ebx, &ecx, &edx);
	if (!(eax & 0x10)) {
		printk(KERN_WARNING "HyperV Time Ref Counter not available!\n");
		return 1;
	}

	cpuid(HV_CPUID_RECOMMENDATIONS, &eax, &ebx, &ecx, &edx);
	printk(KERN_INFO "HyperV recommendations: %x\n", eax);
	printk(KERN_INFO "HyperV spin count: %x\n", ebx);
	return 0;
}


static int __init init_hv_clocksource(void)
{
	if (hv_detect_hyperv())
		return -ENODEV;

	if (!dmi_check_system(hv_timesource_dmi_table))
		return -ENODEV;

	printk(KERN_INFO "Registering HyperV clock source\n");
	return clocksource_register(&hyperv_cs);
}

module_init(init_hv_clocksource);
MODULE_DESCRIPTION("HyperV based clocksource");
MODULE_AUTHOR("K. Y. Srinivasan <ksrinivasan@novell.com>");
MODULE_LICENSE("GPL");
