/*
 *  Copyright IBM Corp. 2008
 *  Author(s): Martin Schwidefsky (schwidefsky@de.ibm.com)
 */

#define KMSG_COMPONENT "cpu"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/cpu.h>
#include <asm/diag.h>
#include <asm/elf.h>
#include <asm/lowcore.h>
#include <asm/param.h>
#include <asm/smp.h>

static DEFINE_PER_CPU(struct cpuid, cpu_id);

void notrace cpu_relax(void)
{
	if (!smp_cpu_mtid && MACHINE_HAS_DIAG44) {
		diag_stat_inc(DIAG_STAT_X044);
		asm volatile("diag 0,0,0x44");
	}
	barrier();
}
EXPORT_SYMBOL(cpu_relax);

/*
 * cpu_init - initializes state that is per-CPU.
 */
void cpu_init(void)
{
	struct cpuid *id = this_cpu_ptr(&cpu_id);

	get_cpu_id(id);
	atomic_inc(&init_mm.mm_count);
	current->active_mm = &init_mm;
	BUG_ON(current->mm);
	enter_lazy_tlb(&init_mm, current);
}

/*
 * cpu_have_feature - Test CPU features on module initialization
 */
int cpu_have_feature(unsigned int num)
{
	return elf_hwcap & (1UL << num);
}
EXPORT_SYMBOL(cpu_have_feature);

/*
 * show_cpuinfo - Get information on one CPU for use by procfs.
 */
static int show_cpuinfo(struct seq_file *m, void *v)
{
	static const char *hwcap_str[] = {
		"esan3", "zarch", "stfle", "msa", "ldisp", "eimm", "dfp",
		"edat", "etf3eh", "highgprs", "te", "vx"
	};
	static const char * const int_hwcap_str[] = {
		"sie"
	};
	unsigned long n = (unsigned long) v - 1;
	int i;

	if (!n) {
		s390_adjust_jiffies();
		seq_printf(m, "vendor_id       : IBM/S390\n"
			   "# processors    : %i\n"
			   "bogomips per cpu: %lu.%02lu\n",
			   num_online_cpus(), loops_per_jiffy/(500000/HZ),
			   (loops_per_jiffy/(5000/HZ))%100);
		seq_printf(m, "max thread id   : %d\n", smp_cpu_mtid);
		seq_puts(m, "features\t: ");
		for (i = 0; i < ARRAY_SIZE(hwcap_str); i++)
			if (hwcap_str[i] && (elf_hwcap & (1UL << i)))
				seq_printf(m, "%s ", hwcap_str[i]);
		for (i = 0; i < ARRAY_SIZE(int_hwcap_str); i++)
			if (int_hwcap_str[i] && (int_hwcap & (1UL << i)))
				seq_printf(m, "%s ", int_hwcap_str[i]);
		seq_puts(m, "\n");
		show_cacheinfo(m);
	}
	get_online_cpus();
	if (cpu_online(n)) {
		struct cpuid *id = &per_cpu(cpu_id, n);
		seq_printf(m, "processor %li: "
			   "version = %02X,  "
			   "identification = %06X,  "
			   "machine = %04X\n",
			   n, id->version, id->ident, id->machine);
	}
	put_online_cpus();
	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < nr_cpu_ids ? (void *)((unsigned long) *pos + 1) : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= show_cpuinfo,
};

