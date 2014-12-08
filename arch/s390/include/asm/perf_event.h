/*
 * Performance event support - s390 specific definitions.
 *
 * Copyright IBM Corp. 2009, 2012
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 *	      Hendrik Brueckner <brueckner@linux.vnet.ibm.com>
 */

#include <asm/cpu_mf.h>


/* Per-CPU flags for PMU states */
#define PMU_F_RESERVED			0x1000
#define PMU_F_ENABLED			0x2000
#define PMU_F_IN_USE			0x4000
#define PMU_F_ERR_IBE			0x0100
#define PMU_F_ERR_LSDA			0x0200
#define PMU_F_ERR_MASK			(PMU_F_ERR_IBE|PMU_F_ERR_LSDA)

#ifdef CONFIG_64BIT

/* Perf callbacks */
struct pt_regs;
extern unsigned long perf_instruction_pointer(struct pt_regs *regs);
extern unsigned long perf_misc_flags(struct pt_regs *regs);
#define perf_misc_flags(regs) perf_misc_flags(regs)

/* Perf pt_regs extension for sample-data-entry indicators */
struct perf_sf_sde_regs {
	unsigned char in_guest:1;	  /* guest sample */
	unsigned long reserved:63;	  /* reserved */
};

/* Perf PMU definitions for the counter facility */
#define PERF_CPUM_CF_MAX_CTR		256

/* Perf PMU definitions for the sampling facility */
#define PERF_CPUM_SF_MAX_CTR		2
#define PERF_EVENT_CPUM_SF		0xB0000UL /* Event: Basic-sampling */
#define PERF_EVENT_CPUM_SF_DIAG		0xBD000UL /* Event: Combined-sampling */
#define PERF_CPUM_SF_BASIC_MODE		0x0001	  /* Basic-sampling flag */
#define PERF_CPUM_SF_DIAG_MODE		0x0002	  /* Diagnostic-sampling flag */
#define PERF_CPUM_SF_MODE_MASK		(PERF_CPUM_SF_BASIC_MODE| \
					 PERF_CPUM_SF_DIAG_MODE)

#define REG_NONE		0
#define REG_OVERFLOW		1
#define OVERFLOW_REG(hwc)	((hwc)->extra_reg.config)
#define SFB_ALLOC_REG(hwc)	((hwc)->extra_reg.alloc)
#define RAWSAMPLE_REG(hwc)	((hwc)->config)
#define TEAR_REG(hwc)		((hwc)->last_tag)
#define SAMPL_RATE(hwc)		((hwc)->event_base)
#define SAMPL_FLAGS(hwc)	((hwc)->config_base)
#define SAMPL_DIAG_MODE(hwc)	(SAMPL_FLAGS(hwc) & PERF_CPUM_SF_DIAG_MODE)

/* Structure for sampling data entries to be passed as perf raw sample data
 * to user space.  Note that raw sample data must be aligned and, thus, might
 * be padded with zeros.
 */
struct sf_raw_sample {
#define SF_RAW_SAMPLE_BASIC	PERF_CPUM_SF_BASIC_MODE
#define SF_RAW_SAMPLE_DIAG	PERF_CPUM_SF_DIAG_MODE
	u64			format;
	u32			 size;	  /* Size of sf_raw_sample */
	u16			bsdes;	  /* Basic-sampling data entry size */
	u16			dsdes;	  /* Diagnostic-sampling data entry size */
	struct hws_basic_entry	basic;	  /* Basic-sampling data entry */
	struct hws_diag_entry	 diag;	  /* Diagnostic-sampling data entry */
	u8		    padding[];	  /* Padding to next multiple of 8 */
} __packed;

/* Perf hardware reserve and release functions */
int perf_reserve_sampling(void);
void perf_release_sampling(void);

#endif /* CONFIG_64BIT */
