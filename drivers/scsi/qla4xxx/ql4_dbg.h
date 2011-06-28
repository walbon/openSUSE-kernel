/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

/* Defines for interim workaround code */
/**
 *  Enabling MIXED_INTR_MODE_WORKAROUND will prevent interrupts from falling
 *  back to INTx mode in cases where interrupts cannot get acquired through
 *  MSI-X or MSI mode.  This workaround will be removed once ER71218 has been
 *  fixed in 82xx firmware.
 **/
#define MIXED_INTR_MODE_WORKAROUND    1

/*
 * Debug Print Macros
 */
#if 1
#define ql4_printk(level, ha, format, arg...)                           \
	printk("%s(%ld): %s: " format ,                                 \
	       dev_driver_string(&((ha)->pdev->dev)),			\
	       (ha)->host_no, dev_name(&((ha)->pdev->dev)), ## arg)
#else
#define ql4_printk(level, ha, format, arg...) \
	dev_printk(level , &((ha)->pdev->dev) , format , ## arg)
#endif

#define ql4_info(ha, format, arg...)    \
	ql4_printk(KERN_INFO, ha, format, ## arg)
#define ql4_warn(ha, format, arg...)    \
	ql4_printk(KERN_WARNING, ha, format, ## arg)
#define ql4_err(ha, format, arg...)     \
	ql4_printk(KERN_ERR, ha, format, ## arg)
#define ql4_dbg(ha, format, arg...)     \
	ql4_printk(KERN_DEBUG, ha, format, ## arg)

/*
 * Driver debug definitions.
 */
#define QL_DEBUG			/* DEBUG messages */
#define QL_DEBUG_LEVEL_2
/* #define QL_DEBUG_LEVEL_3  */		/* Output function tracing */
/* #define QL_DEBUG_LEVEL_4  */
/* #define QL_DEBUG_LEVEL_5  */
#define QL_DEBUG_LEVEL_6
#define QL_DEBUG_LEVEL_7

#ifndef _QL4_DBG_
#define _QL4_DBG_

#if defined(QL_DEBUG)
#define DEBUG(x)	do {if(ql4xextended_error_logging & 0x01) x;} while (0);
#else
#define DEBUG(x)
#endif

#if defined(QL_DEBUG_LEVEL_2)
#define DEBUG2(x)	do {if(ql4xextended_error_logging & 0x02) x;} while (0);
#else
#define DEBUG2(x)
#endif

#if defined(QL_DEBUG_LEVEL_3)
#define DEBUG3(x)	do {if(ql4xextended_error_logging & 0x04) x;} while (0);
#else
#define DEBUG3(x)
#endif

#if defined(QL_DEBUG_LEVEL_4)
#define DEBUG4(x)	do {if(ql4xextended_error_logging & 0x08) x;} while (0);
#else
#define DEBUG4(x)
#endif

#if defined(QL_DEBUG_LEVEL_5)
#define DEBUG5(x)	do {if(ql4xextended_error_logging & 0x10) x;} while (0);
#else
#define DEBUG5(x)
#endif

#if defined(QL_DEBUG_LEVEL_6)
#define DEBUG6(x)	do {if(ql4xextended_error_logging & 0x20) x;} while (0);
#else
#define DEBUG6(x)
#endif

#if defined(QL_DEBUG_LEVEL_7)
#define DEBUG7(x)	do {if(ql4xextended_error_logging & 0x40) x;} while (0);
#else
#define DEBUG7(x)
#endif

#endif /*_QL4_DBG_*/
