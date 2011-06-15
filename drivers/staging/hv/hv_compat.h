
#ifndef _HV_COMPAT_H
#define _HV_COMPAT_H

#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/arp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>

#define CN_KVP_IDX	0x9

#ifndef pr_warn
#define pr_warn(fmt, arg...) printk(KERN_WARNING fmt, ##arg)
#endif


#define DEF_SCSI_QCMD(func_name) \
	int func_name(struct scsi_cmnd *cmd, \
			void (*done)(struct scsi_cmnd *))   \
	{								\
		int rc;							\
		rc = func_name##_lck(cmd, done);			\
		return rc;						\
	}

#define blk_queue_max_segments(a, b)

#ifndef netdev_err
static inline void netdev_err(struct net_device *net, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}

#endif

#ifndef netdev_dbg
#if defined(DEBUG)
#define netdev_dbg(dev, fmt, ...)  netdev_err(dev, fmt, ...)
#else
#define netdev_dbg(__dev, format, args...)                      \
({                                                              \
	if (0)                                                  \
		netdev_err(__dev, format, ##args); \
	0;                                                      \
})

#endif
#endif


#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE == 1536) && \
LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
static inline void  netif_notify_peers(struct net_device *net)
{
	struct in_device *idev;

	rcu_read_lock();
	if (((idev = __in_dev_get_rcu(net)) != NULL) &&
		idev->ifa_list != NULL) {
		arp_send(ARPOP_REQUEST, ETH_P_ARP,
		idev->ifa_list->ifa_address, net,
		idev->ifa_list->ifa_address, NULL,
		net->dev_addr, NULL);
	}
	rcu_read_unlock();
}

#endif
#endif
