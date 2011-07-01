/*
 * QLogic ISCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 *
 * PCI searching functions pci_get_domain_bus_and_slot & pci_channel_offline
 * Copyright (C) 1993 -- 1997 Drew Eckhardt, Frederic Potter,
 *                                      David Mosberger-Tang
 * Copyright (C) 1997 -- 2000 Martin Mares <mj@ucw.cz>
 * Copyright (C) 2003 -- 2004 Greg Kroah-Hartman <greg@kroah.com>.
 */

#ifndef __QLA_KCOMPAT_H
#define __QLA_KCOMPAT_H

#include <linux/version.h>
#include <linux/pci.h>

#if defined (QL4_RHEL6)
static inline struct pci_dev *pci_get_domain_bus_and_slot(int domain, unsigned int bus,
		unsigned int devfn)
{
	struct pci_dev *dev = NULL;

	while ((dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev)) != NULL) {
		if (pci_domain_nr(dev->bus) == domain &&
		    (dev->bus->number == bus && dev->devfn == devfn))
			return dev;
	}
	return NULL;
}
#endif

#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32))
/*
 * Display an IP address in readable format.
 */

#define NIP6(addr) \
        ntohs((addr).s6_addr16[0]), \
        ntohs((addr).s6_addr16[1]), \
        ntohs((addr).s6_addr16[2]), \
        ntohs((addr).s6_addr16[3]), \
        ntohs((addr).s6_addr16[4]), \
        ntohs((addr).s6_addr16[5]), \
        ntohs((addr).s6_addr16[6]), \
        ntohs((addr).s6_addr16[7])

#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define NIP6_SEQFMT "%04x%04x%04x%04x%04x%04x%04x%04x"
#endif
#endif
