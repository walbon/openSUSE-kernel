/*
 * This file is part of the Chelsio T4 Ethernet driver for Linux.
 *
 * Copyright (c) 2003-2010 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __CXGB4_COMPAT_H__
#define __CXGB4_COMPAT_H__

#include <linux/ethtool.h>
#include <linux/in6.h>
#include <linux/ctype.h>
#include <net/sch_generic.h>

#define IPV4_FLOW       0x10
#define IPV6_FLOW       0x11

#define __devnet(nd)                            \
        ((nd)                                   \
         ? ((nd)->dev.parent            \
            ?                           \
            : 0)                                \
         : 0)

#ifndef netdev_printk
#define netdev_printk(level, netdev, format, arg...)                    \
        printk(level "%s %s %s: " format , (netdev)->name ,             \
               (__devnet(netdev)                                        \
                ? __devnet(netdev)->driver->name                        \
                : "") ,                                                 \
               (__devnet(netdev)                                        \
                ? __devnet(netdev)->bus->name                           \
                : "") , ## arg)
#endif

#ifndef netdev_info
#define netdev_info(netdev, format, arg...)     \
        netdev_printk(KERN_INFO , netdev , format , ## arg)
#endif

#ifndef netdev_uc_count
#define netdev_uc_count(netdev)                 0
#endif
#ifndef netdev_for_each_uc_addr
#define netdev_for_each_uc_addr(ha, dev)        if (0)
#endif

#define dev_addr_list   dev_mc_list
#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(d, dev)         \
        for ((d) = (dev)->mc_list; (d); (d) = (d)->next)
#endif

#if 0 // defined in PCIe patches
static inline u32 pci_pcie_cap(struct pci_dev *pci)
{
        return pci_find_capability(pci, PCI_CAP_ID_EXP);
}
#endif

static inline char *skip_spaces(const char *str)
{
        while (isspace(*str))
                ++str;
        return (char *)str;
}

static inline char *strim(char *s)
{
        size_t size;
        char *end;

        s = skip_spaces(s);
        size = strlen(s);
        if (!size)
                return s;

        end = s + size - 1;
        while (end >= s && isspace(*end))
                end--;
        *(end + 1) = '\0';

        return s;
}

#define ethtool_op_set_flags compat_ethtool_op_set_flags

static const u32 flags_dup_features =
        (ETH_FLAG_LRO | ETH_FLAG_NTUPLE | ETH_FLAG_RXHASH);


static inline int compat_ethtool_op_set_flags(struct net_device *dev, u32 data, u32 supported)
{
       if (data & ~supported)
                 return -EINVAL;

       dev->features = ((dev->features & ~flags_dup_features) |
                         (data & flags_dup_features));
       return 0;
}

#define PCI_VPD_INFO_FLD_HDR_SIZE       3

#define PCI_VPD_LRDT                    0x80    /* Large Resource Data Type */
#define PCI_VPD_LRDT_ID(x)              (x | PCI_VPD_LRDT)

/* Large Resource Data Type Tag Item Names */
#define PCI_VPD_LTIN_ID_STRING          0x02    /* Identifier String */
#define PCI_VPD_LTIN_RO_DATA            0x10    /* Read-Only Data */
#define PCI_VPD_LTIN_RW_DATA            0x11    /* Read-Write Data */

#define PCI_VPD_LRDT_ID_STRING          PCI_VPD_LRDT_ID(PCI_VPD_LTIN_ID_STRING)
#define PCI_VPD_LRDT_RO_DATA            PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RO_DATA)
#define PCI_VPD_LRDT_RW_DATA            PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RW_DATA)

/* Small Resource Data Type Tag Item Names */
#define PCI_VPD_STIN_END                0x78    /* End */

#define PCI_VPD_SRDT_END                PCI_VPD_STIN_END

#define PCI_VPD_SRDT_TIN_MASK           0x78
#define PCI_VPD_SRDT_LEN_MASK           0x07

#define PCI_VPD_LRDT_TAG_SIZE           3
#define PCI_VPD_SRDT_TAG_SIZE           1


/**
* pci_vpd_lrdt_size - Extracts the Large Resource Data Type length
* @lrdt: Pointer to the beginning of the Large Resource Data Type tag
*
* Returns the extracted Large Resource Data Type length.
*/
static inline u16 pci_vpd_lrdt_size(const u8 *lrdt)
{
        return (u16)lrdt[1] + ((u16)lrdt[2] << 8);
}

/**
 * pci_vpd_srdt_size - Extracts the Small Resource Data Type length
 * @lrdt: Pointer to the beginning of the Small Resource Data Type tag
 *
 * Returns the extracted Small Resource Data Type length.
 */
static inline u8 pci_vpd_srdt_size(const u8 *srdt)
{
        return (*srdt) & PCI_VPD_SRDT_LEN_MASK;
}



static inline u8 pci_vpd_info_field_size(const u8 *info_field)
{
        return info_field[2];
}

static inline int pci_vpd_find_info_keyword(const u8 *buf, unsigned int off,
                                        unsigned int len, const char *kw)
{
        int i;

        for (i = off; i + PCI_VPD_INFO_FLD_HDR_SIZE <= off + len;) {
                if (buf[i + 0] == kw[0] &&
                    buf[i + 1] == kw[1])
                        return i;

                i += PCI_VPD_INFO_FLD_HDR_SIZE +
                        pci_vpd_info_field_size(&buf[i]);
        }

        return -ENOENT;
}

static inline int pci_vpd_find_tag(const u8 *buf, unsigned int off, unsigned int len, u8 rdt)
{
        int i;

        for (i = off; i < len; ) {
                u8 val = buf[i];

                if (val & PCI_VPD_LRDT) {
                        /* Don't return success of the tag isn't complete */
                        if (i + PCI_VPD_LRDT_TAG_SIZE > len)
                                break;

                        if (val == rdt)
                                return i;

                        i += PCI_VPD_LRDT_TAG_SIZE +
                             pci_vpd_lrdt_size(&buf[i]);
                } else {
                        u8 tag = val & ~PCI_VPD_SRDT_LEN_MASK;

                        if (tag == rdt)
                                return i;

                        if (tag == PCI_VPD_SRDT_END)
                                break;

                        i += PCI_VPD_SRDT_TAG_SIZE +
                             pci_vpd_srdt_size(&buf[i]);
                }
        }

        return -ENOENT;
}

#define NUMA_NO_NODE    (-1)

static inline int netdev_queue_numa_node_read(const struct netdev_queue *q)
{
        return NUMA_NO_NODE;
}


#endif /* __CXGB4_COMPAT_H__ */
