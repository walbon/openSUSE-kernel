#ifndef MDIO_AN_EEE_ADV
#define MDIO_AN_EEE_ADV			60
#endif

#ifndef MDIO_AN_EEE_ADV_100TX
#define MDIO_AN_EEE_ADV_100TX		0x0002
#endif

#ifndef MDIO_AN_EEE_ADV_1000T
#define MDIO_AN_EEE_ADV_1000T		0x0004
#endif

#ifndef CTL1000_AS_MASTER
#define CTL1000_AS_MASTER		0x0800
#endif

#ifndef CTL1000_ENABLE_MASTER
#define CTL1000_ENABLE_MASTER		0x1000
#endif

#define skb_tx_timestamp(skb)

#if defined(CONFIG_X86_64) || defined(CONFIG_DMAR) || defined(CONFIG_DMA_API_DEBUG)
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#else
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)
#define dma_unmap_addr(PTR, ADDR_NAME)		0
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  do { } while (0)
#endif

#define hw_features features

#define netdev_name(netdev)	netdev->name

#ifndef netdev_printk
#define netdev_printk(level, netdev, format, args...)	\
	dev_printk(level, tp->pdev->dev.parent,	\
		   "%s: " format,			\
		   netdev_name(tp->dev), ##args)
#endif

#ifndef NETIF_F_RXCSUM
#define NETIF_F_RXCSUM		(1 << 29)
#endif

#ifndef NETIF_F_LOOPBACK
#define NETIF_F_LOOPBACK	(1 << 31)
#endif

#ifndef NETIF_F_ALL_TSO
#define NETIF_F_ALL_TSO (NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_TSO_ECN)
#endif

#ifndef netif_printk
#define netif_printk(priv, type, level, dev, fmt, args...)	\
do {								\
	if (netif_msg_##type(priv))				\
		netdev_printk(level, (dev), fmt, ##args);	\
} while (0)
#endif

#ifndef netif_info
#define netif_info(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_INFO, (dev), fmt, ##args)
#endif

#ifndef netdev_err
#define netdev_err(dev, format, args...)			\
	netdev_printk(KERN_ERR, dev, format, ##args)
#endif

#ifndef netdev_warn
#define netdev_warn(dev, format, args...)			\
	netdev_printk(KERN_WARNING, dev, format, ##args)
#endif

#ifndef netdev_notice
#define netdev_notice(dev, format, args...)			\
	netdev_printk(KERN_NOTICE, dev, format, ##args)
#endif

#ifndef netdev_info
#define netdev_info(dev, format, args...)			\
	netdev_printk(KERN_INFO, dev, format, ##args)
#endif

#ifndef netdev_mc_count
#define netdev_mc_count(dev) ((dev)->mc_count)
#endif

#ifndef netdev_mc_empty
#define netdev_mc_empty(dev) (netdev_mc_count(dev) == 0)
#endif

#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(ha, dev) \
        struct dev_mc_list * oldmclist; \
        struct dev_mc_list foo; \
        ha = &foo; \
    for (oldmclist = dev->mc_list; oldmclist && memcpy(foo.dmi_addr, oldmclist->dmi_addr, 6); oldmclist = oldmclist->next)
#endif

#define rtnl_link_stats64	net_device_stats

static inline int netif_set_real_num_rx_queues(struct net_device *dev, int num)
{
	return 0;
}

static int tg3_set_phys_id(struct net_device *dev,
			    enum ethtool_phys_id_state state);
static int tg3_phys_id(struct net_device *dev, u32 data)
{
	int i;

	if (!netif_running(dev))
		return -EAGAIN;

	if (data == 0)
		data = UINT_MAX / 2;

	for (i = 0; i < (data * 2); i++) {
		if ((i % 2) == 0)
			tg3_set_phys_id(dev, ETHTOOL_ID_ON);
		else
			tg3_set_phys_id(dev, ETHTOOL_ID_OFF);

		if (msleep_interruptible(500))
			break;
	}
	tg3_set_phys_id(dev, ETHTOOL_ID_INACTIVE);
	return 0;
}

#ifndef PHY_ID_BCM50610
#define PHY_ID_BCM50610		0xbc050d60
#endif

#ifndef PHY_ID_BCM50610M
#define PHY_ID_BCM50610M	0xbc050d70
#endif

#ifndef PHY_ID_BCMAC131
#define PHY_ID_BCMAC131		0xbc050c70
#endif

#ifndef PHY_ID_BCM57780
#define PHY_ID_BCM57780		0x5c0d8990
#endif

#ifndef PHY_BCM_OUI_MASK
#define PHY_BCM_OUI_MASK	0xfffffc00
#endif

#ifndef PHY_BCM_OUI_1
#define PHY_BCM_OUI_1		0x00206000
#endif

#ifndef PHY_BCM_OUI_2
#define PHY_BCM_OUI_2		0x0143bc00
#endif

#ifndef PHY_BCM_OUI_3
#define PHY_BCM_OUI_3		0x03625c00
#endif


#define PCI_VPD_LRDT			0x80	/* Large Resource Data Type */
#define PCI_VPD_LRDT_ID(x)		(x | PCI_VPD_LRDT)

/* Large Resource Data Type Tag Item Names */
#define PCI_VPD_LTIN_ID_STRING		0x02	/* Identifier String */
#define PCI_VPD_LTIN_RO_DATA		0x10	/* Read-Only Data */
#define PCI_VPD_LTIN_RW_DATA		0x11	/* Read-Write Data */

#define PCI_VPD_LRDT_ID_STRING		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_ID_STRING)
#define PCI_VPD_LRDT_RO_DATA		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RO_DATA)
#define PCI_VPD_LRDT_RW_DATA		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RW_DATA)

/* Small Resource Data Type Tag Item Names */
#define PCI_VPD_STIN_END		0x78	/* End */

#define PCI_VPD_SRDT_END		PCI_VPD_STIN_END

#define PCI_VPD_SRDT_TIN_MASK		0x78
#define PCI_VPD_SRDT_LEN_MASK		0x07

#define PCI_VPD_LRDT_TAG_SIZE		3
#define PCI_VPD_SRDT_TAG_SIZE		1

#define PCI_VPD_INFO_FLD_HDR_SIZE	3

#define PCI_VPD_RO_KEYWORD_PARTNO	"PN"
#define PCI_VPD_RO_KEYWORD_MFR_ID	"MN"
#define PCI_VPD_RO_KEYWORD_VENDOR0	"V0"
#define PCI_VPD_RO_KEYWORD_CHKSUM	"RV"

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

/**
 * pci_vpd_info_field_size - Extracts the information field length
 * @lrdt: Pointer to the beginning of an information field header
 *
 * Returns the extracted information field length.
 */
static inline u8 pci_vpd_info_field_size(const u8 *info_field)
{
	return info_field[2];
}

/**
 * pci_vpd_find_tag - Locates the Resource Data Type tag provided
 * @buf: Pointer to buffered vpd data
 * @off: The offset into the buffer at which to begin the search
 * @len: The length of the vpd buffer
 * @rdt: The Resource Data Type to search for
 *
 * Returns the index where the Resource Data Type was found or
 * -ENOENT otherwise.
 */
static int pci_vpd_find_tag(const u8 *buf, unsigned int off, unsigned int len, u8 rdt)
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

/**
 * pci_vpd_find_info_keyword - Locates an information field keyword in the VPD
 * @buf: Pointer to buffered vpd data
 * @off: The offset into the buffer at which to begin the search
 * @len: The length of the buffer area, relative to off, in which to search
 * @kw: The keyword to search for
 *
 * Returns the index where the information field keyword was found or
 * -ENOENT otherwise.
 */
int pci_vpd_find_info_keyword(const u8 *buf, unsigned int off,
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
