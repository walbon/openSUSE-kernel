#ifndef _BNA_COMPAT_H_
#define _BNA_COMPAT_H_

#define rtnl_link_stats64       net_device_stats

#ifndef VLAN_N_VID
#define VLAN_N_VID VLAN_GROUP_ARRAY_LEN
#endif

#ifndef netdev_mc_empty
#define netdev_mc_empty(dev) (netdev_mc_count(dev) == 0)
#endif

static inline int dma_set_coherent_mask(struct device *dev, u64 mask)
{
	return pci_set_consistent_dma_mask(to_pci_dev(dev), mask);
}

#define DEFINE_DMA_UNMAP_ADDR(addr) DECLARE_PCI_UNMAP_ADDR(addr)
#define dma_unmap_addr(ptr, addr)	pci_unmap_addr(ptr, addr)
#define dma_unmap_addr_set(ptr, addr, val) pci_unmap_addr_set(ptr, addr, val)
#define dma_set_coherent_mask(dev, mask)	\
	pci_set_consistent_dma_mask(to_pci_dev(dev), mask)

#endif /* _BNA_COMPAT_H_ */
