#ifndef _QLCNIC_COMPAT_H
#define _QLCNIC_COMPAT_H

#ifndef netdev_mc_count
#define netdev_mc_count(dev) ((dev)->mc_count)
#endif

#ifndef netdev_mc_empty
#define netdev_mc_empty(dev) (netdev_mc_count(dev) == 0)
#endif

#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(mclist, dev) \
	for (mclist = dev->mc_list; mclist; mclist = mclist->next)
#endif

#endif
