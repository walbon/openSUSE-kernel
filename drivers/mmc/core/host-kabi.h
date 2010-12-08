struct mmc_new_host {
	struct notifier_block	pm_notify;
	int			rescan_disable;	/* disable card detection */
	struct mmc_host h;
};

#define to_mmc_new_host(x)	container_of(x, struct mmc_new_host, h)
