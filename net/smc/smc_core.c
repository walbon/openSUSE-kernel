/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Basic Transport Functions exploiting Infiniband API
 *
 *  Copyright IBM Corp. 2016
 *
 *  Author(s):  Ursula Braun <ubraun@linux.vnet.ibm.com>
 */

#include <linux/socket.h>
#include <linux/if_vlan.h>
#include <linux/random.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <rdma/ib_verbs.h>

#include "smc.h"
#include "smc_clc.h"
#include "smc_core.h"
#include "smc_ib.h"

/* Register connection's alert token in our lookup structure.
 * To use rbtrees we have to implement our own insert core.
 * Requires @conns_lock
 * @smc		connection to register
 * Returns 0 on success, != otherwise.
 */
static void smc_lgr_add_alert_token(struct smc_connection *conn)
{
	struct rb_node **link, *parent = NULL;
	u32 token = conn->alert_token_local;

	link = &conn->lgr->conns_all.rb_node;
	while (*link) {
		struct smc_connection *cur = rb_entry(*link,
					struct smc_connection, alert_node);

		parent = *link;
		if (cur->alert_token_local > token)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	/* Put the new node there */
	rb_link_node(&conn->alert_node, parent, link);
	rb_insert_color(&conn->alert_node, &conn->lgr->conns_all);
}

/* Register connection in link group by assigning an alert token
 * registered in a search tree.
 * Requires @conns_lock
 * Note that '0' is a reserved value and not assigned.
 */
static void smc_lgr_register_conn(struct smc_connection *conn)
{
	static atomic_t nexttoken = ATOMIC_INIT(0);

	/* find a new alert_token_local value not yet used by some connection
	 * in this link group
	 */
	while (!conn->alert_token_local) {
		conn->alert_token_local = atomic_inc_return(&nexttoken);
		if (smc_lgr_find_conn(conn->alert_token_local, conn->lgr))
			conn->alert_token_local = 0;
	}
	smc_lgr_add_alert_token(conn);
	conn->lgr->conns_num++;
}

/* Unregister connection and reset the alert token of the given connection
 */
static void smc_lgr_unregister_conn(struct smc_connection *conn)
{
	struct smc_link_group *lgr = conn->lgr;

	write_lock_bh(&lgr->conns_lock);
	rb_erase(&conn->alert_node, &lgr->conns_all);
	lgr->conns_num--;
	write_unlock_bh(&lgr->conns_lock);
}

/* create a new SMC link group */
static int smc_lgr_create(struct smc_sock *smc, __be32 peer_in_addr,
			  struct smc_ib_device *smcibdev, u8 ibport,
			  char *peer_systemid, unsigned short vlan_id)
{
	struct smc_link_group *lgr;
	struct smc_link *lnk;
	u8 rndvec[3];
	int rc = 0;
	int i;

	lgr = kzalloc(sizeof(*lgr), GFP_KERNEL);
	if (!lgr) {
		rc = -ENOMEM;
		goto out;
	}
	lgr->role = smc->listen_smc ? SMC_SERV : SMC_CLNT;
	lgr->daddr = peer_in_addr;
	memcpy(lgr->peer_systemid, peer_systemid, SMC_SYSTEMID_LEN);
	lgr->vlan_id = vlan_id;
	rwlock_init(&lgr->sndbufs_lock);
	rwlock_init(&lgr->rmbs_lock);
	for (i = 0; i < SMC_RMB_SIZES; i++) {
		INIT_LIST_HEAD(&lgr->sndbufs[i]);
		INIT_LIST_HEAD(&lgr->rmbs[i]);
	}

	lnk = &lgr->lnk[SMC_SINGLE_LINK];
	/* initialize link */
	lnk->smcibdev = smcibdev;
	lnk->ibport = ibport;
	lnk->path_mtu = smcibdev->pattr[ibport - 1].active_mtu;
	get_random_bytes(rndvec, sizeof(rndvec));
	lnk->psn_initial = rndvec[0] + (rndvec[1] << 8) + (rndvec[2] << 16);

	smc->conn.lgr = lgr;
	rwlock_init(&lgr->conns_lock);
	spin_lock(&smc_lgr_list.lock);
	list_add_tail(&lgr->list, &smc_lgr_list.list);
	spin_unlock(&smc_lgr_list.lock);
out:
	return rc;
}

static void smc_sndbuf_free(struct smc_connection *conn)
{
	if (conn->sndbuf_desc) {
		xchg(&conn->sndbuf_desc->used, 0);
		conn->sndbuf_size = 0;
	}
}

static void smc_rmb_free(struct smc_connection *conn)
{
	if (conn->rmb_desc) {
		xchg(&conn->rmb_desc->used, 0);
		conn->rmbe_size = 0;
	}
}

/* remove a finished connection from its link group */
void smc_conn_free(struct smc_connection *conn)
{
	struct smc_link_group *lgr = conn->lgr;

	if (!lgr)
		return;
	smc_lgr_unregister_conn(conn);
	conn->lgr = NULL;
	smc_rmb_free(conn);
	smc_sndbuf_free(conn);
}

static void smc_link_clear(struct smc_link_group *lgr)
{
	struct smc_link *lnk = &lgr->lnk[SMC_SINGLE_LINK];

	lnk->peer_qpn = 0;
}

/* remove a link group */
void smc_lgr_free(struct smc_link_group *lgr)
{
	smc_link_clear(lgr);
	kfree(lgr);
}

/* Client checks if creation / reuse of a link group happens
 * synchronously with Server.
 * Returns true iff client and server disagree.
 */
static bool smc_lgr_clt_srv_disagree(struct smc_connection *conn, int new_lgr,
				     int srv_first_contact)
{
	if (!srv_first_contact && new_lgr) {
		/* Server reuses a link group, but Client wants to start
		 * a new one
		 */
		return true;
	}
	if (srv_first_contact && !new_lgr) {
		/* Server starts a new link group, but Client wants to reuse
		 * an existing link group
		 */
		spin_lock(&smc_lgr_list.lock);
		list_del_init(&conn->lgr->list);
		spin_unlock(&smc_lgr_list.lock);
		smc_lgr_unregister_conn(conn); /* takes conns_lock */
		/* tbd: terminate existing connections */
		return true;
	}
	return false;
}

/* Determine vlan of internal TCP socket.
 * @vlan_id: address to store the determined vlan id into
 */
static int smc_vlan_by_tcpsk(struct socket *clcsock, unsigned short *vlan_id)
{
	struct dst_entry *dst = sk_dst_get(clcsock->sk);
	int rc = 0;

	*vlan_id = 0;
	if (!dst) {
		rc = -ENOTCONN;
		goto out;
	}
	if (!dst->dev) {
		rc = -ENODEV;
		goto out_rel;
	}

	if (is_vlan_dev(dst->dev))
		*vlan_id = vlan_dev_vlan_id(dst->dev);

out_rel:
	dst_release(dst);
out:
	return rc;
}

/* determine the link gid matching the vlan id of the link group */
static int smc_link_determine_gid(struct smc_link_group *lgr)
{
	struct smc_link *lnk = &lgr->lnk[SMC_SINGLE_LINK];
	struct ib_gid_attr gattr;
	union ib_gid gid;
	int i;

	if (!lgr->vlan_id) {
		lnk->gid = lnk->smcibdev->gid[lnk->ibport - 1];
		return 0;
	}

	for (i = 0; i < lnk->smcibdev->pattr[lnk->ibport - 1].gid_tbl_len;
	     i++) {
		ib_query_gid(lnk->smcibdev->ibdev, lnk->ibport, i, &gid,
			     &gattr);
		if (gattr.ndev &&
		    (vlan_dev_vlan_id(gattr.ndev) == lgr->vlan_id)) {
			lnk->gid = gid;
			return 0;
		}
	}
	return -ENODEV;
}

/* create a new SMC connection (and a new link group if necessary) */
int smc_conn_create(struct smc_sock *smc, __be32 peer_in_addr,
		    struct smc_ib_device *smcibdev, u8 ibport,
		    struct smc_clc_msg_local *lcl, int srv_first_contact)
{
	struct smc_connection *conn = &smc->conn;
	struct smc_link_group *lgr;
	unsigned short vlan_id;
	enum smc_lgr_role role;
	int local_contact = SMC_FIRST_CONTACT;
	int rc = 0;

	/* wait when another process is already creating a connection
	 * till either this process can reuse an existing link group or
	 * till this process has finished creating a new link group
	 */
	role = smc->listen_smc ? SMC_SERV : SMC_CLNT;
	rc = smc_vlan_by_tcpsk(smc->clcsock, &vlan_id);
	if (rc)
		return rc;

	/* determine if an existing link group can be reused */
	spin_lock(&smc_lgr_list.lock);
	list_for_each_entry(lgr, &smc_lgr_list.list, list) {
		write_lock_bh(&lgr->conns_lock);
		if (!memcmp(lgr->peer_systemid, lcl->id_for_peer,
			    SMC_SYSTEMID_LEN) &&
		    !memcmp(lgr->lnk[SMC_SINGLE_LINK].peer_gid, &lcl->gid,
			    SMC_GID_SIZE) &&
		    !memcmp(lgr->lnk[SMC_SINGLE_LINK].peer_mac, lcl->mac,
			    sizeof(lcl->mac)) &&
		    (lgr->role == role) &&
		    (lgr->vlan_id == vlan_id)) {
			/* link group found */
			local_contact = SMC_REUSE_CONTACT;
			conn->lgr = lgr;
			smc_lgr_register_conn(conn); /* add smc conn to lgr */
			write_unlock_bh(&lgr->conns_lock);
			break;
		}
		write_unlock_bh(&lgr->conns_lock);
	}
	spin_unlock(&smc_lgr_list.lock);

	if (role == SMC_CLNT) {
		if (smc_lgr_clt_srv_disagree(conn, local_contact,
					     srv_first_contact)) {
			/* send out_of_sync decline, reason synchr. error */
			smc->sk.sk_err = ENOLINK;
			return -ENOLINK;
		}
	}

	if (local_contact == SMC_FIRST_CONTACT) {
		rc = smc_lgr_create(smc, peer_in_addr, smcibdev, ibport,
				    lcl->id_for_peer, vlan_id);
		if (rc)
			goto out;
		smc_lgr_register_conn(conn); /* add smc conn to lgr */
		rc = smc_link_determine_gid(conn->lgr);
	}

out:
	return rc ? rc : local_contact;
}

/* try to reuse a sndbuf description slot of the sndbufs list for a certain
 * buf_size; if not available, return NULL
 */
static inline
struct smc_buf_desc *smc_sndbuf_get_slot(struct smc_link_group *lgr,
					 int compressed_bufsize)
{
	struct smc_buf_desc *sndbuf_slot;

	read_lock_bh(&lgr->sndbufs_lock);
	list_for_each_entry(sndbuf_slot, &lgr->sndbufs[compressed_bufsize],
			    list) {
		if (cmpxchg(&sndbuf_slot->used, 0, 1) == 0) {
			read_unlock_bh(&lgr->sndbufs_lock);
			return sndbuf_slot;
		}
	}
	read_unlock_bh(&lgr->sndbufs_lock);
	return NULL;
}

/* try to reuse an rmb description slot of the rmbs list for a certain
 * rmbe_size; if not available, return NULL
 */
static inline
struct smc_buf_desc *smc_rmb_get_slot(struct smc_link_group *lgr,
				      int compressed_bufsize)
{
	struct smc_buf_desc *rmb_slot;

	read_lock_bh(&lgr->rmbs_lock);
	list_for_each_entry(rmb_slot, &lgr->rmbs[compressed_bufsize],
			    list) {
		if (cmpxchg(&rmb_slot->used, 0, 1) == 0) {
			read_unlock_bh(&lgr->rmbs_lock);
			return rmb_slot;
		}
	}
	read_unlock_bh(&lgr->rmbs_lock);
	return NULL;
}

/* create the tx buffer for an SMC socket */
int smc_sndbuf_create(struct smc_sock *smc)
{
	struct smc_connection *conn = &smc->conn;
	struct smc_link_group *lgr = conn->lgr;
	int tmp_bufsize, tmp_bufsize_short;
	struct smc_buf_desc *sndbuf_desc;
	int rc;

	/* use socket send buffer size (w/o overhead) as start value */
	for (tmp_bufsize_short = smc_compress_bufsize(smc->sk.sk_sndbuf / 2);
	     tmp_bufsize_short >= 0; tmp_bufsize_short--) {
		tmp_bufsize = smc_uncompress_bufsize(tmp_bufsize_short);
		/* check for reusable sndbuf_slot in the link group */
		sndbuf_desc = smc_sndbuf_get_slot(lgr, tmp_bufsize_short);
		if (sndbuf_desc) {
			memset(conn->sndbuf_desc->cpu_addr, 0, tmp_bufsize);
			break; /* found reusable slot */
		}
		/* try to alloc a new send buffer */
		sndbuf_desc = kzalloc(sizeof(*sndbuf_desc), GFP_KERNEL);
		if (!sndbuf_desc)
			break; /* give up with -ENOMEM */
		sndbuf_desc->cpu_addr = kzalloc(tmp_bufsize,
						GFP_KERNEL | __GFP_NOWARN |
						__GFP_NOMEMALLOC |
						__GFP_NORETRY);
		if (!sndbuf_desc->cpu_addr) {
			kfree(sndbuf_desc);
			/* if send buffer allocation has failed,
			 * try a smaller one
			 */
			continue;
		}
		rc = smc_ib_buf_map(lgr->lnk[SMC_SINGLE_LINK].smcibdev,
				    tmp_bufsize, sndbuf_desc,
				    DMA_TO_DEVICE);
		if (rc) {
			kfree(sndbuf_desc->cpu_addr);
			kfree(sndbuf_desc);
			continue; /* if mapping failed, try smaller one */
		}
		sndbuf_desc->used = 1;
		write_lock_bh(&lgr->sndbufs_lock);
		list_add(&sndbuf_desc->list,
			 &lgr->sndbufs[tmp_bufsize_short]);
		write_unlock_bh(&lgr->sndbufs_lock);
	}
	if (sndbuf_desc && sndbuf_desc->cpu_addr) {
		conn->sndbuf_desc = sndbuf_desc;
		conn->sndbuf_size = tmp_bufsize;
		smc->sk.sk_sndbuf = tmp_bufsize * 2;
		return 0;
	} else {
		return -ENOMEM;
	}
}

/* create the RMB for an SMC socket (even though the SMC protocol
 * allows more than one RMB-element per RMB, the Linux implementation
 * uses just one RMB-element per RMB, i.e. uses an extra RMB for every
 * connection in a link group
 */
int smc_rmb_create(struct smc_sock *smc)
{
	struct smc_connection *conn = &smc->conn;
	struct smc_link_group *lgr = conn->lgr;
	int tmp_bufsize, tmp_bufsize_short;
	struct smc_buf_desc *rmb_desc;
	int rc;

	/* use socket recv buffer size (w/o overhead) as start value */
	for (tmp_bufsize_short = smc_compress_bufsize(smc->sk.sk_rcvbuf / 2);
	     tmp_bufsize_short >= 0; tmp_bufsize_short--) {
		tmp_bufsize = smc_uncompress_bufsize(tmp_bufsize_short);
		/* check for reusable rmb_slot in the link group */
		rmb_desc = smc_rmb_get_slot(lgr, tmp_bufsize_short);
		if (rmb_desc) {
			memset(conn->rmb_desc->cpu_addr, 0, tmp_bufsize);
			break; /* found reusable slot */
		}
		/* try to alloc a new RMB */
		rmb_desc = kzalloc(sizeof(*rmb_desc), GFP_KERNEL);
		if (!rmb_desc)
			break; /* give up with -ENOMEM */
		rmb_desc->cpu_addr = kzalloc(tmp_bufsize,
					     GFP_KERNEL | __GFP_NOWARN |
					     __GFP_NOMEMALLOC |
					     __GFP_NORETRY);
		if (!rmb_desc->cpu_addr) {
			kfree(rmb_desc);
			/* if RMB allocation has failed,
			 * try a smaller one
			 */
			continue;
		}
		rc = smc_ib_buf_map(lgr->lnk[SMC_SINGLE_LINK].smcibdev,
				    tmp_bufsize, rmb_desc,
				    DMA_FROM_DEVICE);
		if (rc) {
			kfree(rmb_desc->cpu_addr);
			kfree(rmb_desc);
			continue; /* if mapping failed, try smaller one */
		}
		rmb_desc->used = 1;
		write_lock_bh(&lgr->rmbs_lock);
		list_add(&rmb_desc->list,
			 &lgr->rmbs[tmp_bufsize_short]);
		write_unlock_bh(&lgr->rmbs_lock);
	}
	if (rmb_desc && rmb_desc->cpu_addr) {
		conn->rmb_desc = rmb_desc;
		conn->rmbe_size = tmp_bufsize;
		conn->rmbe_size_short = tmp_bufsize_short;
		smc->sk.sk_rcvbuf = tmp_bufsize * 2;
		return 0;
	} else {
		return -ENOMEM;
	}
}
