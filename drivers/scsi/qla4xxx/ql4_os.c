/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */
#include <linux/moduleparam.h>
#include <linux/slab.h>

#include <scsi/scsi_tcq.h>
#include <scsi/scsicam.h>

#include "ql4_def.h"
#include "ql4_version.h"
#include "ql4_glbl.h"
#include "ql4_dbg.h"
#include "ql4_inline.h"

/*
 * Driver version
 */
char qla4xxx_version_str[40];
EXPORT_SYMBOL_GPL(qla4xxx_version_str);

/*
 * List of host adapters
 */
struct klist qla4xxx_hostlist;

struct klist *qla4xxx_hostlist_ptr = &qla4xxx_hostlist;
EXPORT_SYMBOL_GPL(qla4xxx_hostlist_ptr);

static atomic_t qla4xxx_hba_count;

/*
 * SRB allocation cache
 */
static struct kmem_cache *srb_cachep;

/*
 * Module parameter information and variables
 */
int ql4xdontresethba = 0;
module_param(ql4xdontresethba, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ql4xdontresethba,
		"Don't reset the HBA for driver recovery \n"
		"\t\t 0 - It will reset HBA (Default)\n"
		"\t\t 1 - It will NOT reset HBA\n"
		"\t\t 2 - Only reset in eh_host_reset");

int ql4xextended_error_logging = 0; /* 0 = off, 1 = log errors */
module_param(ql4xextended_error_logging, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ql4xextended_error_logging,
		 "Option to enable extended error logging \n"
		 "\t\t 0 - no logging (Default)\n"
		 "\t\t 1 - debug logging");

int ql4xenablemsix = 1;
module_param(ql4xenablemsix, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(ql4xenablemsix,
		"Set to enable MSI or MSI-X interrupt mechanism\n"
		"\t\t 0 - enable INTx interrupt mechanism\n"
		"\t\t 1 - enable MSI-X interrupt mechanism (Default)\n"
		"\t\t 2 - enable MSI interrupt mechanism");

int ql4xkeepalive=0xDEAD;
module_param(ql4xkeepalive, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(ql4xkeepalive,
		"Keep Alive Timeout - Target Session Recovery Timeout\n"
		"\t\t 0xDEAD - retrieved from firmware DDB. (Default)\n"
		"\t\t other  - override for all sessions.");

static int ql4xmaxqdepth = MAX_Q_DEPTH;
module_param(ql4xmaxqdepth, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(ql4xmaxqdepth,
		"Maximum queue depth to report for target devices\n"
		"\t\t Default - 32");

int ql4xmaxcmds = 0;
module_param(ql4xmaxcmds, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(ql4xmaxcmds,
		"Maximum outstanding commands per per host adapter\n"
		"\t\t 0 - uses driver default of 1152. (Default)");

/*
 * SCSI host template entry points
 */
static void qla4xxx_config_dma_addressing(struct scsi_qla_host *ha);

/*
 * iSCSI template entry points
 */
static int qla4xxx_tgt_dscvr(struct Scsi_Host *shost,
			     enum iscsi_tgt_dscvr type, uint32_t enable,
			     struct sockaddr *dst_addr);
static int qla4xxx_conn_get_param(struct iscsi_cls_conn *conn,
				  enum iscsi_param param, char *buf);
static int qla4xxx_sess_get_param(struct iscsi_cls_session *sess,
				  enum iscsi_param param, char *buf);
static int qla4xxx_host_get_param(struct Scsi_Host *shost,
				  enum iscsi_host_param param, char *buf);
static void qla4xxx_recovery_timedout(struct iscsi_cls_session *session);
static enum blk_eh_timer_return qla4xxx_eh_cmd_timed_out(struct scsi_cmnd *sc);

/*
 * SCSI host template entry points
 */
static int qla4xxx_queuecommand(struct Scsi_Host *h, struct scsi_cmnd *cmd);
static int qla4xxx_eh_abort(struct scsi_cmnd *cmd);
static int qla4xxx_eh_device_reset(struct scsi_cmnd *cmd);
static int qla4xxx_eh_target_reset(struct scsi_cmnd *cmd);
static int qla4xxx_eh_host_reset(struct scsi_cmnd *cmd);
static int qla4xxx_slave_alloc(struct scsi_device *device);
static int qla4xxx_slave_configure(struct scsi_device *device);
static void qla4xxx_slave_destroy(struct scsi_device *sdev);
static void qla4xxx_scan_start(struct Scsi_Host *shost);

static struct qla4_8xxx_legacy_intr_set legacy_intr[] =
    QLA82XX_LEGACY_INTR_CONFIG;

static struct scsi_host_template qla4xxx_driver_template = {
	.module			= THIS_MODULE,
	.name			= DRIVER_NAME,
	.proc_name		= DRIVER_NAME,
	.queuecommand		= qla4xxx_queuecommand,

	.eh_abort_handler	= qla4xxx_eh_abort,
	.eh_device_reset_handler = qla4xxx_eh_device_reset,
	.eh_target_reset_handler = qla4xxx_eh_target_reset,
	.eh_host_reset_handler	= qla4xxx_eh_host_reset,
	.eh_timed_out		= qla4xxx_eh_cmd_timed_out,

	.slave_configure	= qla4xxx_slave_configure,
	.slave_alloc		= qla4xxx_slave_alloc,
	.slave_destroy		= qla4xxx_slave_destroy,

	.scan_finished		= iscsi_scan_finished,
	.scan_start		= qla4xxx_scan_start,

	.this_id		= -1,
	.cmd_per_lun		= 3,
	.use_clustering		= ENABLE_CLUSTERING,
	.sg_tablesize		= SG_ALL,

	.max_sectors		= 0xFFFF,
};

static struct iscsi_transport qla4xxx_iscsi_transport = {
	.owner			= THIS_MODULE,
	.name			= DRIVER_NAME,
	.caps			= CAP_FW_DB | CAP_SENDTARGETS_OFFLOAD |
				  CAP_DATA_PATH_OFFLOAD,
	.param_mask		= ISCSI_CONN_PORT | ISCSI_CONN_ADDRESS |
				  ISCSI_TARGET_NAME | ISCSI_TPGT |
				  ISCSI_TARGET_ALIAS,
	.host_param_mask	= ISCSI_HOST_HWADDRESS |
				  ISCSI_HOST_IPADDRESS |
				  ISCSI_HOST_INITIATOR_NAME,
	.tgt_dscvr		= qla4xxx_tgt_dscvr,
	.get_conn_param		= qla4xxx_conn_get_param,
	.get_session_param	= qla4xxx_sess_get_param,
	.get_host_param		= qla4xxx_host_get_param,
	.session_recovery_timedout = qla4xxx_recovery_timedout,
};

static struct scsi_transport_template *qla4xxx_scsi_transport;

static enum blk_eh_timer_return qla4xxx_eh_cmd_timed_out(struct scsi_cmnd *sc)
{
	struct iscsi_cls_session *session;
	struct ddb_entry *ddb_entry;

	session = starget_to_session(scsi_target(sc->device));
	ddb_entry = session->dd_data;

	/* if we are not logged in then the LLD is going to clean up the cmd */
	if (atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE)
		return BLK_EH_RESET_TIMER;
	else
		return BLK_EH_NOT_HANDLED;
}

static void qla4xxx_recovery_timedout(struct iscsi_cls_session *session)
{
	struct ddb_entry *ddb_entry = session->dd_data;
#if defined(QL_DEBUG_LEVEL_2)
	struct scsi_qla_host *ha = ddb_entry->ha;
#endif

	if (atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE) {
		atomic_set(&ddb_entry->state, DDB_STATE_DEAD);

		DEBUG2(ql4_info(ha, "%s: ddb [%d] session recovery timeout "
			      "of (%d) secs exhausted, marking device DEAD.\n",
			      __func__, ddb_entry->fw_ddb_index,
			      ddb_entry->sess->recovery_tmo));
	}
}

static int qla4xxx_host_get_param(struct Scsi_Host *shost,
				  enum iscsi_host_param param, char *buf)
{
	struct scsi_qla_host *ha = to_qla_host(shost);
	int len;

	switch (param) {
	case ISCSI_HOST_PARAM_HWADDRESS:
		len = sysfs_format_mac(buf, ha->my_mac, MAC_ADDR_LEN);
		break;
	case ISCSI_HOST_PARAM_IPADDRESS:
		len = sprintf(buf, "%pI4\n", &ha->ip_address);
		if (!is_ipv4_enabled(ha) && is_ipv6_enabled(ha)) {
			if (ha->ipv6_addr0_state == ACB_STATE_VALID)
				len = sprintf(buf, "%pI6\n",
						&ha->ipv6_addr0);
			else if (ha->ipv6_addr1_state == ACB_STATE_VALID)
				len = sprintf(buf, "%pI6\n",
						&ha->ipv6_addr1);
			else if (ha->ipv6_link_local_state == ACB_STATE_VALID)
				len = sprintf(buf, "%pI6\n",
					&ha->ipv6_link_local_addr);
		}
		break;
	case ISCSI_HOST_PARAM_INITIATOR_NAME:
		len = sprintf(buf, "%s\n", ha->name_string);
		break;
	default:
		return -ENOSYS;
	}

	return len;
}

static int qla4xxx_sess_get_param(struct iscsi_cls_session *sess,
				  enum iscsi_param param, char *buf)
{
	struct ddb_entry *ddb_entry = sess->dd_data;
	int len;

	switch (param) {
	case ISCSI_PARAM_TARGET_NAME:
		len = snprintf(buf, PAGE_SIZE - 1, "%s\n",
			       ddb_entry->iscsi_name);
		break;
	case ISCSI_PARAM_TPGT:
		len = sprintf(buf, "%u\n", ddb_entry->tpgt);
		break;
	case ISCSI_PARAM_TARGET_ALIAS:
		len = snprintf(buf, PAGE_SIZE - 1, "%s\n",
		    ddb_entry->iscsi_alias);
		break;
	default:
		return -ENOSYS;
	}

	return len;
}

static int qla4xxx_conn_get_param(struct iscsi_cls_conn *conn,
				  enum iscsi_param param, char *buf)
{
	struct iscsi_cls_session *session;
	struct ddb_entry *ddb_entry;
	int len;

	session = iscsi_dev_to_session(conn->dev.parent);
	ddb_entry = session->dd_data;

	switch (param) {
	case ISCSI_PARAM_CONN_PORT:
		len = sprintf(buf, "%hu\n", ddb_entry->port);
		break;
	case ISCSI_PARAM_CONN_ADDRESS:
		if (is_ipv6_ddb(ddb_entry))
			len = sprintf(buf, NIP6_FMT"\n",
				NIP6(ddb_entry->ipv6_addr));
		else
			len = sprintf(buf, NIPQUAD_FMT"\n",
				NIPQUAD(ddb_entry->ipv6_addr));

		break;
	default:
		return -ENOSYS;
	}

	return len;
}

static int qla4xxx_tgt_dscvr(struct Scsi_Host *shost,
			     enum iscsi_tgt_dscvr type, uint32_t enable,
			     struct sockaddr *dst_addr)
{
	struct scsi_qla_host *ha;
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;
	int ret = 0;

	ha = (struct scsi_qla_host *) shost->hostdata;

	switch (type) {
	case ISCSI_TGT_DSCVR_SEND_TARGETS:
		if (dst_addr->sa_family == AF_INET) {
			addr = (struct sockaddr_in *)dst_addr;
			if (qla4xxx_send_tgts(ha, (char *)&addr->sin_addr,
					      addr->sin_port) != QLA_SUCCESS)
				ret = -EIO;
		} else if (dst_addr->sa_family == AF_INET6) {
			/*
			 * TODO: fix qla4xxx_send_tgts
			 */
			addr6 = (struct sockaddr_in6 *)dst_addr;
			if (qla4xxx_send_tgts(ha, (char *)&addr6->sin6_addr,
					      addr6->sin6_port) != QLA_SUCCESS)
				ret = -EIO;
		} else
			ret = -ENOSYS;
		break;
	default:
		ret = -ENOSYS;
	}
	return ret;
}

static int ql4_alloc_osindex(struct scsi_qla_host *ha)
{
        unsigned int idx;

get_idx:
       idx = find_first_zero_bit(ha->os_map, MAX_DDB_ENTRIES);
       if (idx >= MAX_DDB_ENTRIES)
               return -1;

       if (test_and_set_bit(idx, ha->os_map))
               goto get_idx;

       return idx;
}

static void ql4_free_osindex(struct scsi_qla_host *ha, uint32_t idx)
{
       clear_bit(idx, ha->os_map);
}

void qla4xxx_destroy_sess(struct ddb_entry *ddb_entry)
{
	if (!ddb_entry->sess)
		return;

	ql4_free_osindex(ddb_entry->ha, ddb_entry->os_target_id);

	if (ddb_entry->conn) {
		atomic_set(&ddb_entry->state, DDB_STATE_DEAD);
		ql4_info(ddb_entry->ha, "%s: ddb[%d] os[%d] DEAD\n",
			__func__, ddb_entry->fw_ddb_index,
			ddb_entry->os_target_id);
		iscsi_remove_session(ddb_entry->sess);
	}
	iscsi_free_session(ddb_entry->sess);
}

int qla4xxx_add_sess(struct ddb_entry *ddb_entry)
{
	int err;
	struct scsi_qla_host *ha = ddb_entry->ha;

	err = iscsi_add_session(ddb_entry->sess, ddb_entry->os_target_id);
	if (err) {
		DEBUG2(ql4_err(ha, "Could not add session.\n"));
		return err;
	}

	ddb_entry->conn = iscsi_create_conn(ddb_entry->sess, 0, 0);
	if (!ddb_entry->conn) {
		iscsi_remove_session(ddb_entry->sess);
		DEBUG2(ql4_err(ha, "Could not add connection.\n"));
		return -ENOMEM;
	}

	ddb_entry->sess->recovery_tmo = (ql4xkeepalive != 0xDEAD)
			?ql4xkeepalive:ddb_entry->ka_timeout;

	/* finally ready to go */
	iscsi_unblock_session(ddb_entry->sess);
	DEBUG2(ql4_info(ha, "%s: iscsi_unblock_session "
			"ddb[%d] os[%d] sess 0x%p conn 0x%p\n", __func__,
			ddb_entry->fw_ddb_index, ddb_entry->os_target_id,
			ddb_entry->sess, ddb_entry->conn));

	return 0;
}

struct ddb_entry *qla4xxx_alloc_sess(struct scsi_qla_host *ha)
{
	struct ddb_entry *ddb_entry;
	struct iscsi_cls_session *sess;
	int os_idx;

	os_idx = ql4_alloc_osindex(ha);
	if (os_idx == -1) {
		DEBUG2(ql4_info(ha, "%s: os_idx=%d\n", __func__, os_idx));
		return NULL;
	}

	sess = iscsi_alloc_session(ha->host, &qla4xxx_iscsi_transport,
				   sizeof(struct ddb_entry));
	if (!sess) {
		ql4_free_osindex(ha, os_idx);
		return NULL;
	}

	ddb_entry = sess->dd_data;
	memset(ddb_entry, 0, sizeof(*ddb_entry));
	ddb_entry->os_target_id = os_idx;
	ddb_entry->ha = ha;
	ddb_entry->sess = sess;
	return ddb_entry;
}

static void qla4xxx_scan_start(struct Scsi_Host *shost)
{
	struct scsi_qla_host *ha = shost_priv(shost);
	struct ddb_entry *ddb_entry, *ddbtemp;

	/* finish setup of sessions that were already setup in firmware */
	list_for_each_entry_safe(ddb_entry, ddbtemp, &ha->ddb_list, list) {
		if (ddb_entry->fw_ddb_device_state == DDB_DS_SESSION_ACTIVE)
			qla4xxx_add_sess(ddb_entry);
	}
}

/*
 * Timer routines
 */

static void qla4xxx_start_timer(struct scsi_qla_host *ha, void *func,
				unsigned long interval)
{
	DEBUG(ql4_info(ha, "scsi: %s: Starting timer thread for adapter\n",
		     __func__));
	init_timer(&ha->timer);
	ha->timer.expires = jiffies + interval * HZ;
	ha->timer.data = (unsigned long)ha;
	ha->timer.function = (void (*)(unsigned long))func;
	add_timer(&ha->timer);
	ha->timer_active = 1;
}

static void qla4xxx_stop_timer(struct scsi_qla_host *ha)
{
	del_timer_sync(&ha->timer);
	ha->timer_active = 0;
}

/***
 * qla4xxx_mark_device_missing - mark a device as missing.
 * @ha: Pointer to host adapter structure.
 * @ddb_entry: Pointer to device database entry
 *
 * This routine marks a device missing and close connection.
 **/
void qla4xxx_mark_device_missing(struct scsi_qla_host *ha,
				 struct ddb_entry *ddb_entry)
{
	if ((atomic_read(&ddb_entry->state) != DDB_STATE_DEAD)) {
		atomic_set(&ddb_entry->state, DDB_STATE_MISSING);
		DEBUG2(ql4_info(ha, "ddb [%d] os [%d] marked MISSING\n",
			ddb_entry->fw_ddb_index,
			ddb_entry->os_target_id));
	} else
		DEBUG2(ql4_info(ha, "ddb [%d] os [%d] DEAD\n",
			ddb_entry->fw_ddb_index,
			ddb_entry->os_target_id))

	iscsi_block_session(ddb_entry->sess);
	iscsi_conn_error_event(ddb_entry->conn, ISCSI_ERR_CONN_FAILED);
}

/**
 * qla4xxx_mark_all_devices_missing - mark all devices as missing.
 * @ha: Pointer to host adapter structure.
 *
 * This routine marks a device missing and resets the relogin retry count.
 **/
void qla4xxx_mark_all_devices_missing(struct scsi_qla_host *ha)
{
	struct ddb_entry *ddb_entry, *ddbtemp;
	list_for_each_entry_safe(ddb_entry, ddbtemp, &ha->ddb_list, list) {
		qla4xxx_mark_device_missing(ha, ddb_entry);
	}
}

static struct srb* qla4xxx_get_new_srb(struct scsi_qla_host *ha,
				       struct ddb_entry *ddb_entry,
				       struct scsi_cmnd *cmd)
{
	struct srb *srb;

	srb = mempool_alloc(ha->srb_mempool, GFP_ATOMIC);
	if (!srb)
		return srb;

	kref_init(&srb->srb_ref);
	srb->ha = ha;
	srb->ddb = ddb_entry;
	srb->cmd = cmd;
	srb->flags = 0;
	CMD_SP(cmd) = (void *)srb;

	return srb;
}

static void qla4xxx_srb_free_dma(struct scsi_qla_host *ha, struct srb *srb)
{
	struct scsi_cmnd *cmd = srb->cmd;

	if (srb->flags & SRB_DMA_VALID) {
		scsi_dma_unmap(cmd);
		srb->flags &= ~SRB_DMA_VALID;
	}
	CMD_SP(cmd) = NULL;
}

void qla4xxx_srb_compl(struct kref *ref)
{
	struct srb *srb = container_of(ref, struct srb, srb_ref);
	struct scsi_cmnd *cmd = srb->cmd;
	struct scsi_qla_host *ha = srb->ha;

	if (!(srb->flags & SRB_SCSI_PASSTHRU)) {
		qla4xxx_srb_free_dma(ha, srb);
		mempool_free(srb, ha->srb_mempool);
	}
	cmd->scsi_done(cmd);
}

/**
 * qla4xxx_queuecommand - scsi layer issues scsi command to driver.
 * @host: scsi host
 * @cmd: Pointer to Linux's SCSI command structure
 *
 * Remarks:
 * This routine is invoked by Linux to send a SCSI command to the driver.
 * The mid-level driver tries to ensure that queuecommand never gets
 * invoked concurrently with itself or the interrupt handler (although
 * the interrupt handler may call this routine as part of request-
 * completion handling).   Unfortunely, it sometimes calls the scheduler
 * in interrupt context which is a big NO! NO!.
 **/
static int qla4xxx_queuecommand(struct Scsi_Host *host, struct scsi_cmnd *cmd)
{
	struct scsi_qla_host *ha = to_qla_host(host);
	struct ddb_entry *ddb_entry = cmd->device->hostdata;
	struct iscsi_cls_session *sess = ddb_entry->sess;
	struct srb *srb;
	int rval;

	if (test_bit(AF_EEH_BUSY, &ha->flags)) {
		if (test_bit(AF_PCI_CHANNEL_IO_PERM_FAILURE, &ha->flags))
			cmd->result = DID_NO_CONNECT << 16;
		else
			cmd->result = DID_REQUEUE << 16;
		goto qc_fail_command;
	}

	if (!sess) {
		cmd->result = DID_IMM_RETRY << 16;
		goto qc_fail_command;
	}

	rval = iscsi_session_chkready(sess);
	if (rval) {
		cmd->result = rval;
		goto qc_fail_command;
	}

	if (atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE) {
		if (atomic_read(&ddb_entry->state) == DDB_STATE_DEAD) {
			cmd->result = DID_NO_CONNECT << 16;
			goto qc_fail_command;
		}
		return SCSI_MLQUEUE_TARGET_BUSY;
	}

	if (test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_ACTIVE, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_HA, &ha->dpc_flags) ||
	    test_bit(DPC_HA_UNRECOVERABLE, &ha->dpc_flags) ||
	    test_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_QUIESCENT, &ha->dpc_flags) ||
	    test_bit(DPC_QUIESCE_ACTIVE, &ha->dpc_flags) ||
	    !test_bit(AF_ONLINE, &ha->flags) ||
	    test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags))
		goto qc_host_busy;

	srb = qla4xxx_get_new_srb(ha, ddb_entry, cmd);
	if (!srb)
		goto qc_host_busy;

	rval = qla4xxx_send_command_to_isp(ha, srb);
	if (rval != QLA_SUCCESS)
		goto qc_host_busy_free_sp;

	return 0;

qc_host_busy_free_sp:
	qla4xxx_srb_free_dma(ha, srb);
	mempool_free(srb, ha->srb_mempool);

qc_host_busy:
	return SCSI_MLQUEUE_HOST_BUSY;

qc_fail_command:
	cmd->scsi_done(cmd);

	return 0;
}

/**
 * qla4xxx_mem_free - frees memory allocated to adapter
 * @ha: Pointer to host adapter structure.
 *
 * Frees memory previously allocated by qla4xxx_mem_alloc
 **/
static void qla4xxx_mem_free(struct scsi_qla_host *ha)
{
	struct list_head *ptr;
	struct async_msg_pdu_iocb *apdu_iocb;

	if (ha->queues)
		dma_free_coherent(&ha->pdev->dev, ha->queues_len, ha->queues,
				  ha->queues_dma);

	if (ha->gen_req_rsp_iocb)
		dma_free_coherent(&ha->pdev->dev, PAGE_SIZE,
			ha->gen_req_rsp_iocb, ha->gen_req_rsp_iocb_dma);

	while (!list_empty(&ha->async_iocb_list)) {
		ptr = ha->async_iocb_list.next;
		apdu_iocb = list_entry(ptr, struct async_msg_pdu_iocb, list);
		list_del_init(&apdu_iocb->list);
		kfree(apdu_iocb);
	}

	ha->queues_len = 0;
	ha->queues = NULL;
	ha->queues_dma = 0;
	ha->request_ring = NULL;
	ha->request_dma = 0;
	ha->response_ring = NULL;
	ha->response_dma = 0;
	ha->shadow_regs = NULL;
	ha->shadow_regs_dma = 0;

	/* Free srb pool. */
	if (ha->srb_mempool)
		mempool_destroy(ha->srb_mempool);

	ha->srb_mempool = NULL;

	/* Free DMA Pool for Passthru IOCBs */
	if (ha->pt_iocb_dmapool) {
		dma_pool_destroy(ha->pt_iocb_dmapool);
		ha->pt_iocb_dmapool = NULL;
	}

	/* release io space registers  */
	if (is_qla8022(ha)) {
		if (ha->nx_pcibase)
			iounmap(
			    (struct device_reg_82xx __iomem *)ha->nx_pcibase);
	} else if (ha->reg)
		iounmap(ha->reg);
	pci_release_regions(ha->pdev);
}

/**
 * qla4xxx_mem_alloc - allocates memory for use by adapter.
 * @ha: Pointer to host adapter structure
 *
 * Allocates DMA memory for request and response queues. Also allocates memory
 * for srbs.
 **/
static int qla4xxx_mem_alloc(struct scsi_qla_host *ha)
{
	unsigned long align;
	__u8 name[24];

	/* Allocate contiguous block of DMA memory for queues. */
	ha->queues_len = ((REQUEST_QUEUE_DEPTH * QUEUE_SIZE) +
			  (RESPONSE_QUEUE_DEPTH * QUEUE_SIZE) +
			  sizeof(struct shadow_regs) +
			  MEM_ALIGN_VALUE +
			  (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
	ha->queues = dma_alloc_coherent(&ha->pdev->dev, ha->queues_len,
					&ha->queues_dma, GFP_KERNEL);
	if (ha->queues == NULL) {
		ql4_warn(ha, "Memory Allocation failed - queues.\n");

		goto mem_alloc_error_exit;
	}
	memset(ha->queues, 0, ha->queues_len);

	/*
	 * As per RISC alignment requirements -- the bus-address must be a
	 * multiple of the request-ring size (in bytes).
	 */
	align = 0;
	if ((unsigned long)ha->queues_dma & (MEM_ALIGN_VALUE - 1))
		align = MEM_ALIGN_VALUE - ((unsigned long)ha->queues_dma &
					   (MEM_ALIGN_VALUE - 1));

	/* Update request and response queue pointers. */
	ha->request_dma = ha->queues_dma + align;
	ha->request_ring = (struct queue_entry *) (ha->queues + align);
	ha->response_dma = ha->queues_dma + align +
		(REQUEST_QUEUE_DEPTH * QUEUE_SIZE);
	ha->response_ring = (struct queue_entry *) (ha->queues + align +
						    (REQUEST_QUEUE_DEPTH *
						     QUEUE_SIZE));
	ha->shadow_regs_dma = ha->queues_dma + align +
		(REQUEST_QUEUE_DEPTH * QUEUE_SIZE) +
		(RESPONSE_QUEUE_DEPTH * QUEUE_SIZE);
	ha->shadow_regs = (struct shadow_regs *) (ha->queues + align +
						  (REQUEST_QUEUE_DEPTH *
						   QUEUE_SIZE) +
						  (RESPONSE_QUEUE_DEPTH *
						   QUEUE_SIZE));

	/* Allocate memory for srb pool. */
	ha->srb_mempool = mempool_create(SRB_MIN_REQ, mempool_alloc_slab,
					 mempool_free_slab, srb_cachep);
	if (ha->srb_mempool == NULL) {
		ql4_warn(ha, "Memory Allocation failed - SRB Pool.\n");
		goto mem_alloc_error_exit;
	}

	/* Allocate memory for async pdus. */
	ha->gen_req_rsp_iocb = dma_alloc_coherent(&ha->pdev->dev, PAGE_SIZE,
		&ha->gen_req_rsp_iocb_dma, GFP_KERNEL);
	if (ha->gen_req_rsp_iocb == NULL) {
		dev_warn(&ha->pdev->dev,
			"Memory Allocation failed - gen_req_rsp_iocb.\n");
		goto mem_alloc_error_exit;
	}

	/* Create DMA pool for Passthru IOCBs */
	snprintf(name, sizeof(name), "%s_iocb_%d", DRIVER_NAME,
							ha->pdev->device);
	ha->pt_iocb_dmapool = dma_pool_create(name, &ha->pdev->dev, PAGE_SIZE,
					sizeof(struct passthru0), 0);

	if (ha->pt_iocb_dmapool == NULL) {
		dev_warn(&ha->pdev->dev,
			"Memory Allocation failed - Passthru IOCB dmapool.\n");
		goto mem_alloc_error_exit;
	}

	return QLA_SUCCESS;

mem_alloc_error_exit:
	qla4xxx_mem_free(ha);
	return QLA_ERROR;
}

/**
 * qla4_8xxx_check_fw_alive  - Check firmware health
 * @ha: Pointer to host adapter structure.
 *
 * Returns: 1 if the firmware is hung.
 * Context: Interrupt
 **/
int qla4_8xxx_check_fw_alive(struct scsi_qla_host *ha)
{
	uint32_t fw_heartbeat_counter;
	int status = 0;

	fw_heartbeat_counter = qla4_8xxx_rd_32(ha, QLA82XX_PEG_ALIVE_COUNTER);
	/* If PEG_ALIVE_COUNTER is 0xffffffff, AER/EEH is in progress, ignore */
	if (fw_heartbeat_counter == 0xffffffff) {
		DEBUG2(ql4_warn(ha, "%s: Device in frozen "
		    "state, QLA82XX_PEG_ALIVE_COUNTER is 0xffffffff\n",
		    __func__));
		status = 1;
		return status;
	}

	if (ha->fw_heartbeat_counter == fw_heartbeat_counter) {
		ha->seconds_since_last_heartbeat++;
		/* FW not alive after 2 seconds */
		if (ha->seconds_since_last_heartbeat == 2) {
			ha->seconds_since_last_heartbeat = 0;
			ql4_printk(KERN_INFO, ha, "scsi%ld: %s: FW HANG "
					"detected !!\n", ha->host_no,
					__func__);
			status = 1;
		}
	} else
		ha->seconds_since_last_heartbeat = 0;

	ha->fw_heartbeat_counter = fw_heartbeat_counter;

	return status;
}

/**
 * qla4_8xxx_watchdog - Poll dev state
 * @ha: Pointer to host adapter structure.
 *
 * Context: Interrupt
 **/
void qla4_8xxx_watchdog(struct scsi_qla_host *ha)
{
	uint32_t dev_state, halt_status;

	/* don't poll if reset is going on */
	if (!(test_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags) ||
	      test_bit(DPC_RESET_HA, &ha->dpc_flags) ||
	      test_bit(DPC_RESET_ACTIVE, &ha->dpc_flags))) {
		dev_state = qla4_8xxx_rd_32(ha, QLA82XX_CRB_DEV_STATE);
		if (dev_state == QLA82XX_DEV_NEED_RESET &&
		    !test_bit(DPC_RESET_HA, &ha->dpc_flags)) {
			if (!ql4xdontresethba) {
				ql4_info(ha, "%s: HW State: NEED RESET!\n",
						__func__);
				set_bit(DPC_RESET_HA, &ha->dpc_flags);
				qla4xxx_wake_dpc(ha);
			}
		} else if (dev_state == QLA82XX_DEV_NEED_QUIESCENT &&
		    !test_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags)) {
			ql4_err(ha, "%s: HW State: NEED QUIESCENT detected "
					"flags=0x%lx, dpc_flags=0x%lx\n",
					__func__, ha->flags, ha->dpc_flags);
			set_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags);
			qla4xxx_wake_dpc(ha);
		} else if ((dev_state == QLA82XX_DEV_QUIESCENT) &&
			    test_bit(DPC_RESET_QUIESCENT, &ha->dpc_flags)) {
			qla4xxx_wake_dpc(ha);
		} else  {
			/* Check firmware health */
			if (qla4_8xxx_check_fw_alive(ha)) {
				halt_status = qla4_8xxx_rd_32(ha,
						QLA82XX_PEG_HALT_STATUS1);

				ql4_printk(KERN_INFO, ha,
					"scsi(%ld): %s, Dumping hw/fw "
					"registers: PEG_HALT_STATUS1: 0x%x, "
					"PEG_HALT_STATUS2: 0x%x,\n "
					"PEG_NET_0_PC: 0x%x, PEG_NET_1_PC:"
					" 0x%x,\n PEG_NET_2_PC: 0x%x, "
					"PEG_NET_3_PC: 0x%x,\n PEG_NET_4_PC: "
					"0x%x\n", ha->host_no,
					__func__, halt_status,
					qla4_8xxx_rd_32(ha,
							QLA82XX_PEG_HALT_STATUS2),
					qla4_8xxx_rd_32(ha,
							QLA82XX_CRB_PEG_NET_0 +
							0x3c),
					qla4_8xxx_rd_32(ha,
							QLA82XX_CRB_PEG_NET_1 +
							0x3c),
					qla4_8xxx_rd_32(ha,
							QLA82XX_CRB_PEG_NET_2 +
							0x3c),
					qla4_8xxx_rd_32(ha,
							QLA82XX_CRB_PEG_NET_3 +
							0x3c),
					qla4_8xxx_rd_32(ha,
							QLA82XX_CRB_PEG_NET_4 +
							0x3c));


				/* Since we cannot change dev_state in
				 * interrupt context, set appropriate DPC
				 * flag then wakeup DPC */
				if (halt_status & HALT_STATUS_UNRECOVERABLE)
					set_bit(DPC_HA_UNRECOVERABLE,
						&ha->dpc_flags);
				else {
					ql4_printk(KERN_INFO, ha,
							"scsi%ld: %s: "
							"detect HA Reset "
							"needed!\n",
							ha->host_no,
							__func__);
					set_bit(DPC_RESET_HA, &ha->dpc_flags);
				}

				qla4xxx_wake_dpc(ha);
				qla4xxx_mailbox_premature_completion(ha);
			}
		}
	}
}

/**
 * qla4xxx_timer - checks every second for work to do.
 * @ha: Pointer to host adapter structure.
 **/
void qla4xxx_timer(struct scsi_qla_host *ha)
{
	struct ddb_entry *ddb_entry, *dtemp;
	int start_dpc = 0;
	uint16_t w;

	/* If we are in the middle of AER/EEH processing
	 * skip any processing and reschedule the timer
	 */
	if (test_bit(AF_EEH_BUSY, &ha->flags)) {
		mod_timer(&ha->timer, jiffies + HZ);
		return;
	}

	/* Hardware read to trigger an EEH error during mailbox waits. */
	if (!pci_channel_offline(ha->pdev))
		pci_read_config_word(ha->pdev, PCI_VENDOR_ID, &w);

	if (test_bit(AF_HA_REMOVAL, &ha->flags)) {
		DEBUG2(ql4_info(ha, "%s exited. HBA GOING AWAY\n", __func__));
		return;
	}

	if (is_qla8022(ha)) {
		qla4_8xxx_watchdog(ha);
	}

	/* Search for relogin's to time-out and port down retry. */
	list_for_each_entry_safe(ddb_entry, dtemp, &ha->ddb_list, list) {
		/* Count down time between sending relogins */
		if (adapter_up(ha) &&
		    !test_bit(DF_RELOGIN, &ddb_entry->flags) &&
		    atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE) {
			if (atomic_read(&ddb_entry->retry_relogin_timer) !=
			    INVALID_ENTRY) {
				if (atomic_read(&ddb_entry->retry_relogin_timer)
				    		== 0) {
					atomic_set(&ddb_entry->
						retry_relogin_timer,
						INVALID_ENTRY);
					set_bit(DPC_RELOGIN_DEVICE,
						&ha->dpc_flags);
					set_bit(DF_RELOGIN, &ddb_entry->flags);
					DEBUG2(ql4_info(ha, "%s: ddb [%d]"
						      " login device\n",
						      __func__,
						      ddb_entry->fw_ddb_index));
				} else
					atomic_dec(&ddb_entry->
							retry_relogin_timer);
			}
		}

		/* Wait for relogin to timeout */
		if (atomic_read(&ddb_entry->relogin_timer) &&
		    (atomic_dec_and_test(&ddb_entry->relogin_timer) != 0)) {
			/*
			 * If the relogin times out and the device is
			 * still NOT ONLINE then try and relogin again.
			 */
			if (atomic_read(&ddb_entry->state) !=
			    DDB_STATE_ONLINE &&
			    ddb_entry->fw_ddb_device_state ==
			    DDB_DS_SESSION_FAILED) {
				/* Reset retry relogin timer */
				atomic_inc(&ddb_entry->relogin_retry_count);
				DEBUG2(ql4_info(ha, "ddb [%d] relogin"
					      " timed out-retrying"
					      " relogin (%d)\n",
					      ddb_entry->fw_ddb_index,
					      atomic_read(&ddb_entry->
							  relogin_retry_count))
					);
				start_dpc++;
				DEBUG(ql4_info(ha, "ddb [%d] "
					     "initate relogin after"
					     " %d seconds\n",
					     ddb_entry->fw_ddb_index,
					     ddb_entry->default_time2wait + 4)
					);

				atomic_set(&ddb_entry->retry_relogin_timer,
					   ddb_entry->default_time2wait + 4);
			}
		}
	}

	if (!is_qla8022(ha)) {
		/* Check for heartbeat interval. */
		if (ha->firmware_options & FWOPT_HEARTBEAT_ENABLE &&
		    ha->heartbeat_interval != 0) {
			ha->seconds_since_last_heartbeat++;
			if (ha->seconds_since_last_heartbeat >
			    ha->heartbeat_interval + 2)
				set_bit(DPC_RESET_HA, &ha->dpc_flags);
		}
	}

	/* Check for iSNS actions */
	if (adapter_up(ha)) {
		/* Re-register with the iSNS server if two times
		 * the esi interval has elapsed-- to prevent
		 * iSNS server from de-registering us. */
		if (test_bit(ISNS_FLAG_ISNS_SRV_REGISTERED,
		    &ha->isns.flags) &&
		    atomic_read(&ha->isns.esi_timer)) {
			if (atomic_dec_and_test(&ha->isns.esi_timer)) {
				ql4_info(ha, "ESI timer expired. "
				    "Re-register with iSNS server\n");
				set_bit(DPC_ISNS_REREGISTER, &ha->dpc_flags);
			}
		}

		/* Decrement the restart timer.  When it has elapsed,
		 * start the iSNS server */
		if ((atomic_read(&ha->isns.state) ==
		    ISNS_STATE_RESTART_SRV_WAIT) &&
		    atomic_read(&ha->isns.restart_timer) != 0) {
			if (atomic_dec_and_test(&ha->isns.restart_timer)) {
				set_bit(DPC_ISNS_START, &ha->dpc_flags);
			}
		}
		else if (test_bit(ISNS_FLAG_ISNS_ENABLED_IN_ISP,
		    &ha->isns.flags) &&
		    atomic_read(&ha->isns.state) ==
		    ISNS_STATE_TCP_DISCONNECTED &&
		    !test_bit(DPC_ISNS_RESTART, &ha->dpc_flags) &&
		    !test_bit(DPC_ISNS_START, &ha->dpc_flags)) {
			/* If iSNS is enabled in ISP, but no TCP connection
			 * with an iSNS server has been established,
			 * periodically poll for an iSNS server connection. */
			ql4_isns_restart_timer(ha, ISNS_POLL_SVR_TOV);
		}
	}

	/* Wakeup the dpc routine for this adapter, if needed. */
	if (start_dpc ||
	     test_bit(DPC_RESET_HA, &ha->dpc_flags) ||
	     test_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags) ||
	     test_bit(DPC_RELOGIN_DEVICE, &ha->dpc_flags) ||
	     test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags) ||
	     test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags) ||
	     test_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags) ||
	     test_bit(DPC_LINK_CHANGED, &ha->dpc_flags) ||
	     test_bit(DPC_HA_UNRECOVERABLE, &ha->dpc_flags) ||
	     test_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags) ||
	     test_bit(DPC_RESET_QUIESCENT, &ha->dpc_flags) ||
	     test_bit(DPC_ASYNC_ISCSI_PDU, &ha->dpc_flags) ||
	     test_bit(DPC_DYNAMIC_LUN_SCAN, &ha->dpc_flags) ||
	     test_bit(DPC_REMOVE_DEVICE, &ha->dpc_flags) ||
	     test_bit(DPC_ISNS_RESTART, &ha->dpc_flags) ||
	     test_bit(DPC_ISNS_START, &ha->dpc_flags) ||
	     test_bit(DPC_ISNS_REREGISTER, &ha->dpc_flags) ||
	     test_bit(DPC_ISNS_DEREGISTER, &ha->dpc_flags) ||
	     test_bit(DPC_ISNS_STOP, &ha->dpc_flags) ||
	     test_bit(DPC_AEN, &ha->dpc_flags)) {
		DEBUG2(ql4_info(ha, "%s: scheduling dpc routine"
			      " - dpc flags = 0x%lx\n",
			      __func__, ha->dpc_flags));
		qla4xxx_wake_dpc(ha);
	}

	/* Reschedule timer thread to call us back in one second */
	mod_timer(&ha->timer, jiffies + HZ);

	DEBUG2(ha->seconds_since_last_intr++);
}

/**
 * qla4xxx_cmd_wait - waits for all outstanding commands to complete
 * @ha: Pointer to host adapter structure.
 *
 * This routine stalls the driver until all outstanding commands are returned.
 * Caller must release the Hardware Lock prior to calling this routine.
 **/
int qla4xxx_cmd_wait(struct scsi_qla_host *ha, uint32_t timeout)
{
	uint32_t index = 0;
	unsigned long flags;
	unsigned long wtime;

	if (timeout)
		wtime = jiffies + (timeout * HZ);
	else
		wtime = jiffies + (WAIT_CMD_TOV * HZ);

	DEBUG2(ql4_info(ha, "Wait up to %d seconds for cmds to "
	    "complete\n", timeout ? timeout : WAIT_CMD_TOV));

	while (!time_after_eq(jiffies, wtime)) {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		/* Find a command that hasn't completed. */
		for (index = 1; index < MAX_SRBS; index++) {
                        if (ha->active_srb_array[index] != NULL)
				break;
		}
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		/* If No Commands are pending, wait is complete */
		if (index == MAX_SRBS)
			return QLA_SUCCESS;

		msleep(1000);
	}
	/* If we timed out on waiting for commands to come back
	 * return ERROR. */
	return QLA_ERROR;
}

int qla4xxx_hw_reset(struct scsi_qla_host *ha)
{
	uint32_t ctrl_status;
	unsigned long flags = 0;

	DEBUG2(ql4_err(ha, "%s\n", __func__));

	if (ql4xxx_lock_drvr_wait(ha) != QLA_SUCCESS)
		return QLA_ERROR;

	spin_lock_irqsave(&ha->hardware_lock, flags);

	/*
	 * If the SCSI Reset Interrupt bit is set, clear it.
	 * Otherwise, the Soft Reset won't work.
	 */
	ctrl_status = readw(&ha->reg->ctrl_status);
	if ((ctrl_status & CSR_SCSI_RESET_INTR) != 0)
		writel(set_rmask(CSR_SCSI_RESET_INTR), &ha->reg->ctrl_status);

	/* Issue Soft Reset */
	writel(set_rmask(CSR_SOFT_RESET), &ha->reg->ctrl_status);
	readl(&ha->reg->ctrl_status);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	return QLA_SUCCESS;
}

/**
 * qla4xxx_soft_reset - performs soft reset.
 * @ha: Pointer to host adapter structure.
 **/
int qla4xxx_soft_reset(struct scsi_qla_host *ha)
{
	uint32_t max_wait_time;
	unsigned long flags = 0;
	int status;
	uint32_t ctrl_status;

	status = qla4xxx_hw_reset(ha);
	if (status != QLA_SUCCESS)
		return status;

	status = QLA_ERROR;
	/* Wait until the Network Reset Intr bit is cleared */
	max_wait_time = RESET_INTR_TOV;
	do {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		ctrl_status = readw(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		if ((ctrl_status & CSR_NET_RESET_INTR) == 0)
			break;

		msleep(1000);
	} while ((--max_wait_time));

	if ((ctrl_status & CSR_NET_RESET_INTR) != 0) {
		DEBUG2(ql4_warn(ha, "Network Reset Intr not cleared by "
			      "Network function, clearing it now!\n"));
		spin_lock_irqsave(&ha->hardware_lock, flags);
		writel(set_rmask(CSR_NET_RESET_INTR), &ha->reg->ctrl_status);
		readl(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
	}

	/* Wait until the firmware tells us the Soft Reset is done */
	max_wait_time = SOFT_RESET_TOV;
	do {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		ctrl_status = readw(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		if ((ctrl_status & CSR_SOFT_RESET) == 0) {
			status = QLA_SUCCESS;
			break;
		}

		msleep(1000);
	} while ((--max_wait_time));

	/*
	 * Also, make sure that the SCSI Reset Interrupt bit has been cleared
	 * after the soft reset has taken place.
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ctrl_status = readw(&ha->reg->ctrl_status);
	if ((ctrl_status & CSR_SCSI_RESET_INTR) != 0) {
		writel(set_rmask(CSR_SCSI_RESET_INTR), &ha->reg->ctrl_status);
		readl(&ha->reg->ctrl_status);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	/* If soft reset fails then most probably the bios on other
	 * function is also enabled.
	 * Since the initialization is sequential the other fn
	 * wont be able to acknowledge the soft reset.
	 * Issue a force soft reset to workaround this scenario.
	 */
	if (max_wait_time == 0) {
		/* Issue Force Soft Reset */
		spin_lock_irqsave(&ha->hardware_lock, flags);
		writel(set_rmask(CSR_FORCE_SOFT_RESET), &ha->reg->ctrl_status);
		readl(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
		/* Wait until the firmware tells us the Soft Reset is done */
		max_wait_time = SOFT_RESET_TOV;
		do {
			spin_lock_irqsave(&ha->hardware_lock, flags);
			ctrl_status = readw(&ha->reg->ctrl_status);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);

			if ((ctrl_status & CSR_FORCE_SOFT_RESET) == 0) {
				status = QLA_SUCCESS;
				break;
			}

			msleep(1000);
		} while ((--max_wait_time));
	}

	return status;
}

/**
 * qla4xxx_abort_active_cmds - returns all outstanding i/o requests to O.S.
 * @ha: Pointer to host adapter structure.
 * @res: returned scsi status
 *
 * This routine is called just prior to a HARD RESET to return all
 * outstanding commands back to the Operating System.
 * Caller should make sure that the following locks are released
 * before this calling routine: Hardware lock, and io_request_lock.
 **/
static void qla4xxx_abort_active_cmds(struct scsi_qla_host *ha, int res)
{
	struct srb *srb;
	int i;
	unsigned long flags;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (i = 1; i < MAX_SRBS; i++) {
		srb = ha->active_srb_array[i];
		if (srb != NULL) {
			qla4xxx_del_from_active_array(ha, i);
			srb->cmd->result = res;
			kref_put(&srb->srb_ref, qla4xxx_srb_compl);
		}
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}

void qla4xxx_dead_adapter_cleanup(struct scsi_qla_host *ha)
{
	clear_bit(AF_ONLINE, &ha->flags);

	/* Disable the board */
	ql4_info(ha, "Disabling the board\n");
	qla4xxx_abort_active_cmds(ha, DID_NO_CONNECT << 16);
	qla4xxx_mark_all_devices_missing(ha);
	clear_bit(AF_INIT_DONE, &ha->flags);
}

/**
 * qla4xxx_recover_adapter - recovers adapter after a fatal error
 * @ha: Pointer to host adapter structure.
 **/
static int qla4xxx_recover_adapter(struct scsi_qla_host *ha)
{
	int status = QLA_ERROR;
	uint8_t reset_chip = 0;
	unsigned long wait;

	/* Stall incoming I/O until we are done */
	DEBUG2(ql4_info(ha, "recover adapter .. BEGIN\n"));
	DEBUG2(ql4_info(ha, "%s: scsi_block_requests\n", __func__));
	scsi_block_requests(ha->host);

	ql4_info(ha, "%s: Adapter OFFLINE\n", __func__);
	clear_bit(AF_ONLINE, &ha->flags);

	set_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);

	/* Block all sessions, so iscsi_block_scsi_eh()
	 * blocks device_reset and target_reset error handlers
	 * till sessions become ACTIVE
	 */
	qla4xxx_mark_all_devices_missing(ha);

	if (test_bit(DPC_RESET_HA, &ha->dpc_flags))
		reset_chip = 1;

	/* For the DPC_RESET_HA_INTR case (ISP-4xxx specific)
	 * do not reset adapter, jump to initialize_adapter */
	if (test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags)) {
		status = QLA_SUCCESS;
		goto recover_ha_init_adapter;
	}

	/* For the ISP-82xx adapter, issue a stop_firmware if invoked
	 * from eh_host_reset or ioctl module */
	if (is_qla8022(ha) && !reset_chip &&
	    test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags)) {

		DEBUG2(ql4_info(ha, "%s - Performing stop_firmware...\n",
				__func__));
		status = ha->isp_ops->reset_firmware(ha);
		if (status == QLA_SUCCESS) {
			if (!test_bit(AF_FW_RECOVERY, &ha->flags))
				qla4xxx_cmd_wait(ha, 5);
			ha->isp_ops->disable_intrs(ha);
			qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
			qla4xxx_abort_active_cmds(ha, DID_RESET << 16);
		} else {
			/* If the stop_firmware fails then
			 * reset the entire chip */
			reset_chip = 1;
			clear_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
			set_bit(DPC_RESET_HA, &ha->dpc_flags);
		}
	}

	/* Issue full chip reset if recovering from a catastrophic error,
	 * or if stop_firmware fails for ISP-82xx.
	 * This is the default case for ISP-4xxx */
	if (!is_qla8022(ha) || reset_chip) {
		if (is_qla8022(ha)) {
			/* Check if 82XX firmware is alive or not
			 * We may have arrived here from NEED_RESET
			 * detection only */
			wait = jiffies + (FW_ALIVE_WAIT_TOV * HZ);
			if (!test_bit(AF_FW_RECOVERY, &ha->flags)) {
				while (time_before(jiffies, wait)) {
					if (qla4_8xxx_check_fw_alive(ha)) {
						qla4xxx_mailbox_premature_completion(ha);
						break;
					}

					set_current_state(TASK_UNINTERRUPTIBLE);
					schedule_timeout(HZ);
				}
			}

			if (!test_bit(AF_FW_RECOVERY, &ha->flags))
				qla4xxx_cmd_wait(ha, 0);
		} else
			qla4xxx_cmd_wait(ha, 0);
		qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
		qla4xxx_abort_active_cmds(ha, DID_RESET << 16);
		DEBUG2(ql4_info(ha, "%s - Performing chip reset..\n",
				__func__));
		status = ha->isp_ops->reset_chip(ha);
	}

	/* Flush any pending ddb changed AENs */
	qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);

	if (is_qla8022(ha))
		clear_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);

recover_ha_init_adapter:
	/* Upon successful firmware/chip reset, re-initialize the adapter */
	if (status == QLA_SUCCESS) {
		DEBUG2(ql4_info(ha, "%s - Initializing adapter..\n",
			__func__));

		/* For ISP-4xxx, force function 1 to always initialize
		 * before function 3 to prevent both funcions from
		 * stepping on top of the other */
		if (!is_qla8022(ha) && (ha->mac_index == 3))
			ssleep(6);

		/* NOTE: AF_ONLINE flag set upon successful completion of
		 *       qla4xxx_initialize_adapter */
		status = qla4xxx_initialize_adapter(ha, PRESERVE_DDB_LIST);
	}

	/* Retry failed adapter initialization, if necessary
	 * Do not retry initialize_adapter for RESET_HA_INTR (ISP-4xxx specific)
	 * case to prevent ping-pong resets between functions */
	if (!test_bit(AF_ONLINE, &ha->flags) &&
	    !test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags)) {
		/* Adapter initialization failed, see if we can retry
		 * resetting the ha.
		 * Since we don't want to block the DPC for too long
		 * with multiple resets in the same thread,
		 * utilize DPC to retry */
		if (!test_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags)) {
			ha->retry_reset_ha_cnt = MAX_RESET_HA_RETRIES;
			DEBUG2(ql4_info(ha, "recover adapter - retrying "
				      "(%d) more times\n",
				      ha->retry_reset_ha_cnt));
			set_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags);
			status = QLA_ERROR;
		} else {
			if (ha->retry_reset_ha_cnt > 0) {
				/* Schedule another Reset HA--DPC will retry */
				ha->retry_reset_ha_cnt--;
				DEBUG2(ql4_info(ha, "recover adapter - "
					      "retry remaining %d\n",
					      ha->retry_reset_ha_cnt));
				status = QLA_ERROR;
			}

			if (ha->retry_reset_ha_cnt == 0) {
				/* Recover adapter retries have been exhausted.
				 * Adapter DEAD */
				DEBUG2(ql4_info(ha, "recover adapter "
					      "failed - board disabled\n"));
				qla4xxx_dead_adapter_cleanup(ha);
				clear_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags);
				clear_bit(DPC_RESET_HA, &ha->dpc_flags);
				clear_bit(DPC_RESET_HA_FW_CONTEXT,
					  &ha->dpc_flags);
				status = QLA_ERROR;
			}
		}
	} else {
		clear_bit(DPC_RESET_HA, &ha->dpc_flags);
		clear_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
		clear_bit(DPC_RETRY_RESET_HA, &ha->dpc_flags);
	}

	ha->adapter_error_count++;

	if (test_bit(AF_ONLINE, &ha->flags))
		ha->isp_ops->enable_intrs(ha);

	DEBUG2(ql4_info(ha, "%s: scsi_unblock_requests\n", __func__));
	scsi_unblock_requests(ha->host);

	clear_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);
	DEBUG2(ql4_info(ha, "recover adapter: %s\n",
	    status == QLA_ERROR ? "FAILED" : "SUCCEDED"));

	return status;
}

/*
 * qla4xxx_process_async_pdu_iocb - processes ASYNC PDU IOCBS, if they are greater in
 * length than 48 bytes (i.e., more than just the iscsi header). Used for
 * unsolicited pdus received from target.
 */
static void qla4xxx_process_async_iscsi_pdu_iocb(struct scsi_qla_host *ha,
                        struct async_msg_pdu_iocb *amsg_pdu_iocb)
{
	struct iscsi_hdr *hdr;
	struct async_pdu_iocb *apdu;
	uint32_t len;
	void *buf_addr;
	dma_addr_t buf_addr_dma;
	uint32_t offset;
	struct passthru0 *pthru0_iocb;
	struct ddb_entry *ddb_entry = NULL;
	struct async_pdu_sense *pdu_sense;

	uint8_t using_prealloc = 1;
	uint8_t async_event_type;

	apdu = (struct async_pdu_iocb *)amsg_pdu_iocb->iocb;
	hdr = (struct iscsi_hdr *)apdu->iscsi_pdu_hdr;
	len = hdr->hlength + hdr->dlength[2] +
		(hdr->dlength[1]<<8) + (hdr->dlength[0]<<16);

	offset = sizeof(struct passthru0) + sizeof(struct passthru_status);
	if (len <= (PAGE_SIZE - offset)) {
		buf_addr_dma = ha->gen_req_rsp_iocb_dma + offset;
		buf_addr = (uint8_t *)ha->gen_req_rsp_iocb + offset;
	} else {
		using_prealloc = 0;
		buf_addr = dma_alloc_coherent(&ha->pdev->dev, len,
			&buf_addr_dma, GFP_KERNEL);
		if (!buf_addr) {
			dev_info(&ha->pdev->dev,
				"%s: dma_alloc_coherent failed\n", __func__);
			return;
		}
	}
	/* Create the pass-thru0 iocb */
	pthru0_iocb = ha->gen_req_rsp_iocb;
	memset(pthru0_iocb, 0, offset);

	pthru0_iocb->hdr.entry_type = ET_PASSTHRU0;
	pthru0_iocb->hdr.entry_count = 1;
	pthru0_iocb->target = cpu_to_le16(apdu->target_id);
	pthru0_iocb->ctrl_flags =
		cpu_to_le16(PT_FLAG_ISCSI_PDU | PT_FLAG_WAIT_4_RESPONSE);
	pthru0_iocb->timeout = cpu_to_le16(PT_DEFAULT_TIMEOUT);
	pthru0_iocb->in_data_seg64.base.addr_hi =
		cpu_to_le32(MSDW(buf_addr_dma));
	pthru0_iocb->in_data_seg64.base.addr_lo =
		cpu_to_le32(LSDW(buf_addr_dma));
	pthru0_iocb->in_data_seg64.count = cpu_to_le32(len);
	pthru0_iocb->async_pdu_handle = cpu_to_le32(apdu->async_pdu_handle);

	dev_info(&ha->pdev->dev,
		"%s: qla4xxx_issue_iocb\n", __func__);

	if (qla4xxx_issue_iocb(ha, sizeof(struct passthru0),
	    ha->gen_req_rsp_iocb_dma) != QLA_SUCCESS) {
		dev_info(&ha->pdev->dev,
			"%s: qla4xxx_issue_iocb failed\n", __func__);
		goto exit_async_pdu_iocb;
	}

	async_event_type = ((struct iscsi_async *)hdr)->async_event;
	pdu_sense = (struct async_pdu_sense *)buf_addr;

	switch (async_event_type) {
	case ISCSI_ASYNC_MSG_SCSI_EVENT:
		dev_info(&ha->pdev->dev,
			"%s: async msg event 0x%x processed\n"
			, __func__, async_event_type);

		if (pdu_sense->sense_data[12] == 0x3F) {
			if (pdu_sense->sense_data[13] == 0x0E) {
				/* reported luns data has changed */
				uint16_t fw_index = apdu->target_id;

				ddb_entry =
					qla4xxx_lookup_ddb_by_fw_index(ha,
								fw_index);
				if (ddb_entry == NULL) {
					dev_info(&ha->pdev->dev,
						"%s: No DDB entry for index "
						"[%d]\n" , __func__, fw_index);
					goto exit_async_pdu_iocb;
				}
				if (ddb_entry->fw_ddb_device_state !=
							DDB_DS_SESSION_ACTIVE) {
					dev_info(&ha->pdev->dev,
						"scsi%ld: %s: No Active Session"
						" for index [%d]\n",
						ha->host_no, __func__,
						fw_index);
					goto exit_async_pdu_iocb;
				}

				/* report new lun to kernel */
				if (test_bit(AF_ONLINE, &ha->flags))
					scsi_scan_target(&ddb_entry->sess->dev, 0,
						ddb_entry->sess->target_id,
						SCAN_WILD_CARD, 0);
			}
		}
		break;
	case ISCSI_ASYNC_MSG_REQUEST_LOGOUT:
	case ISCSI_ASYNC_MSG_DROPPING_CONNECTION:
	case ISCSI_ASYNC_MSG_DROPPING_ALL_CONNECTIONS:
	case ISCSI_ASYNC_MSG_PARAM_NEGOTIATION:
		dev_info(&ha->pdev->dev,
			"%s: async msg event 0x%x processed\n"
			, __func__, async_event_type);
		qla4xxx_conn_close_sess_logout(ha, apdu->target_id, 0);
		break;
	default:
		dev_info(&ha->pdev->dev,
			"%s: async msg event 0x%x not processed\n",
			__func__, async_event_type);
		break;
	};
exit_async_pdu_iocb:
	if (!using_prealloc)
		dma_free_coherent(&ha->pdev->dev, len,
				buf_addr, buf_addr_dma);
	return;
}

static void qla4xxx_relogin_all_devices(struct scsi_qla_host *ha)
{
	struct ddb_entry *ddb_entry, *dtemp;

	list_for_each_entry_safe(ddb_entry, dtemp, &ha->ddb_list, list) {
		if ((atomic_read(&ddb_entry->state) == DDB_STATE_MISSING) ||
		    (atomic_read(&ddb_entry->state) == DDB_STATE_DEAD)) {
			if (ddb_entry->fw_ddb_device_state ==
			    DDB_DS_SESSION_ACTIVE) {
				atomic_set(&ddb_entry->state, DDB_STATE_ONLINE);
				ql4_printk(KERN_INFO, ha, "scsi%ld: %s: ddb[%d]"
				    " marked ONLINE\n",	ha->host_no, __func__,
				    ddb_entry->fw_ddb_index);

				iscsi_unblock_session(ddb_entry->sess);
			} else
				qla4xxx_relogin_device(ha, ddb_entry);
		}
	}
}

void qla4xxx_wake_dpc(struct scsi_qla_host *ha)
{
	if (ha->dpc_thread)
		queue_work(ha->dpc_thread, &ha->dpc_work);
}

/**
 * qla4xxx_do_dpc - dpc routine
 * @data: in our case pointer to adapter structure
 *
 * This routine is a task that is schedule by the interrupt handler
 * to perform the background processing for interrupts.  We put it
 * on a task queue that is consumed whenever the scheduler runs; that's
 * so you can do anything (i.e. put the process to sleep etc).  In fact,
 * the mid-level tries to sleep when it reaches the driver threshold
 * "host->can_queue". This can cause a panic if we were in our interrupt code.
 **/
static void qla4xxx_do_dpc(struct work_struct *data)
{
	struct scsi_qla_host *ha =
		container_of(data, struct scsi_qla_host, dpc_work);
	struct ddb_entry *ddb_entry, *dtemp;
	struct async_msg_pdu_iocb *apdu_iocb, *apdu_iocb_tmp;
	int status = QLA_ERROR;

	DEBUG2(ql4_info(ha, "%s: DPC handler waking up."
	    "flags = 0x%08lx, dpc_flags = 0x%08lx\n", __func__, ha->flags,
	    ha->dpc_flags))

	/* Initialization not yet finished. Don't do anything yet. */
	if (!test_bit(AF_INIT_DONE, &ha->flags))
		return;

	if (test_bit(AF_EEH_BUSY, &ha->flags)) {
		DEBUG2(ql4_info(ha, "%s: flags = %lx\n", __func__, ha->flags));
		return;
	}

	/* HBA is in the process of being permanently disabled.
	 * Don't process anything */
	if (test_bit(AF_HA_REMOVAL, &ha->flags))
		return;

	if (is_qla8022(ha)) {
		if (test_bit(DPC_HA_UNRECOVERABLE, &ha->dpc_flags)) {
			qla4_8xxx_idc_lock(ha);
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
			    QLA82XX_DEV_FAILED);
			qla4_8xxx_idc_unlock(ha);
			ql4_info(ha, "HW State: FAILED\n");
			qla4_8xxx_device_state_handler(ha);
		}
		if (test_bit(DPC_HA_NEED_QUIESCENT, &ha->dpc_flags)) {
			qla4_8xxx_idc_lock(ha);
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
					QLA82XX_DEV_NEED_QUIESCENT);
			qla4_8xxx_idc_unlock(ha);
			qla4_8xxx_device_state_handler(ha);
			/* Clear quiescent state of all functions except
			 * quiesce owner quiescent state is cleared for owner
			 * during reset qsnt
			 */
			if (!test_bit(AF_QUIESCE_OWNER, &ha->flags)) {
				qla4_8xxx_idc_lock(ha);
				qla4_8xxx_clear_qsnt_ready(ha);
				clear_bit(DPC_QUIESCE_ACTIVE, &ha->dpc_flags);
				qla4_8xxx_idc_unlock(ha);
			}
		}
		if (test_bit(DPC_RESET_QUIESCENT, &ha->dpc_flags)) {
			if (test_bit(AF_QUIESCE_OWNER, &ha->flags)) {
				qla4_8xxx_idc_lock(ha);
				qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
							QLA82XX_DEV_READY);
				qla4_8xxx_clear_qsnt_ready(ha);
				clear_bit(DPC_QUIESCE_ACTIVE, &ha->dpc_flags);
				qla4_8xxx_idc_unlock(ha);
			}
			clear_bit(DPC_RESET_QUIESCENT, &ha->dpc_flags);
		}
	}

	if (!test_bit(DPC_RESET_ACTIVE, &ha->dpc_flags) &&
	    (test_bit(DPC_RESET_HA, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags) ||
	    test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags))) {
		if (ql4xdontresethba) {
			DEBUG2(ql4_info(ha, "%s: Don't Reset HBA\n", __func__));
			clear_bit(DPC_RESET_HA, &ha->dpc_flags);
			clear_bit(DPC_RESET_HA_INTR, &ha->dpc_flags);
			clear_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
			goto dpc_post_reset_ha;
		}
		if (test_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags) ||
		    test_bit(DPC_RESET_HA, &ha->dpc_flags))
			qla4xxx_recover_adapter(ha);

		if (test_bit(DPC_RESET_HA_INTR, &ha->dpc_flags)) {
			uint8_t wait_time = RESET_INTR_TOV;

			while ((readw(&ha->reg->ctrl_status) &
				(CSR_SOFT_RESET | CSR_FORCE_SOFT_RESET)) != 0) {
				if (--wait_time == 0)
					break;
				msleep(1000);
			}
			if (wait_time == 0)
				DEBUG2(ql4_info(ha, "%s: SR|FSR "
					      "bit not cleared-- resetting\n",
					      __func__));
			qla4xxx_abort_active_cmds(ha, DID_RESET << 16);
			if (ql4xxx_lock_drvr_wait(ha) == QLA_SUCCESS) {
				qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
				status = qla4xxx_recover_adapter(ha);
			}
			clear_bit(DPC_RESET_HA_INTR, &ha->dpc_flags);
			if (status == QLA_SUCCESS)
				ha->isp_ops->enable_intrs(ha);
		}
	}

dpc_post_reset_ha:

	/* ---- process AEN? --- */
	if (test_and_clear_bit(DPC_AEN, &ha->dpc_flags))
		qla4xxx_process_aen(ha, PROCESS_ALL_AENS);

	/* ---- Get DHCP IP Address? --- */
	if (test_and_clear_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags))
		qla4xxx_get_dhcp_ip_address(ha);

	/* ---- link change? --- */
	if (test_and_clear_bit(DPC_LINK_CHANGED, &ha->dpc_flags)) {
		if (!test_bit(AF_LINK_UP, &ha->flags)) {
			/* ---- link down? --- */
			qla4xxx_mark_all_devices_missing(ha);
		} else {
			/* ---- link up? --- *
			 * F/W will auto login to all devices ONLY ONCE after
			 * link up during driver initialization and runtime
			 * fatal error recovery.  Therefore, the driver must
			 * manually relogin to devices when recovering from
			 * connection failures, logouts, expired KATO, etc. */
			qla4xxx_relogin_all_devices(ha);
		}
	}

	/* ---- remove device ? ---- */
	if (test_and_clear_bit(DPC_REMOVE_DEVICE, &ha->dpc_flags)) {
		list_for_each_entry_safe(ddb_entry, dtemp,
		    &ha->ddb_list, list) {
			if (test_and_clear_bit(DF_REMOVE, &ddb_entry->flags)) {
				dev_info(&ha->pdev->dev,
					"%s: ddb[%d] os[%d] - removed\n",
					__func__, ddb_entry->fw_ddb_index,
					ddb_entry->os_target_id);
				qla4xxx_free_ddb(ha, ddb_entry);
			}
		}
	}

	/* ---- relogin device? --- */
	if (adapter_up(ha) &&
	    test_and_clear_bit(DPC_RELOGIN_DEVICE, &ha->dpc_flags)) {
		list_for_each_entry_safe(ddb_entry, dtemp,
					 &ha->ddb_list, list) {
			if (test_and_clear_bit(DF_RELOGIN, &ddb_entry->flags) &&
			    atomic_read(&ddb_entry->state) != DDB_STATE_ONLINE)
				qla4xxx_relogin_device(ha, ddb_entry);

			/*
			 * If mbx cmd times out there is no point
			 * in continuing further.
			 * With large no of targets this can hang
			 * the system.
			 */
			if (test_bit(DPC_RESET_HA, &ha->dpc_flags)) {
				ql4_warn(ha, "%s: need to reset hba\n",
				       __func__);
				break;
			}
		}
	}

	/* ---- perform dynamic lun scan? --- */
	if (adapter_up(ha) &&
	    test_and_clear_bit(DPC_DYNAMIC_LUN_SCAN, &ha->dpc_flags)) {
		list_for_each_entry_safe(ddb_entry, dtemp,
		    &ha->ddb_list, list) {
			if (test_and_clear_bit(DF_DYNAMIC_LUN_SCAN_NEEDED,
			    &ddb_entry->flags)) {
				dev_info(&ha->pdev->dev,"%s: ddb[%d] os[%d] "
					"perform dynamic lun scan\n",
					__func__, ddb_entry->fw_ddb_index,
					ddb_entry->os_target_id);
				/* report new lun to kernel */
				scsi_scan_target(&ddb_entry->sess->dev, 0,
					ddb_entry->sess->target_id,
					SCAN_WILD_CARD, 0);
				/* report new lun to GUI */
				qla4xxx_queue_lun_change_aen(ha,
					ddb_entry->fw_ddb_index);
			}
		}
	}

	/* iSNS Server Actions */
	if (adapter_up(ha)) {
		/* Error Recovery Case:
		 * The driver detected some sort of iSNS error.
		 * Stop the TCP connection then reschedule
		 */
		if (test_and_clear_bit(DPC_ISNS_RESTART, &ha->dpc_flags))
			ql4_isns_restart_service(ha);

		/* IP Address Change Case:
		 * If the initiator's IP address changes, we
		 * stop the TCP connection using the old source IP address. */
		if (test_and_clear_bit(DPC_ISNS_STOP, &ha->dpc_flags))
			ql4_isns_stop_service(ha);

		/* AEN 8021 iSNS Service Connection FAILED Case:
		 * We already have a TCP connection to iSNS server, but the
		 * iSNS Server closes the connection, so de-register.
		 * A future attempt will be made to re-register with iSNS
		 * server after the ISNS_STATE_RESTART_SRV_WAIT wait-time
		 * has expired. */
		if (test_and_clear_bit(DPC_ISNS_DEREGISTER, &ha->dpc_flags)) {
			ql4_isns_deregister_isns_server(ha);
		}

		/* ESI Timeout Case:
		 * We already have a TCP connection to iSNS server.
		 * De-register then attempt to re-register with iSNS server. */
		if (test_bit(DPC_ISNS_REREGISTER, &ha->dpc_flags) &&
			ql4_is_isns_active(ha)) {
			ql4_isns_register_isns_server(ha);
		}

		/* No Current TCP Connection --
		 * Polling, IP Address Change and Rescheduled Start Cases: */
		if (test_and_clear_bit(DPC_ISNS_START, &ha->dpc_flags))
			ql4_isns_start_service(ha);
	}

	/* Check for ASYNC iSCSI PDU IOCBs */
	if (adapter_up(ha) &&
	    test_bit(DPC_ASYNC_ISCSI_PDU, &ha->dpc_flags)) {

		list_for_each_entry_safe(apdu_iocb, apdu_iocb_tmp,
		    &ha->async_iocb_list, list) {
			qla4xxx_process_async_iscsi_pdu_iocb(ha, apdu_iocb);
			list_del_init(&apdu_iocb->list);
			kfree(apdu_iocb);
		}
		clear_bit(DPC_ASYNC_ISCSI_PDU, &ha->dpc_flags);
	}
}

/**
 * qla4xxx_free_adapter - release the adapter
 * @ha: pointer to adapter structure
 **/
static void qla4xxx_free_adapter(struct scsi_qla_host *ha, int rm_host)
{
	/* Deregister with the iSNS Server */
	/* NOTE: On 4xxx dual port adapters, if one port unloads and resets the
	 *       chip, the other port will no longer be able to communicate
	 *       with the chip.  Thus, iSNS will not deregister or get
	 *       disabled on the second port.  The iSNS server will deregister
	 *       the second port (no ESI notification) in approximately 15
	 *       minutes.  But, if driver re-loads within that time, the driver
	 *       will first de-register with the iSNS server, then register
	 *       with it to prevent multiple registration errors.
	 */
	if (test_bit(AF_ONLINE, &ha->flags) &&
	    test_bit(ISNS_FLAG_ISNS_ENABLED_IN_ISP, &ha->isns.flags)) {
		DEBUG2(ql4_info(ha, "%s: Stop iSNS service\n", __func__));
		ql4_isns_stop_service(ha);
	}

	if (test_bit(AF_INTERRUPTS_ON, &ha->flags)) {
		/* Turn-off interrupts on the card. */
		ha->isp_ops->disable_intrs(ha);
	}

	/* Remove timer thread, if present */
	if (ha->timer_active)
		qla4xxx_stop_timer(ha);

	/* Kill the kernel thread for this host */
	if (ha->pt_thread)
		destroy_workqueue(ha->pt_thread);
	if (ha->dpc_thread)
		destroy_workqueue(ha->dpc_thread);

	if (rm_host ) {
		/* remove devs from iscsi_sessions to scsi_devices */
		qla4xxx_free_ddb_list(ha);

		scsi_remove_host(ha->host);
	}

	/* Put firmware in known state */
	ha->isp_ops->reset_firmware(ha);

	if (is_qla8022(ha)) {
		qla4_8xxx_idc_lock(ha);
		qla4_8xxx_clear_drv_active(ha);
		qla4_8xxx_idc_unlock(ha);
	}

	/* Detach interrupts */
	if (test_and_clear_bit(AF_IRQ_ATTACHED, &ha->flags))
		qla4xxx_free_irqs(ha);

	/* free extra memory */
	qla4xxx_mem_free(ha);
}

int qla4_8xxx_iospace_config(struct scsi_qla_host *ha)
{
	int status = 0;
	uint8_t revision_id;
	unsigned long mem_base, mem_len, db_base, db_len;
	struct pci_dev *pdev = ha->pdev;

	status = pci_request_regions(pdev, DRIVER_NAME);
	if (status) {
		ql4_warn(ha, "Failed to reserve PIO regions (%s) status=%d\n",
			pci_name(pdev), status);
		goto iospace_error_exit;
	}

	pci_read_config_byte(pdev, PCI_REVISION_ID, &revision_id);
	DEBUG2(ql4_info(ha, "%s: revision-id=%d\n", __func__, revision_id));
	ha->revision_id = revision_id;

	/* remap phys address */
	mem_base = pci_resource_start(pdev, 0); /* 0 is for BAR 0 */
	mem_len = pci_resource_len(pdev, 0);
	DEBUG2(ql4_info(ha, "%s: ioremap from %lx a size of %lx\n",
	    __func__, mem_base, mem_len));

	/* mapping of pcibase pointer */
	ha->nx_pcibase = (unsigned long)ioremap(mem_base, mem_len);
	if (!ha->nx_pcibase) {
		ql4_err(ha, "cannot remap MMIO (%s), aborting\n",
			pci_name(pdev));
		pci_release_regions(ha->pdev);
		goto iospace_error_exit;
	}

	/* Mapping of IO base pointer, door bell read and write pointer */

	/* mapping of IO base pointer */
	ha->qla4_8xxx_reg =
	    (struct device_reg_82xx  __iomem *)((uint8_t *)ha->nx_pcibase +
	    0xbc000 + (ha->pdev->devfn << 11));

	db_base = pci_resource_start(pdev, 4);  /* doorbell is on bar 4 */
	db_len = pci_resource_len(pdev, 4);

	ha->nx_db_wr_ptr = (ha->pdev->devfn == 4 ? QLA82XX_CAM_RAM_DB1 :
				QLA82XX_CAM_RAM_DB2);

	return 0;
iospace_error_exit:
	return -ENOMEM;
}

/***
 * qla4xxx_iospace_config - maps registers
 * @ha: pointer to adapter structure
 *
 * This routines maps HBA's registers from the pci address space
 * into the kernel virtual address space for memory mapped i/o.
 **/
int qla4xxx_iospace_config(struct scsi_qla_host *ha)
{
	unsigned long pio, pio_len, pio_flags;
	unsigned long mmio, mmio_len, mmio_flags;

	pio = pci_resource_start(ha->pdev, 0);
	pio_len = pci_resource_len(ha->pdev, 0);
	pio_flags = pci_resource_flags(ha->pdev, 0);
	if (pio_flags & IORESOURCE_IO) {
		if (pio_len < MIN_IOBASE_LEN) {
			ql4_warn(ha, "Invalid PCI I/O region size\n");
			pio = 0;
		}
	} else {
		ql4_warn(ha, "region #0 not a PIO resource\n");
		pio = 0;
	}

	/* Use MMIO operations for all accesses. */
	mmio = pci_resource_start(ha->pdev, 1);
	mmio_len = pci_resource_len(ha->pdev, 1);
	mmio_flags = pci_resource_flags(ha->pdev, 1);

	if (!(mmio_flags & IORESOURCE_MEM)) {
		ql4_err(ha, "region #0 not an MMIO resource, aborting\n");

		goto iospace_error_exit;
	}

	if (mmio_len < MIN_IOBASE_LEN) {
		ql4_err(ha, "Invalid PCI mem region size, aborting\n");
		goto iospace_error_exit;
	}

	if (pci_request_regions(ha->pdev, DRIVER_NAME)) {
		ql4_warn(ha, "Failed to reserve PIO/MMIO regions\n");

		goto iospace_error_exit;
	}

	ha->pio_address = pio;
	ha->pio_length = pio_len;
	ha->reg = ioremap(mmio, MIN_IOBASE_LEN);
	if (!ha->reg) {
		ql4_err(ha, "cannot remap MMIO, aborting\n");

		goto iospace_error_exit;
	}

	return 0;

iospace_error_exit:
	return -ENOMEM;
}

static struct isp_operations qla4xxx_isp_ops = {
	.iospace_config         = qla4xxx_iospace_config,
	.pci_config             = qla4xxx_pci_config,
	.disable_intrs          = qla4xxx_disable_intrs,
	.enable_intrs           = qla4xxx_enable_intrs,
	.start_firmware         = qla4xxx_start_firmware,
	.intr_handler           = qla4xxx_intr_handler,
	.interrupt_service_routine = qla4xxx_interrupt_service_routine,
	.reset_chip             = qla4xxx_soft_reset,
	.reset_firmware         = qla4xxx_hw_reset,
	.queue_iocb             = qla4xxx_queue_iocb,
	.complete_iocb          = qla4xxx_complete_iocb,
	.rd_shdw_req_q_out      = qla4xxx_rd_shdw_req_q_out,
	.rd_shdw_rsp_q_in       = qla4xxx_rd_shdw_rsp_q_in,
	.get_sys_info           = qla4xxx_get_sys_info,
};

static struct isp_operations qla4_8xxx_isp_ops = {
	.iospace_config         = qla4_8xxx_iospace_config,
	.pci_config             = qla4_8xxx_pci_config,
	.disable_intrs          = qla4_8xxx_disable_intrs,
	.enable_intrs           = qla4_8xxx_enable_intrs,
	.start_firmware         = qla4_8xxx_load_risc,
	.intr_handler           = qla4_8xxx_intr_handler,
	.interrupt_service_routine = qla4_8xxx_interrupt_service_routine,
	.reset_chip             = qla4_8xxx_isp_reset,
	.reset_firmware         = qla4_8xxx_stop_firmware,
	.queue_iocb             = qla4_8xxx_queue_iocb,
	.complete_iocb          = qla4_8xxx_complete_iocb,
	.rd_shdw_req_q_out      = qla4_8xxx_rd_shdw_req_q_out,
	.rd_shdw_rsp_q_in       = qla4_8xxx_rd_shdw_rsp_q_in,
	.get_sys_info           = qla4_8xxx_get_sys_info,
};

uint16_t qla4xxx_rd_shdw_req_q_out(struct scsi_qla_host *ha)
{
	return (uint16_t)le32_to_cpu(ha->shadow_regs->req_q_out);
}

uint16_t qla4_8xxx_rd_shdw_req_q_out(struct scsi_qla_host *ha)
{
	return (uint16_t)le32_to_cpu(readl(&ha->qla4_8xxx_reg->req_q_out));
}

uint16_t qla4xxx_rd_shdw_rsp_q_in(struct scsi_qla_host *ha)
{
	return (uint16_t)le32_to_cpu(ha->shadow_regs->rsp_q_in);
}

uint16_t qla4_8xxx_rd_shdw_rsp_q_in(struct scsi_qla_host *ha)
{
	return (uint16_t)le32_to_cpu(readl(&ha->qla4_8xxx_reg->rsp_q_in));
}

static void ql4_get_aen_log(struct scsi_qla_host *ha, struct ql4_aen_log *aenl)
{
	if (aenl) {
		memcpy(aenl, &ha->aen_log, sizeof (ha->aen_log));
		ha->aen_log.count = 0;
	}
}

static inline int qla4xxx_ioctl_init(struct scsi_qla_host *ha)
{
	ha->ql4mbx = qla4xxx_mailbox_command;
	ha->ql4cmd = qla4xxx_send_command_to_isp;
	ha->ql4getaenlog = ql4_get_aen_log;
	ha->ql4_isns_start_svc = ql4_isns_start_service;
	ha->ql4_isns_stop_svc = ql4_isns_stop_service;
	ha->ql4_isns_populate_server_ip = ql4_isns_populate_server_ip;
	ha->ql4_isns_send_dev_get_next = ql4_isns_send_dev_get_next;
	ha->ql4_isns_send_dev_attr_qry = ql4_isns_send_dev_attr_qry;
	ha->ql4_is_isns_active = ql4_is_isns_active;
	return 0;
}

/**
 * qla4xxx_probe_adapter - callback function to probe HBA
 * @pdev: pointer to pci_dev structure
 * @pci_device_id: pointer to pci_device entry
 *
 * This routine will probe for Qlogic 4xxx iSCSI host adapters.
 * It returns zero if successful. It also initializes all data necessary for
 * the driver.
 **/
static int __devinit qla4xxx_probe_adapter(struct pci_dev *pdev,
					   const struct pci_device_id *ent)
{
	int ret = -ENODEV, status;
	struct Scsi_Host *host;
	struct scsi_qla_host *ha;
	uint8_t init_retry_count = 0;
	char buf[34];
	struct qla4_8xxx_legacy_intr_set *nx_legacy_intr;
	int rm_host = 0;
	uint32_t dev_state;

	if (pci_enable_device(pdev))
		return -1;

	host = scsi_host_alloc(&qla4xxx_driver_template, sizeof(*ha));
	if (host == NULL) {
		printk("qla4xxx: Couldn't allocate host from scsi layer!\n");
		goto probe_disable_device;
	}

	/* Clear our data area */
	ha = (struct scsi_qla_host *) host->hostdata;
	memset(ha, 0, sizeof(*ha));

	/* Save the information from PCI BIOS.	*/
	ha->pdev = pdev;
	ha->host = host;
	ha->host_no = host->host_no;
	ha->func_num = PCI_FUNC(ha->pdev->devfn);
	ha->struct_chk = sizeof(struct scsi_qla_host) +
		sizeof(struct ddb_entry) + sizeof(struct srb);

	pci_enable_pcie_error_reporting(pdev);

	/* Setup Runtime configurable options */
	if (is_qla8022(ha)) {
		ha->isp_ops = &qla4_8xxx_isp_ops;
		rwlock_init(&ha->hw_lock);
		ha->qdr_sn_window = -1;
		ha->ddr_mn_window = -1;
		ha->curr_window = 255;
		ha->func_num = PCI_FUNC(ha->pdev->devfn);
		nx_legacy_intr = &legacy_intr[ha->func_num];
		ha->nx_legacy_intr.int_vec_bit = nx_legacy_intr->int_vec_bit;
		ha->nx_legacy_intr.tgt_status_reg =
			nx_legacy_intr->tgt_status_reg;
		ha->nx_legacy_intr.tgt_mask_reg = nx_legacy_intr->tgt_mask_reg;
		ha->nx_legacy_intr.pci_int_reg = nx_legacy_intr->pci_int_reg;
	} else {
		ha->isp_ops = &qla4xxx_isp_ops;
	}

#if defined (QL4_SLES11_SP1) || defined (QL4_RHEL6)
	/* Set EEH reset type to fundamental if required by hba */
	if (is_qla8022(ha))
		pdev->needs_freset = 1;
#endif

	/* Configure PCI I/O space. */
	ret = ha->isp_ops->iospace_config(ha);
	if (ret)
		goto probe_failed_ioconfig;

	ql4_info(ha, "Found an ISP%04x, irq %d, iobase 0x%p\n",
		   pdev->device, pdev->irq, ha->reg);

	qla4xxx_config_dma_addressing(ha);

	/* Initialize lists and spinlocks. */
	INIT_LIST_HEAD(&ha->ddb_list);
	INIT_LIST_HEAD(&ha->free_srb_q);
	INIT_LIST_HEAD(&ha->async_iocb_list);
	INIT_LIST_HEAD(&ha->isns.rcvd_pdu_list);

	mutex_init(&ha->pt_sem);
	mutex_init(&ha->mbox_sem);
	init_completion(&ha->mbx_intr_comp);

	spin_lock_init(&ha->hardware_lock);

	/* Allocate dma buffers */
	if (qla4xxx_mem_alloc(ha)) {
		ql4_warn(ha, "[ERROR] Failed to allocate memory for adapter\n");

		ret = -ENOMEM;
		goto probe_failed;
	}

	if (is_qla8022(ha))
		(void) qla4_8xxx_get_flash_info(ha);

	DEBUG2(ql4_info(ha, "scsi: %s: Starting kernel thread for "
		      "qla4xxx_ptc\n", __func__));
	sprintf(buf, "qla4xxx_%lu_pt", ha->host_no);
	ha->pt_thread = create_singlethread_workqueue(buf);
	if (!ha->pt_thread) {
		dev_warn(&ha->pdev->dev, "Unable to start pt thread!\n");
		ret = -ENODEV;
		goto probe_failed;
	}
	INIT_WORK(&ha->pt_work, ql4_isns_dequeue_passthru_sts_iocb);

	/*
	 * Initialize the Host adapter request/response queues and
	 * firmware
	 * NOTE: interrupts enabled upon successful completion
	 */
	status = qla4xxx_initialize_adapter(ha, REBUILD_DDB_LIST);
	while ((!test_bit(AF_ONLINE, &ha->flags)) &&
	    init_retry_count++ < MAX_INIT_RETRIES) {
		if (is_qla8022(ha)) {
			qla4_8xxx_idc_lock(ha);
			dev_state = qla4_8xxx_rd_32(ha, QLA82XX_CRB_DEV_STATE);
			qla4_8xxx_idc_unlock(ha);
			if (dev_state == QLA82XX_DEV_FAILED) {
				dev_info(&ha->pdev->dev, "%s: don't retry "
					"adapter init. H/W is in Failed state\n",
					__func__);
				break;
			}
		}

		DEBUG2(ql4_info(ha, "scsi: %s: retrying adapter initialization "
			      "(%d)\n", __func__, init_retry_count));

		if (ha->isp_ops->reset_chip(ha) == QLA_ERROR)
			continue;

		status = qla4xxx_initialize_adapter(ha, REBUILD_DDB_LIST);
	}

	if (!test_bit(AF_ONLINE, &ha->flags)) {
		ql4_warn(ha, "Failed to initialize adapter\n");
		if (is_qla8022(ha) && ql4xdontresethba) {
			qla4_8xxx_idc_lock(ha);
			DEBUG2(ql4_info(ha, "HW State: Setting to failed\n"));
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
					QLA82XX_DEV_FAILED);
			qla4_8xxx_idc_unlock(ha);
		}

		ret = -ENODEV;
		goto probe_failed;
	}

	host->cmd_per_lun = 3;
	host->max_channel = 0;
	host->max_lun = MAX_LUNS - 1;
	host->max_id = MAX_TARGETS;
	host->max_cmd_len = IOCB_MAX_CDB_LEN;
	host->transportt = qla4xxx_scsi_transport;

	if (is_qla8022(ha) && ql4xmaxcmds)
		host->can_queue = ql4xmaxcmds;
	else
		host->can_queue = REQUEST_QUEUE_DEPTH + 128;

	/* Startup the kernel thread for this host adapter. */
	DEBUG2(ql4_info(ha, "scsi: %s: Starting kernel thread for "
		      "qla4xxx_dpc\n", __func__));
	sprintf(buf, "qla4xxx_%lu_dpc", ha->host_no);
	ha->dpc_thread = create_singlethread_workqueue(buf);
	if (!ha->dpc_thread) {
		ql4_warn(ha, "Unable to start DPC thread!\n");
		ret = -ENODEV;
		goto probe_failed;
	}
	INIT_WORK(&ha->dpc_work, qla4xxx_do_dpc);

	/* For ISP-82XX, request_irqs is called in qla4_8xxx_load_risc
	 * (which is called indirectly by qla4xxx_initialize_adapter),
	 * so that irqs will be registered after crbinit but before
	 * mbx_intr_enable.
	 */
	if (!is_qla8022(ha)) {
		ret = qla4xxx_request_irqs(ha);
		if (ret) {
			ql4_warn(ha, "Failed to reserve "
			    "interrupt %d already in use.\n", pdev->irq);
			goto probe_failed;
		}
	}

	pci_save_state(ha->pdev);
	ha->isp_ops->enable_intrs(ha);

	/* Start timer thread. */
	qla4xxx_start_timer(ha, qla4xxx_timer, 1);

	pci_set_drvdata(pdev, ha);

	ret = scsi_add_host(host, &pdev->dev);
	if (ret)
		goto probe_failed;

	ql4_info(ha, " QLogic iSCSI HBA Driver version: %s\n"
	       "  QLogic ISP%04x @ %s, fw=%02d.%02d.%02d.%02d\n",
	       qla4xxx_version_str, ha->pdev->device, pci_name(ha->pdev),
	       ha->firmware_version[0], ha->firmware_version[1],
	       ha->patch_number, ha->build_number);

	scsi_scan_host(host);

	/* Insert new entry into the list of adapters. */
	klist_add_tail(&ha->node, &qla4xxx_hostlist);
	ha->instance = atomic_inc_return(&qla4xxx_hba_count) - 1;

	if (qla4xxx_ioctl_init(ha)) {
		dev_warn(&ha->pdev->dev, "ioctl init failed\n");
		goto remove_host;
	}

	set_bit(AF_INIT_DONE, &ha->flags);
	dev_info(&ha->pdev->dev, "%s: AF_INIT_DONE\n", __func__);
	return 0;

remove_host:
	rm_host = 1;

probe_failed:
	qla4xxx_free_adapter(ha, rm_host);

probe_failed_ioconfig:
	pci_disable_pcie_error_reporting(pdev);
	scsi_host_put(ha->host);

probe_disable_device:
	pci_disable_device(pdev);

	return ret;
}

/**
 * qla4xxx_prevent_other_port_reinit - Mark the other ISP-4xxx port to indicate
 * that the driver is being removed, so that the other port will not
 * re-initialize while in the process of removing the ha due to driver unload
 * or hba hotplug.
 * @ha: pointer to adapter structure
 **/
static void qla4xxx_prevent_other_port_reinit(struct scsi_qla_host *ha)
{
        struct scsi_qla_host *ha_listp;
	struct klist_iter i;
	struct klist_node *n;

	klist_iter_init(&qla4xxx_hostlist, &i);
	while ((n = klist_next(&i)) != NULL) {
		ha_listp = container_of(n, struct scsi_qla_host, node);
                if (ha == ha_listp)
                        continue;

                if ((pci_domain_nr(ha->pdev->bus) ==
                     pci_domain_nr(ha_listp->pdev->bus)) &&
                    (ha->pdev->bus->number ==
                     ha_listp->pdev->bus->number) &&
                    (PCI_SLOT(ha->pdev->devfn) ==
                     PCI_SLOT(ha_listp->pdev->devfn)) ) {

                        set_bit(AF_HA_REMOVAL, &ha_listp->flags);
			DEBUG2(ql4_info(ha, "%s: Prevent %s reinit\n",
				__func__, dev_name(&((ha_listp)->pdev->dev))));
                }
        }

	klist_iter_exit(&i);
}

/**
 * qla4xxx_remove_adapter - calback function to remove adapter.
 * @pci_dev: PCI device pointer
 **/
static void __devexit qla4xxx_remove_adapter(struct pci_dev *pdev)
{
	struct scsi_qla_host *ha;
	int rm_host = 1;

	ha = pci_get_drvdata(pdev);

	if (!is_qla8022(ha))
		qla4xxx_prevent_other_port_reinit(ha);

	klist_remove(&ha->node);
	atomic_dec(&qla4xxx_hba_count);

	qla4xxx_free_adapter(ha, rm_host);

	scsi_host_put(ha->host);

	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

/**
 * qla4xxx_config_dma_addressing() - Configure OS DMA addressing method.
 * @ha: HA context
 *
 * At exit, the @ha's flags.enable_64bit_addressing set to indicated
 * supported addressing method.
 */
static void qla4xxx_config_dma_addressing(struct scsi_qla_host *ha)
{
	int retval;

	/* Update our PCI device dma_mask for full 64 bit mask */
	if (pci_set_dma_mask(ha->pdev, DMA_BIT_MASK(64)) == 0) {
		if (pci_set_consistent_dma_mask(ha->pdev, DMA_BIT_MASK(64))) {
			dev_dbg(&ha->pdev->dev,
				  "Failed to set 64 bit PCI consistent mask; "
				   "using 32 bit.\n");
			retval = pci_set_consistent_dma_mask(ha->pdev,
							     DMA_BIT_MASK(32));
		}
	} else
		retval = pci_set_dma_mask(ha->pdev, DMA_BIT_MASK(32));
}

static int qla4xxx_slave_alloc(struct scsi_device *sdev)
{
	struct iscsi_cls_session *sess = starget_to_session(sdev->sdev_target);
	struct ddb_entry *ddb = sess->dd_data;
	int queue_depth = MAX_Q_DEPTH;

	if (ql4xmaxqdepth != 0 && ql4xmaxqdepth <= 0xffffU)
		queue_depth = ql4xmaxqdepth;

	sdev->hostdata = ddb;
	sdev->tagged_supported = 1;
	scsi_activate_tcq(sdev, queue_depth);
	return 0;
}

static int qla4xxx_slave_configure(struct scsi_device *sdev)
{
	sdev->tagged_supported = 1;
	return 0;
}

static void qla4xxx_slave_destroy(struct scsi_device *sdev)
{
	int queue_depth = MAX_Q_DEPTH;

	if (ql4xmaxqdepth != 0 && ql4xmaxqdepth <= 0xffffU)
		queue_depth = ql4xmaxqdepth;

	scsi_deactivate_tcq(sdev, queue_depth);
}

/**
 * qla4xxx_del_from_active_array - returns an active srb
 * @ha: Pointer to host adapter structure.
 * @index: index into the active_array
 *
 * This routine removes and returns the srb at the specified index
 **/
struct srb *qla4xxx_del_from_active_array(struct scsi_qla_host *ha,
    uint32_t index)
{
	struct srb *srb = NULL;

	/* validate handle and remove from active array */
	if (index >= MAX_SRBS)
		return srb;

	srb = ha->active_srb_array[index];
	ha->active_srb_array[index] = NULL;
	if (!srb)
		return srb;

	/* update counters */
	if (srb->flags & SRB_DMA_VALID) {
		ha->req_q_count += srb->iocb_cnt;
		ha->iocb_cnt -= srb->iocb_cnt;
		if (srb->cmd)
			srb->cmd->host_scribble =
				(unsigned char *)(unsigned long) MAX_SRBS;
	}
	return srb;
}

/**
 * qla4xxx_eh_wait_on_command - waits for command to be returned by firmware
 * @ha: Pointer to host adapter structure.
 * @cmd: Scsi Command to wait on.
 *
 * This routine waits for the command to be returned by the Firmware
 * for some max time.
 **/
static int qla4xxx_eh_wait_on_command(struct scsi_qla_host *ha,
				      struct scsi_cmnd *cmd)
{
	int done = 0;
	struct srb *rp;
	uint32_t max_wait_time = EH_WAIT_CMD_TOV;
	int ret = SUCCESS;

	/* Dont wait on command if PCI error is being handled
	 * by PCI AER driver
	 */
	if (unlikely(pci_channel_offline(ha->pdev)) ||
	    (test_bit(AF_EEH_BUSY, &ha->flags))) {
		ql4_warn(ha, "Return from %s\n", __func__);
		return ret;
	}

	do {
		/* Checking to see if its returned to OS */
		rp = (struct srb *) CMD_SP(cmd);
		if (rp == NULL) {
			done++;
			break;
		}

		msleep(2000);
	} while (max_wait_time--);

	return done;
}

/**
 * qla4xxx_wait_for_hba_online - waits for HBA to come online
 * @ha: Pointer to host adapter structure
 **/
static int qla4xxx_wait_for_hba_online(struct scsi_qla_host *ha)
{
	unsigned long wait_online;

	wait_online = jiffies + (HBA_ONLINE_TOV * HZ);
	while (time_before(jiffies, wait_online)) {

		if (adapter_up(ha))
			return QLA_SUCCESS;

		msleep(2000);
	}

	return QLA_ERROR;
}

/**
 * qla4xxx_eh_wait_for_commands - wait for active cmds to finish.
 * @ha: pointer to HBA
 * @t: target id
 * @l: lun id
 *
 * This function waits for all outstanding commands to a lun to complete. It
 * returns 0 if all pending commands are returned and 1 otherwise.
 **/
static int qla4xxx_eh_wait_for_commands(struct scsi_qla_host *ha,
					struct scsi_target *stgt,
					struct scsi_device *sdev)
{
	int cnt;
	int status = 0;
	struct srb *sp;
	struct scsi_cmnd *cmd;
	unsigned long flags;

	/*
	 * Waiting for all commands for the designated target or dev
	 * in the active array
	 */
	for (cnt = 1; cnt < MAX_SRBS; cnt++) {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		sp = ha->active_srb_array[cnt];
		if (sp) {
			cmd = sp->cmd;
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			if (cmd && stgt==scsi_target(cmd->device) &&
				(!sdev || sdev==cmd->device)) {
				if (!qla4xxx_eh_wait_on_command(ha, cmd)) {
					status++;
					break;
				}
			}
		} else {
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
		}
	}

	return status;
}

/**
 * qla4xxx_eh_abort - callback for abort task.
 * @cmd: Pointer to Linux's SCSI command structure
 *
 * This routine is called by the Linux OS to abort the specified
 * command.
 **/
static int qla4xxx_eh_abort(struct scsi_cmnd *cmd)
{
	struct scsi_qla_host *ha = to_qla_host(cmd->device->host);
	unsigned int id = cmd->device->id;
	unsigned int lun = cmd->device->lun;
	unsigned long serial = cmd->serial_number;
	unsigned long flags;
	struct srb *srb = NULL;
	int ret = SUCCESS;
	int wait = 0;

	ql4_info(ha, "%d:%d: Abort command issued cmd=%p, pid=%ld\n",
			id, lun, cmd, serial);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	srb = (struct srb *) CMD_SP(cmd);

	if (!srb) {
		DEBUG2(ql4_info(ha, "ABORT - cmd already completed.\n"));
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
		return SUCCESS;
	}

	kref_get(&srb->srb_ref);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (qla4xxx_abort_task(ha, srb) != QLA_SUCCESS) {
		DEBUG3(ql4_info(ha, "%d:%d: Abort_task mbx failed.\n",
				id, lun));
		ret = FAILED;
	} else {
		DEBUG3(ql4_info(ha, "%d:%d: Abort_task mbx success.\n",
				id, lun));
		wait = 1;
	}

	kref_put(&srb->srb_ref, qla4xxx_srb_compl);

	/* Wait for command to complete */
	if (wait) {
		if (!qla4xxx_eh_wait_on_command(ha, cmd)) {
			DEBUG2(ql4_info(ha, "%d:%d: Abort handler timed out\n",
					id, lun));
			ret = FAILED;
		}
	}

	ql4_info(ha, "%d:%d: Abort command - %s\n", id, lun,
		(ret == SUCCESS) ? "succeded" : "failed");

	return ret;
}

/**
 * qla4xxx_eh_device_reset - callback for target reset.
 * @cmd: Pointer to Linux's SCSI command structure
 *
 * This routine is called by the Linux OS to reset all luns on the
 * specified target.
 **/
static int qla4xxx_eh_device_reset(struct scsi_cmnd *cmd)
{
	struct scsi_qla_host *ha = to_qla_host(cmd->device->host);
	struct ddb_entry *ddb_entry = cmd->device->hostdata;
	int ret = FAILED, stat;

	if (!ddb_entry)
		return ret;

	ret = iscsi_block_scsi_eh(cmd);
	if (ret)
		return ret;
	ret = FAILED;

	ql4_info(ha, "%d:%d:%d: DEVICE RESET ISSUED.\n",
		   cmd->device->channel, cmd->device->id, cmd->device->lun);

	DEBUG2(ql4_info(ha, "DEVICE_RESET cmd=%p jiffies = 0x%lx, to=%x,"
		      "dpc_flags=%lx, status=%x allowed=%d\n",
		      cmd, jiffies, cmd->request->timeout / HZ,
		      ha->dpc_flags, cmd->result, cmd->allowed));

	/* FIXME: wait for hba to go online */
	stat = qla4xxx_reset_lun(ha, ddb_entry, cmd->device->lun);
	if (stat != QLA_SUCCESS) {
		ql4_info(ha, "DEVICE RESET FAILED. %d\n", stat);
		goto eh_dev_reset_done;
	}

	if (qla4xxx_eh_wait_for_commands(ha, scsi_target(cmd->device),
					 cmd->device)) {
		ql4_info(ha, "DEVICE RESET FAILED - waiting for "
			   "commands.\n");
		goto eh_dev_reset_done;
	}

	/* Send marker. */
	if (qla4xxx_send_marker_iocb(ha, ddb_entry, cmd->device->lun,
		MM_LUN_RESET) != QLA_SUCCESS)
		goto eh_dev_reset_done;

	ql4_info(ha, "%d:%d:%d): DEVICE RESET SUCCEEDED.\n",
		   cmd->device->channel, cmd->device->id, cmd->device->lun);

	ret = SUCCESS;

eh_dev_reset_done:

	return ret;
}

/**
 * qla4xxx_eh_target_reset - callback for target reset.
 * @cmd: Pointer to Linux's SCSI command structure
 *
 * This routine is called by the Linux OS to reset the target.
 **/
static int qla4xxx_eh_target_reset(struct scsi_cmnd *cmd)
{
	struct scsi_qla_host *ha = to_qla_host(cmd->device->host);
	struct ddb_entry *ddb_entry = cmd->device->hostdata;
	int stat, ret;

	if (!ddb_entry)
		return FAILED;

	ret = iscsi_block_scsi_eh(cmd);
	if (ret)
		return ret;

	starget_printk(KERN_INFO, scsi_target(cmd->device),
		       "WARM TARGET RESET ISSUED.\n");

	DEBUG2(ql4_info(ha, "TARGET_DEVICE_RESET cmd=%p jiffies = 0x%lx, "
		      "to=%x,dpc_flags=%lx, status=%x allowed=%d\n",
		      cmd, jiffies, cmd->request->timeout / HZ,
		      ha->dpc_flags, cmd->result, cmd->allowed));

	stat = qla4xxx_reset_target(ha, ddb_entry);
	if (stat != QLA_SUCCESS) {
		starget_printk(KERN_INFO, scsi_target(cmd->device),
			       "WARM TARGET RESET FAILED.\n");
		return FAILED;
	}

	if (qla4xxx_eh_wait_for_commands(ha, scsi_target(cmd->device),
					 NULL)) {
		starget_printk(KERN_INFO, scsi_target(cmd->device),
			       "WARM TARGET DEVICE RESET FAILED - "
			       "waiting for commands.\n");
		return FAILED;
	}

	/* Send marker. */
	if (qla4xxx_send_marker_iocb(ha, ddb_entry, cmd->device->lun,
		MM_TGT_WARM_RESET) != QLA_SUCCESS) {
		starget_printk(KERN_INFO, scsi_target(cmd->device),
			       "WARM TARGET DEVICE RESET FAILED - "
			       "marker iocb failed.\n");
		return FAILED;
	}

	starget_printk(KERN_INFO, scsi_target(cmd->device),
		       "WARM TARGET RESET SUCCEEDED.\n");
	return SUCCESS;
}

/**
 * qla4xxx_eh_host_reset - kernel callback
 * @cmd: Pointer to Linux's SCSI command structure
 *
 * This routine is invoked by the Linux kernel to perform fatal error
 * recovery on the specified adapter.
 **/
static int qla4xxx_eh_host_reset(struct scsi_cmnd *cmd)
{
	int return_status = FAILED;
	struct scsi_qla_host *ha;

	ha = (struct scsi_qla_host *) cmd->device->host->hostdata;

	if (ql4xdontresethba == 1) {
		DEBUG2(ql4_info(ha, "%s: Don't Reset HBA\n", __func__));
		return FAILED;
	}

	ql4_info(ha, "%d:%d:%d: HOST RESET ISSUED.\n",
		   cmd->device->channel, cmd->device->id, cmd->device->lun);

	if (qla4xxx_wait_for_hba_online(ha) != QLA_SUCCESS) {
		DEBUG2(ql4_info(ha, "%d: %s: Unable to reset host.  Adapter "
			      "DEAD.\n", cmd->device->channel, __func__));

		return FAILED;
	}

	if (!test_bit(DPC_RESET_HA, &ha->dpc_flags)) {
		if (is_qla8022(ha))
			set_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
		else
			set_bit(DPC_RESET_HA, &ha->dpc_flags);
	}

	if (qla4xxx_recover_adapter(ha) == QLA_SUCCESS)
		return_status = SUCCESS;

	ql4_info(ha, "HOST RESET %s.\n",
		   return_status == FAILED ? "FAILED" : "SUCCEDED");

	return return_status;
}

/* PCI AER driver recovers from all correctable errors w/o
 * driver intervention. For uncorrectable errors PCI AER
 * driver calls the following device driver's callbacks
 *
 * - Fatal Errors - link_reset
 * - Non-Fatal Errors - driver's pci_error_detected() which
 * returns CAN_RECOVER, NEED_RESET or DISCONNECT.
 *
 * PCI AER driver calls
 * CAN_RECOVER - driver's pci_mmio_enabled(), mmio_enabled
 *               returns RECOVERED or NEED_RESET if fw_hung
 * NEED_RESET - driver's slot_reset()
 * DISCONNECT - device is dead & cannot recover
 * RECOVERED - driver's pci_resume()
 */
static pci_ers_result_t
qla4xxx_pci_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct scsi_qla_host *ha = pci_get_drvdata(pdev);

	ql4_warn(ha, "%s: error detected:state %x\n", __func__, state);

	if (!is_aer_supported(ha))
		return PCI_ERS_RESULT_NONE;

	switch (state) {
	case pci_channel_io_normal:
		clear_bit(AF_EEH_BUSY, &ha->flags);
		return PCI_ERS_RESULT_CAN_RECOVER;
	case pci_channel_io_frozen:
		set_bit(AF_EEH_BUSY, &ha->flags);
		qla4xxx_mailbox_premature_completion(ha);
		qla4xxx_free_irqs(ha);
		pci_disable_device(pdev);
		/* Return back all IOs */
		qla4xxx_abort_active_cmds(ha, DID_RESET << 16);
		return PCI_ERS_RESULT_NEED_RESET;
	case pci_channel_io_perm_failure:
		set_bit(AF_EEH_BUSY, &ha->flags);
		set_bit(AF_PCI_CHANNEL_IO_PERM_FAILURE, &ha->flags);
		qla4xxx_abort_active_cmds(ha, DID_NO_CONNECT << 16);
		return PCI_ERS_RESULT_DISCONNECT;
	}
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * qla4xxx_pci_mmio_enabled() gets called if
 * qla4xxx_pci_error_detected() returns PCI_ERS_RESULT_CAN_RECOVER
 * and read/write to the device still works.
 **/
static pci_ers_result_t
qla4xxx_pci_mmio_enabled(struct pci_dev *pdev)
{
	struct scsi_qla_host *ha = pci_get_drvdata(pdev);

	if (!is_aer_supported(ha))
		return PCI_ERS_RESULT_NONE;

	return PCI_ERS_RESULT_RECOVERED;
}

static uint32_t qla4_8xxx_error_recovery(struct scsi_qla_host *ha)
{
	uint32_t rval = QLA_ERROR;
	uint32_t ret = 0;
	int fn;
	struct pci_dev *other_pdev = NULL;

	ql4_warn(ha, "In %s\n", __func__);

	set_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);

	if (test_bit(AF_ONLINE, &ha->flags)) {
		clear_bit(AF_ONLINE, &ha->flags);
		qla4xxx_mark_all_devices_missing(ha);
		qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
	}

	fn = PCI_FUNC(ha->pdev->devfn);
	while (fn > 0) {
		fn--;
		ql4_info(ha, "%s: Finding PCI device at func %x\n",
			 __func__, fn);
		/* Get the pci device given the domain, bus,
		 * slot/function number */
		other_pdev =
		    pci_get_domain_bus_and_slot(pci_domain_nr(ha->pdev->bus),
		    ha->pdev->bus->number, PCI_DEVFN(PCI_SLOT(ha->pdev->devfn),
		    fn));

		if (!other_pdev)
			continue;

		if (atomic_read(&other_pdev->enable_cnt)) {
			ql4_info(ha, "%s: Found PCI func in enabled state%x\n",
			    __func__, fn);
			pci_dev_put(other_pdev);
			break;
		}
		pci_dev_put(other_pdev);
	}

	/* The first function on the card, the reset owner will
	 * start & initialize the firmware. The other functions
	 * on the card will reset the firmware context
	 */
	if (!fn) {
		ql4_info(ha, "%s: devfn being reset 0x%x is the owner\n",
			__func__, ha->pdev->devfn);

		qla4_8xxx_idc_lock(ha);
		qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
		    QLA82XX_DEV_COLD);

		qla4_8xxx_wr_32(ha, QLA82XX_CRB_DRV_IDC_VERSION,
		    QLA82XX_IDC_VERSION);

		qla4_8xxx_idc_unlock(ha);
		clear_bit(AF_FW_RECOVERY, &ha->flags);
		rval = qla4xxx_initialize_adapter(ha, PRESERVE_DDB_LIST);
		qla4_8xxx_idc_lock(ha);

		if (rval != QLA_SUCCESS) {
			ql4_info(ha, "%s: HW State: FAILED\n", __func__);
			qla4_8xxx_clear_drv_active(ha);
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
			    QLA82XX_DEV_FAILED);
		} else {
			ql4_info(ha, "%s: HW State: READY\n", __func__);
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DEV_STATE,
			    QLA82XX_DEV_READY);
			/* Clear driver state register */
			qla4_8xxx_wr_32(ha, QLA82XX_CRB_DRV_STATE, 0);
			qla4_8xxx_set_drv_active(ha);
			ret = qla4xxx_request_irqs(ha);
			if (ret) {
				ql4_warn(ha, "Failed to reserve interrupt %d "
					"already in use.\n", ha->pdev->irq);
				rval = QLA_ERROR;
			} else {
				ha->isp_ops->enable_intrs(ha);
				rval = QLA_SUCCESS;
			}
		}
		qla4_8xxx_idc_unlock(ha);
	} else {
		ql4_info(ha, "%s: devfn 0x%x is not the reset owner\n",
				__func__, ha->pdev->devfn);
		if ((qla4_8xxx_rd_32(ha, QLA82XX_CRB_DEV_STATE) ==
		    QLA82XX_DEV_READY)) {
			clear_bit(AF_FW_RECOVERY, &ha->flags);
			rval = qla4xxx_initialize_adapter(ha,
			    PRESERVE_DDB_LIST);
			if (rval == QLA_SUCCESS) {
				ret = qla4xxx_request_irqs(ha);
				if (ret) {
					ql4_warn(ha, "Failed to"
					    " reserve interrupt %d already in"
					    " use.\n", ha->pdev->irq);
					rval = QLA_ERROR;
				} else {
					ha->isp_ops->enable_intrs(ha);
					rval = QLA_SUCCESS;
				}
			}
			qla4_8xxx_idc_lock(ha);
			qla4_8xxx_set_drv_active(ha);
			qla4_8xxx_idc_unlock(ha);
		}
	}
	clear_bit(DPC_RESET_ACTIVE, &ha->dpc_flags);
	return rval;
}

static pci_ers_result_t
qla4xxx_pci_slot_reset(struct pci_dev *pdev)
{
	pci_ers_result_t ret = PCI_ERS_RESULT_DISCONNECT;
	struct scsi_qla_host *ha = pci_get_drvdata(pdev);
	int rc;

	ql4_warn(ha, "%s: slot_reset\n", __func__);

	if (!is_aer_supported(ha))
		return PCI_ERS_RESULT_NONE;

	/* Restore the saved state of PCIe device -
	 * BAR registers, PCI Config space, PCIX, MSI,
	 * IOV states
	 */
	pci_restore_state(pdev);

	/* pci_restore_state() clears the saved_state flag of the device
	 * save restored state which resets saved_state flag
	 */
	pci_save_state(pdev);

	/* Initialize device or resume if in suspended state */
	rc = pci_enable_device(pdev);
	if (rc) {
		ql4_warn(ha, "%s: Cant re-enable device after reset\n",
				 __func__);
		goto exit_slot_reset;
	}

	ha->isp_ops->disable_intrs(ha);

	if (is_qla8022(ha)) {
		if (qla4_8xxx_error_recovery(ha) == QLA_SUCCESS) {
			ret = PCI_ERS_RESULT_RECOVERED;
			goto exit_slot_reset;
		} else
			goto exit_slot_reset;
	}

exit_slot_reset:
	ql4_warn(ha, "%s: Return=%x\n device after reset\n", __func__, ret);
	return ret;
}

static void
qla4xxx_pci_resume(struct pci_dev *pdev)
{
	struct scsi_qla_host *ha = pci_get_drvdata(pdev);
	int ret;

	printk("%s: pci_resume\n", __func__);

	ret = qla4xxx_wait_for_hba_online(ha);
	if (ret != QLA_SUCCESS) {
		printk("%s: the device failed to resume I/O from "
			"slot/link_reset\n", __func__);
	}

	pci_cleanup_aer_uncorrect_error_status(pdev);
	clear_bit(AF_EEH_BUSY, &ha->flags);
}

static struct pci_error_handlers qla4xxx_err_handler = {
	.error_detected = qla4xxx_pci_error_detected,
	.mmio_enabled = qla4xxx_pci_mmio_enabled,
	.slot_reset = qla4xxx_pci_slot_reset,
	.resume = qla4xxx_pci_resume,
};

static struct pci_device_id qla4xxx_pci_tbl[] = {
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP4010,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
	},
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP4022,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
	},
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP4032,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
	},
	{
		.vendor         = PCI_VENDOR_ID_QLOGIC,
		.device         = PCI_DEVICE_ID_QLOGIC_ISP8022,
		.subvendor      = PCI_ANY_ID,
		.subdevice      = PCI_ANY_ID,
	},
	{0, 0},
};
MODULE_DEVICE_TABLE(pci, qla4xxx_pci_tbl);

static struct pci_driver qla4xxx_pci_driver = {
	.name		= DRIVER_NAME,
	.id_table	= qla4xxx_pci_tbl,
	.probe		= qla4xxx_probe_adapter,
	.remove		= qla4xxx_remove_adapter,
	.err_handler = &qla4xxx_err_handler,
};

static int __init qla4xxx_module_init(void)
{
	int ret;

	atomic_set(&qla4xxx_hba_count, 0);
	klist_init(&qla4xxx_hostlist, NULL, NULL);
	/* Allocate cache for SRBs. */
	srb_cachep = kmem_cache_create("qla4xxx_srbs", sizeof(struct srb), 0,
				       SLAB_HWCACHE_ALIGN, NULL);
	if (srb_cachep == NULL) {
		printk("%s: Unable to allocate SRB cache..."
		       "Failing load!\n", DRIVER_NAME);
		ret = -ENOMEM;
		goto no_srp_cache;
	}

	/* Derive version string. */
	strcpy(qla4xxx_version_str, QLA4XXX_DRIVER_VERSION);
	if (ql4xextended_error_logging)
		strcat(qla4xxx_version_str, "-debug");

	qla4xxx_scsi_transport =
		iscsi_register_transport(&qla4xxx_iscsi_transport);
	if (!qla4xxx_scsi_transport){
		ret = -ENODEV;
		goto release_srb_cache;
	}

	ret = pci_register_driver(&qla4xxx_pci_driver);
	if (ret)
		goto unregister_transport;

	printk("QLogic iSCSI HBA Driver\n");
	return 0;

unregister_transport:
	iscsi_unregister_transport(&qla4xxx_iscsi_transport);
release_srb_cache:
	kmem_cache_destroy(srb_cachep);
no_srp_cache:
	return ret;
}

static void __exit qla4xxx_module_exit(void)
{
	pci_unregister_driver(&qla4xxx_pci_driver);
	iscsi_unregister_transport(&qla4xxx_iscsi_transport);
	kmem_cache_destroy(srb_cachep);
}

module_init(qla4xxx_module_init);
module_exit(qla4xxx_module_exit);

MODULE_AUTHOR("QLogic Corporation");
MODULE_DESCRIPTION("QLogic iSCSI HBA Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(QLA4XXX_DRIVER_VERSION);
