/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */
#include <linux/ctype.h>

#include "ql4_def.h"
#include "ql4_glbl.h"
#include "ql4_dbg.h"
#include "ql4_inline.h"

/********************     iSNS Helper Functions    ***********************/

/**
 * ql4_prn_str - retrieve associated print string
 * @val: Value of string
 * @tbl: Table of strings
 * @return: String corresponding to value in specified table
 *
 * Iterate through specified table searching for @val.  If found,
 * returns associated string.  Otherwise, return default "UNKNOWN" string.
 * Last element in table MUST be {-1, "UNKNOWN"}.
 **/

#if defined(QL_DEBUG_LEVEL_6)
static const char * ql4_prn_str(int val, struct prn_str_tbl *tbl)
{
	for (; tbl->val != (-1); tbl++)
		if (tbl->val == val)
			break;

	return tbl->s;
}
#endif

struct prn_str_tbl isns_attr_str [] = {
	{ISNS_ATTR_DELIMITER             , "ISNS_ATTR_DELIMITER"},
	{ISNS_ATTR_ENTITY_IDENTIFIER     , "ISNS_ATTR_ENTITY_IDENTIFIER"},
	{ISNS_ATTR_ENTITY_PROTOCOL       , "ISNS_ATTR_ENTITY_PROTOCOL"},
	{ISNS_ATTR_MGMT_IP_ADDRESS       , "ISNS_ATTR_MGMT_IP_ADDRESS"},
	{ISNS_ATTR_TIMESTAMP             , "ISNS_ATTR_TIMESTAMP"},
	{ISNS_ATTR_REGISTRATION_PERIOD   , "ISNS_ATTR_REGISTRATION_PERIOD"},
	{ISNS_ATTR_PORTAL_IP_ADDRESS     , "ISNS_ATTR_PORTAL_IP_ADDRESS"},
	{ISNS_ATTR_PORTAL_PORT           , "ISNS_ATTR_PORTAL_PORT"},
	{ISNS_ATTR_PORTAL_SYMBOLIC_NAME  , "ISNS_ATTR_PORTAL_SYMBOLIC_NAME"},
	{ISNS_ATTR_ESI_INTERVAL          , "ISNS_ATTR_ESI_INTERVAL"},
	{ISNS_ATTR_ESI_PORT              , "ISNS_ATTR_ESI_PORT"},
	{ISNS_ATTR_PORTAL_GROUP          , "ISNS_ATTR_PORTAL_GROUP"},
	{ISNS_ATTR_PORTAL_INDEX          , "ISNS_ATTR_PORTAL_INDEX"},
	{ISNS_ATTR_SCN_PORT              , "ISNS_ATTR_SCN_PORT"},
	{ISNS_ATTR_PORTAL_SECURITY_BITMAP, "ISNS_ATTR_PORTAL_SECURITY_BITMAP"},
	{ISNS_ATTR_ISCSI_NAME            , "ISNS_ATTR_ISCSI_NAME"},
	{ISNS_ATTR_ISCSI_NODE_TYPE       , "ISNS_ATTR_ISCSI_NODE_TYPE"},
	{ISNS_ATTR_ISCSI_ALIAS           , "ISNS_ATTR_ISCSI_ALIAS"},
	{ISNS_ATTR_ISCSI_SCN_BITMAP      , "ISNS_ATTR_ISCSI_SCN_BITMAP"},
	{ISNS_ATTR_PG_ISCSI_NAME         , "ISNS_ATTR_PG_ISCSI_NAME"},
	{ISNS_ATTR_PG_PORTAL_IP_ADDRESS  , "ISNS_ATTR_PG_PORTAL_IP_ADDRESS"},
	{ISNS_ATTR_PG_PORTAL_PORT        , "ISNS_ATTR_PG_PORTAL_PORT"},
	{ISNS_ATTR_PG_TAG                , "ISNS_ATTR_PG_TAG"},
	{ISNS_ATTR_DD_ID                 , "ISNS_ATTR_DD_ID"},
	{-1, "UNKNOWN"}
};

struct prn_str_tbl isns_func_str [] = {
	{ISNS_FUNC_DevAttrReg   , "ISNS_FUNC_DevAttrReg"},
	{ISNS_FUNC_DevAttrQry   , "ISNS_FUNC_DevAttrQry"},
	{ISNS_FUNC_DevGetNext   , "ISNS_FUNC_DevGetNext"},
	{ISNS_FUNC_DevDereg     , "ISNS_FUNC_DevDereg"},
	{ISNS_FUNC_SCNReg       , "ISNS_FUNC_SCNReg"},
	{ISNS_FUNC_SCNDereg     , "ISNS_FUNC_SCNDereg"},
	{ISNS_FUNC_SCNEvent     , "ISNS_FUNC_SCNEvent"},
	{ISNS_FUNC_SCN          , "ISNS_FUNC_SCN"},
	{ISNS_FUNC_ESI          , "ISNS_FUNC_ESI"},
	{ISNS_FUNC_DevAttrRegRsp, "ISNS_FUNC_DevAttrRegRsp"},
	{ISNS_FUNC_DevAttrQryRsp, "ISNS_FUNC_DevAttrQryRsp"},
	{ISNS_FUNC_DevGetNextRsp, "ISNS_FUNC_DevGetNextRsp"},
	{ISNS_FUNC_DevDeregRsp  , "ISNS_FUNC_DevDeregRsp"},
	{ISNS_FUNC_SCNRegRsp    , "ISNS_FUNC_SCNRegRsp"},
	{ISNS_FUNC_SCNDeregRsp  , "ISNS_FUNC_SCNDeregRsp"},
	{ISNS_FUNC_SCNEventRsp  , "ISNS_FUNC_SCNEventRsp"},
	{ISNS_FUNC_SCNRsp       , "ISNS_FUNC_SCNRsp"},
	{ISNS_FUNC_DDRegRsp     , "ISNS_FUNC_DDRegRsp"},
	{ISNS_FUNC_DDDeregRsp   , "ISNS_FUNC_DDDeregRsp"},
	{ISNS_FUNC_DDSRegRsp    , "ISNS_FUNC_DDSRegRsp"},
	{ISNS_FUNC_DDSDeregRsp  , "ISNS_FUNC_DDSDeregRsp"},
	{ISNS_FUNC_ESIRsp       , "ISNS_FUNC_ESIRsp"},
	{-1, "UNKNOWN"}
};

struct prn_str_tbl isns_sts_str [] = {
	{ISNS_STS_SUCCESS                   , "ISNS_STS_SUCCESS"},
	{ISNS_STS_UNKNOWN                   , "ISNS_STS_UNKNOWN"},
	{ISNS_STS_MSG_FORMAT                , "ISNS_STS_MSG_FORMAT "},
	{ISNS_STS_INVALID_REG               , "ISNS_STS_INVALID_REG"},
	{ISNS_STS_INVALID_QUERY             , "ISNS_STS_INVALID_QUERY "},
	{ISNS_STS_SOURCE_UNKNOWN            , "ISNS_STS_SOURCE_UNKNOWN"},
	{ISNS_STS_SOURCE_ABSENT             , "ISNS_STS_SOURCE_ABSENT"},
	{ISNS_STS_SOURCE_UNAUTHORIZED       , "ISNS_STS_SOURCE_UNAUTHORIZED"},
	{ISNS_STS_NO_SUCH_ENTRY             , "ISNS_STS_NO_SUCH_ENTRY"},
	{ISNS_STS_VER_NOT_SUPPORTED         , "ISNS_STS_VER_NOT_SUPPORTED"},
	{ISNS_STS_INTERNAL_ERROR            , "ISNS_STS_INTERNAL_ERROR"},
	{ISNS_STS_BUSY                      , "ISNS_STS_BUSY"},
	{ISNS_STS_OPT_NOT_UNDERSTOOD        , "ISNS_STS_OPT_NOT_UNDERSTOOD"},
	{ISNS_STS_INVALID_UPDATE            , "ISNS_STS_INVALID_UPDATE"},
	{ISNS_STS_MSG_NOT_SUPPORTED         , "ISNS_STS_MSG_NOT_SUPPORTED"},
	{ISNS_STS_SCN_EVENT_REJECTED        , "ISNS_STS_SCN_EVENT_REJECTED"},
	{ISNS_STS_SCN_REG_REJECTED          , "ISNS_STS_SCN_REG_REJECTED"},
	{ISNS_STS_ATTR_NOT_IMPLEMENTED      , "ISNS_STS_ATTR_NOT_IMPLEMENTED"},
	{ISNS_STS_FC_DOMAIN_ID_NOT_AVAIL    , "ISNS_STS_FC_DOMAIN_ID_NOT_AVAIL"},
	{ISNS_STS_FC_DOMAIN_ID_NOT_ALLOC    , "ISNS_STS_FC_DOMAIN_ID_NOT_ALLOC"},
	{ISNS_STS_ESI_NOT_AVAILABLE         , "ISNS_STS_ESI_NOT_AVAILABLE"},
	{ISNS_STS_INVALID_DEREG             , "ISNS_STS_INVALID_DEREG"},
	{ISNS_STS_REG_FEATURES_NOT_SUPPORTED, "ISNS_STS_REG_FEATURES_NOT_SUPPORTED"},
	{-1, "UNKNOWN"}
};

struct prn_str_tbl iscsi_node_type_str [] = {
	{ISCSI_NODE_TYPE_TARGET,    "ISCSI_NODE_TYPE_TARGET"},
	{ISCSI_NODE_TYPE_INITIATOR, "ISCSI_NODE_TYPE_INITIATOR"},
	{ISCSI_NODE_TYPE_CONTROL,   "ISCSI_NODE_TYPE_CONTROL"},
	{-1, "UNKNOWN"}
};

struct prn_str_tbl iscsi_scn_str [] = {
	{ISCSI_SCN_OBJECT_UPDATED           ,    "ISCSI_SCN_OBJECT_UPDATED"},
	{ISCSI_SCN_OBJECT_ADDED             ,    "ISCSI_SCN_OBJECT_ADDED"},
	{ISCSI_SCN_OBJECT_REMOVED           ,    "ISCSI_SCN_OBJECT_REMOVED"},
	{ISCSI_SCN_TARGET_AND_SELF_INFO_ONLY,    "ISCSI_SCN_TARGET_AND_SELF_INFO_ONLY"},
	{-1, "UNKNOWN"}
};

/**
 * ql4_isns_get_prb - Allocate a PDU
 * @ha: Pointer to Host Adapter structure
 * @pdu_size: Size of PDU requested. Will be rounded up to the nearest page.
 **/
static struct isns_prb *ql4_isns_get_prb(struct scsi_qla_host *ha,
					__u32 pdu_size)
{
	struct isns_prb *prb = NULL;
	__u8 index = ha->isns.curr_pdu;

	mutex_lock(&ha->isns.prb_lock);

	if (ha->isns.active_pdus == MAX_PDU_ENTRIES) {
		DEBUG2(ql4_info(ha, "%s: Out of PDUs!\n", __func__));
		mutex_unlock(&ha->isns.prb_lock);
		return NULL;
	}

	/* Find next available prb index */
	do {
		index++;
		if (index == MAX_PDU_ENTRIES)
			index = 0;
		if (index == ha->isns.curr_pdu) {
			mutex_unlock(&ha->isns.prb_lock);
			return NULL;
		}
	} while (ha->isns.prb_array[index].prb_in_use == 1);

	/* Allocate PDU. All PDU sizes are rounded up to the nearest page
	 * and are aligned on a page boundary
	 */
	prb = &ha->isns.prb_array[index];
	pdu_size = (pdu_size + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);
	prb->pdu = dma_alloc_coherent(&ha->pdev->dev, pdu_size, &prb->pdu_dma,
					GFP_KERNEL);
	if (!prb->pdu) {
		DEBUG2(ql4_info(ha, "%s: Unable to allocate memory for PDU!\n",
				__func__));
		mutex_unlock(&ha->isns.prb_lock);
		return NULL;
	}

	mutex_unlock(&ha->isns.prb_lock);

	/* Allocate an IOCB */
	prb->pkt = dma_pool_alloc(ha->pt_iocb_dmapool, GFP_KERNEL,
					&prb->pkt_dma);
	if (!prb->pkt) {
		DEBUG6(ql4_info(ha,"%s: Unable to alloc memory for Passthru "
					"IOCB\n", __func__));
		dma_free_coherent(&ha->pdev->dev, prb->pdu_buf_len, prb->pdu,
					prb->pdu_dma);
		return NULL;
	}

	prb->pdu_buf_len = pdu_size;
	prb->prb_in_use = 1;
	ha->isns.curr_pdu = index;
	ha->isns.active_pdus++;

	DEBUG7(ql4_info(ha, "%s: prb=%p pdu=%p index=%d pkt=%p pkt_dma=%llx\n",
	      __func__, prb, prb->pdu, index, prb->pkt,
		(unsigned long long)prb->pkt_dma));

	return prb;
}

static void ql4_isns_free_prb(struct scsi_qla_host *ha, struct isns_prb *prb)
{
	DEBUG7(ql4_info(ha, "%s: prb=%p, pdu=%p, pkt=%p, pkt_dma=%llx \n",
	      __func__, prb, prb->pdu, prb->pkt,
	      (unsigned long long)prb->pkt_dma));

	mutex_lock(&ha->isns.prb_lock);
	dma_pool_free(ha->pt_iocb_dmapool, prb->pkt, prb->pkt_dma);
	dma_free_coherent(&ha->pdev->dev, prb->pdu_buf_len, prb->pdu,
			  prb->pdu_dma);
	memset(prb, 0, sizeof(*prb));
	ha->isns.active_pdus--;
	mutex_unlock(&ha->isns.prb_lock);
}

/* Notify application that the specified iSNS Status Change occurred */
void ql4_queue_isns_sts_chg_aen(struct scsi_qla_host *ha,
					uint32_t chg_type)
{
	uint32_t mbox_sts[MBOX_REG_COUNT];
	memset(mbox_sts, 0, sizeof(mbox_sts));
	mbox_sts[0] = MBOX_DRVR_ASTS_ISNS_STATUS_CHANGE;
	mbox_sts[1] = chg_type;
	qla4xxx_queue_aen_log(ha, &mbox_sts[0]);

	DEBUG2(ql4_info(ha, "%s: AEN 0x7002\n", __func__));
}

static __u32 ql4_isns_build_iocb_handle(struct scsi_qla_host *ha,
				__u32 type, struct isns_prb *prb)
{
	__u32 index = ((__u8 *)prb - (__u8 *)ha->isns.prb_array) /
                sizeof(struct isns_prb);

	return IOCB_ISNS_PT_PDU_TYPE(type) | index;
}

static void ql4_isns_build_entity_id(struct scsi_qla_host *ha)
{
	__u8 *s;

	snprintf(ha->isns.entity_id, sizeof(ha->isns.entity_id),
		"%02x:%02x:%02x:%02x:%02x:%02x", ha->my_mac[0], ha->my_mac[1],
		ha->my_mac[2], ha->my_mac[3], ha->my_mac[4], ha->my_mac[5]);

	for (s = ha->isns.entity_id; *s; s++)
		*s = tolower(*s);
	DEBUG6(ql4_info(ha, "Entity ID %s\n", ha->isns.entity_id));
}

/**
 * ql4_isns_create_header - Populates iSNSP Header in Network Byte Order
 * @ha: Pointer to Host Adapter structure
 * @hdr: Pointer to iSNSP Header structure
 * @func_id: iSNSP Function ID
 **/
static void ql4_isns_create_header(struct scsi_qla_host *ha,
			    struct isnsp_header *hdr, __u16 func_id)
{
	hdr->ver      = htons(ISNSP_VERSION);
	hdr->func_id  = htons(func_id);
	hdr->trans_id = htons(++ha->isns.trans_id);
	hdr->seq_id   = 0;
	hdr->flags    = htons(ISNSP_FLAG_CLIENT_SENDER |
                             ISNSP_FLAG_FIRST_PDU |
                             ISNSP_FLAG_LAST_PDU);

	if (func_id == ISNS_FUNC_DevAttrReg)
		hdr->flags |= htons(ISNSP_FLAG_REPLACE_FLAG);
}

/**
 * ql4_isns_append_attr - Append integer attribute to pdu message
 * @ha: Pointer to Host Adapter structure
 * @ptr: Pointer to attribute in pdu message buffer.
 *       Returns pointer to next attribute.
 * @tag: Attribute tag
 * @len: Attribute length
 * @val: Pointer to Attribute Value
 * Remarks: Integers are either 0 or 4 bytes in length.
 * Delimiters have 0 size lengths, all others have a length of 4.
 **/
static void ql4_isns_append_attr(struct scsi_qla_host *ha,
				 __u8 **ptr, __u16 tag, __u16 len, __u32 val)
{
	struct isnsp_attribute *attr = (struct isnsp_attribute *) *ptr;

	attr->tag = htonl(tag);
	attr->len = htonl(len);
	*(__u32 *) attr->val = htonl(val);

	*ptr += sizeof(struct isnsp_attribute) + len;
}

/**
 * ql4_isns_append_attr_ip - Append IP address attribute to pdu message
 * @ha: Pointer to Host Adapter structure
 * @ptr: Pointer to attribute in pdu message buffer.
 *       Returns pointer to next attribute.
 * @tag: Attribute tag
 * @val: Pointer to Attribute Value
 *
 * Remarks: All IP addresses are fixed 16 bytes in length.
 * IPv4 addresses are stored as IPv4-mapped IPv6 address,
 * where the most significant bytes are 0x00,
 * bytes 10 and 11 are 0xFF, and bytes 12-15 contain the IP address
 **/
static void ql4_isns_append_attr_ip(struct scsi_qla_host *ha,
				     __u8 **ptr, __u16 tag, __u8 *val)
{
	struct isnsp_attribute *attr = (struct isnsp_attribute *) *ptr;
	__u16 len = 16;

	attr->tag = htonl(tag);
	attr->len = htonl(len);

	memcpy(attr->val, val, len);
	*ptr += sizeof(struct isnsp_attribute) + len;
}

/**
 * ql4_isns_append_attr_str - Append string attribute to pdu message
 * @ha: Pointer to Host Adapter structure
 * @ptr: Pointer to attribute in pdu message buffer.
 *       Returns pointer to next attribute.
 * @tag: Attribute tag
 * @val: Pointer to Attribute Value
 *
 * Remarks: Strings must be UTF-8 encoded NULL-terminated on a 4-byte boundary.
 * Strings must have a minimum length of 4, with the exception of iscsi_name
 * specified in the message key attribute used to retrieve the first object
 * with dev_get_next, * where the length must be 0.
 * For that case we pass in val ptr of NULL
 **/
static void ql4_isns_append_attr_str(struct scsi_qla_host *ha,
				     __u8 **ptr, __u16 tag, __u8 *val)
{
	struct isnsp_attribute *attr = (struct isnsp_attribute *) *ptr;
	__u16 raw_len = 0;
	__u16 len = 0;

	if (val) {
		strcpy(attr->val, val);

		raw_len = strlen(val);
		raw_len++; /* Pad for NULL termination */
		len = ALIGN(raw_len, 4);

		/* Cleanup padded bytes */
		memset(attr->val + raw_len, 0, len - raw_len);
	}

	attr->tag = htonl(tag);
	attr->len = htonl(len);

	*ptr += sizeof(struct isnsp_attribute) + len;
}

void ql4_isns_clear_flags(struct scsi_qla_host *ha)
{
	clear_bit(ISNS_FLAG_DISABLE_IN_PROGRESS, &ha->isns.flags);
	clear_bit(ISNS_FLAG_ISNS_SRV_REGISTERED, &ha->isns.flags);
	clear_bit(ISNS_FLAG_ISNS_SCN_REGISTERED, &ha->isns.flags);
	clear_bit(ISNS_FLAG_SRV_DEREG_IN_PROGRESS, &ha->isns.flags);
	atomic_set(&ha->isns.state, ISNS_STATE_TCP_DISCONNECTED);
}

void ql4_isns_restart_timer(struct scsi_qla_host *ha, __u32 time)
{
	ql4_isns_clear_flags(ha);

	/* Set timer for restart to complete */
	atomic_set(&ha->isns.state, ISNS_STATE_RESTART_SRV_WAIT);
	atomic_set(&ha->isns.restart_timer, time);
	DEBUG2(ql4_info(ha,
		"%s: (re)attempt iSNS Server connection in (%d) seconds\n",
		__func__, time));
}

void ql4_isns_restart_service(struct scsi_qla_host *ha)
{
	ql4_isns_stop_service(ha);
	ql4_isns_restart_timer(ha, ISNS_RESTART_SVR_TOV);
}

/**
 * ql4_isns_send_passthru_iocb - Prepare and Send Passthru0 IOCB
 *
 * @ha: Pointer to Host Adapter structure
 * @prb: Pointer to PDU Request Block structure
 **/
static __u8 ql4_isns_send_passthru_iocb(struct scsi_qla_host *ha,
                                       struct isns_prb *prb)
{
	struct passthru0 *pkt;
	struct isnsp_header *hdr;
	__u16 ctrl_flags = PT_FLAG_ETHERNET_FRAME;
	__u32 pdu_type = IOCB_ISNS_PT_PDU_TYPE(prb->handle);
	__u32 wait_count;
	__u8 status = QLA_ERROR;

	if (prb->tx_len == 0 && prb->rx_len == 0) {
		DEBUG6(ql4_info(ha,"%s: IOCB not sent.  "
			"Non-zero xfer length required\n", __func__));
		return status;
	}

	/* Passthru code active */
	wait_count = MBOX_TOV * 100;
	while (wait_count--) {
		mutex_lock(&ha->pt_sem);
		if (!test_bit(AF_PT_ACTIVE, &ha->flags)) {
			set_bit(AF_PT_ACTIVE, &ha->flags);
			mutex_unlock(&ha->pt_sem);
			break;
		}
		mutex_unlock(&ha->pt_sem);
		if (!wait_count) {
			DEBUG2(ql4_info(ha, "%s: pt_sem failed\n", __func__));
			return status;
		}
		msleep(10);
	}

	pkt = (struct passthru0 *) prb->pkt;
	memset(pkt, 0, sizeof(struct passthru0));
	pkt->hdr.entry_type = ET_PASSTHRU0;
	pkt->hdr.entry_count = 1;
	pkt->handle  = cpu_to_le32(prb->handle);
	pkt->conn_id = cpu_to_le16(prb->conn_id);
	pkt->target  = __constant_cpu_to_le16(ISNS_DEVICE_INDEX);
	pkt->timeout = __constant_cpu_to_le16(PT_DEFAULT_TIMEOUT);

	if (prb->tx_len) {
		ctrl_flags |= PT_FLAG_SEND_BUFFER;
		pkt->out_data_seg64.base.addr_hi =
			cpu_to_le32(MSDW(prb->pdu_dma));
		pkt->out_data_seg64.base.addr_lo =
			cpu_to_le32(LSDW(prb->pdu_dma));
		pkt->out_data_seg64.count =
			cpu_to_le32(prb->tx_len);
	}

	if (prb->rx_len) {
		pkt->in_data_seg64.base.addr_hi =
			cpu_to_le32(MSDW(prb->pdu_dma + prb->offset));
		pkt->in_data_seg64.base.addr_lo =
			cpu_to_le32(LSDW(prb->pdu_dma + prb->offset));
		pkt->in_data_seg64.count =
			cpu_to_le32(prb->rx_len);
	}

	if (pdu_type != ISNS_ASYNC_RSP_PDU)
		ctrl_flags |= PT_FLAG_WAIT_4_RESPONSE;

	pkt->ctrl_flags = cpu_to_le16(ctrl_flags);
	wmb();

	hdr = (struct isnsp_header *) prb->pdu;
	DEBUG6(ql4_info(ha,"------------------------\n"));
	if (pdu_type == ISNS_ASYNC_REQ_PDU) {
		DEBUG6(ql4_info(ha,"Requesting iSNS ASYNC PDU  handle=0x%x, "
			"cid=0x%x, rx_len=0x%x\n",
			prb->handle, prb->conn_id, prb->rx_len));
	} else {
		DEBUG6(ql4_info(ha,"Sending tid=0x%x %s   0x%x ->   "
			"(Display MAX 0x100)\n",
			ntohs(hdr->trans_id),
			ql4_prn_str(ntohs(hdr->func_id), &isns_func_str[0]),
			prb->tx_len));
	}
	DEBUG6(qla4xxx_dump_bytes(prb->pdu, min((__u16)prb->tx_len,
					(__u16)0x100)));
	DEBUG7(__dump_prb(ha,prb));
	DEBUG7(ql4_info(ha,"dump passthru iocb %p\n", pkt));
	DEBUG7(qla4xxx_dump_bytes(pkt, sizeof(*pkt)));

	if (qla4xxx_issue_iocb(ha, 0, prb->pkt_dma) == QLA_SUCCESS) {
		__u32 pdu_type = IOCB_ISNS_PT_PDU_TYPE(prb->handle);

		status = QLA_SUCCESS;

		if (pdu_type == ISNS_REQ_RSP_PDU ||
			pdu_type == ISNS_ASYNC_REQ_PDU)
			ql4_isns_queue_passthru_sts_iocb(ha, prb);
		else if (pdu_type == ISNS_ASYNC_RSP_PDU)
			ql4_isns_free_prb(ha, prb);
		else {
			ql4_info(ha, "%s: Error: Invalid pdu_type returned "
				"(0x%x)! Restart iSNS Service\n",
				__func__, pdu_type);
			set_bit(DPC_ISNS_REREGISTER, &ha->dpc_flags);
			DEBUG2(ql4_info(ha, "%s: Re-Register with iSNS "
					"server\n", __func__));
		}
	} else
		DEBUG6(ql4_info(ha,"%s: qla4xxx_issue_iocb failed\n",
				__func__));

	mutex_lock(&ha->pt_sem);
	clear_bit(AF_PT_ACTIVE, &ha->flags);
	mutex_unlock(&ha->pt_sem);
	return status;
}


/********************    iSNS Send PDU Functions   ****************/

/**
 * ql4_isns_send_async_msg_rsp - Send response to ESI and SCN async messages
 **/
static void ql4_isns_send_async_msg_rsp(struct scsi_qla_host *ha,
                                        struct isns_prb *msg_prb)
{
	struct isnsp_message *msg;
	struct isnsp_response *rsp;
	struct isns_prb *rsp_prb;
	__u16 msg_pdu_len;

	rsp_prb = ql4_isns_get_prb(ha, PAGE_SIZE);
	if (!rsp_prb) {
		return;
	}

	msg = (struct isnsp_message *) msg_prb->pdu;
	rsp = (struct isnsp_response *) rsp_prb->pdu;

	msg_pdu_len = ntohs(msg->hdr.pdu_len);

	rsp->hdr.ver      = htons(ISNSP_VERSION);
	rsp->hdr.func_id  = msg->hdr.func_id | htons(ISNS_FUNC_RESPONSE);
	rsp->hdr.trans_id = msg->hdr.trans_id;
	rsp->hdr.seq_id   = 0;
	rsp->hdr.flags    = htons(ISNSP_FLAG_CLIENT_SENDER |
                                  ISNSP_FLAG_FIRST_PDU |
                                  ISNSP_FLAG_LAST_PDU);
	rsp->hdr.pdu_len = htons(msg_pdu_len + sizeof(rsp->status_code));
	rsp->status_code = htonl(ISNS_STS_SUCCESS);
	memcpy(&rsp->attributes[0], &msg->attributes[0], msg_pdu_len);

	rsp_prb->conn_id = msg_prb->conn_id;
	rsp_prb->handle  = ql4_isns_build_iocb_handle(ha, ISNS_ASYNC_RSP_PDU,
                                                      rsp_prb);
	rsp_prb->tx_len  = sizeof(struct isnsp_response) + msg_pdu_len;
	rsp_prb->rx_len  = 0;

	if (ql4_isns_send_passthru_iocb(ha, rsp_prb) != QLA_SUCCESS)
		ql4_isns_free_prb(ha, rsp_prb);
}

static void ql4_isns_send_scn_reg(struct scsi_qla_host *ha)
{
	struct isns_prb *prb;
	struct isnsp_message *pdu;
	__u8 *ptr;

	prb = ql4_isns_get_prb(ha, PAGE_SIZE);
	if (!prb) {
		return;
	}

	pdu = (struct isnsp_message *) prb->pdu;
	ptr = (__u8 *) &pdu->attributes[0];

	ql4_isns_create_header(ha, &pdu->hdr, ISNS_FUNC_SCNReg);
	/* Source Attribute */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);
	/* Key Attributes */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);
	/* Delimiter to indicate division between Key & Operating attributes */
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_DELIMITER, 0, 0);
	/* Operating Attributes */
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ISCSI_SCN_BITMAP, 4,
		ISCSI_SCN_OBJECT_UPDATED |
		ISCSI_SCN_OBJECT_ADDED |
		ISCSI_SCN_OBJECT_REMOVED |
		ISCSI_SCN_TARGET_AND_SELF_INFO_ONLY);

	prb->conn_id = ISNS_DEFAULT_SERVER_CONN_ID;
	prb->handle  = ql4_isns_build_iocb_handle(ha, ISNS_REQ_RSP_PDU, prb);
	prb->tx_len  = (__u16)(ptr - &prb->pdu[0]);
	prb->rx_len  = prb->pdu_buf_len;
	pdu->hdr.pdu_len = htons(prb->tx_len - sizeof(struct isnsp_header));

	if (ql4_isns_send_passthru_iocb(ha, prb) != QLA_SUCCESS)
		ql4_isns_free_prb(ha, prb);
}

void ql4_isns_send_scn_dereg(struct scsi_qla_host *ha)
{
	struct isns_prb *prb;
	struct isnsp_message *pdu;
	__u8 *ptr;

	prb = ql4_isns_get_prb(ha, PAGE_SIZE);
	if (!prb) {
		return;
	}

	pdu = (struct isnsp_message *) prb->pdu;
	ptr = (__u8 *) &pdu->attributes[0];

	ql4_isns_create_header(ha, &pdu->hdr, ISNS_FUNC_SCNDereg);
	/* Source Attribute */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);
	/* Key Attributes */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);

	prb->conn_id = ISNS_DEFAULT_SERVER_CONN_ID;
	prb->handle  = ql4_isns_build_iocb_handle(ha, ISNS_REQ_RSP_PDU, prb);
	prb->tx_len  = (__u16)(ptr - &prb->pdu[0]);
	prb->rx_len  = prb->pdu_buf_len;
	pdu->hdr.pdu_len = htons(prb->tx_len - sizeof(struct isnsp_header));

	set_bit(ISNS_FLAG_SRV_DEREG_IN_PROGRESS, &ha->isns.flags);

	if (ql4_isns_send_passthru_iocb(ha, prb) != QLA_SUCCESS)
		ql4_isns_free_prb(ha, prb);
}

static void ql4_isns_send_dev_dereg(struct scsi_qla_host *ha)
{
	struct isns_prb *prb;
	struct isnsp_message *pdu;
	__u8 *ptr;

	prb = ql4_isns_get_prb(ha, PAGE_SIZE);
	if (!prb) {
		return;
	}

	pdu = (struct isnsp_message *) prb->pdu;
	ptr = (__u8 *) &pdu->attributes[0];

	ql4_isns_create_header(ha, &pdu->hdr, ISNS_FUNC_DevDereg);
	/* Source Attribute */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);
	/* No Key Attribute for DevDereg */
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_DELIMITER, 0, 0);
	/* Operating Attributes fo register */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ENTITY_IDENTIFIER,
		ha->isns.entity_id);
	ql4_isns_append_attr_ip(ha, &ptr, ISNS_ATTR_PORTAL_IP_ADDRESS,
		ha->isns.source_ip);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PORTAL_PORT, 4,
		(__u32) ha->isns.source_port);
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);

	prb->conn_id = ISNS_DEFAULT_SERVER_CONN_ID;
	prb->handle  = ql4_isns_build_iocb_handle(ha, ISNS_REQ_RSP_PDU, prb);
	prb->tx_len  = (__u16)(ptr - &prb->pdu[0]);
	prb->rx_len  = prb->pdu_buf_len;
	pdu->hdr.pdu_len = htons(prb->tx_len - sizeof(struct isnsp_header));

	if (ql4_isns_send_passthru_iocb(ha, prb) != QLA_SUCCESS)
		ql4_isns_free_prb(ha, prb);
}

void ql4_isns_send_dev_get_next(struct scsi_qla_host *ha,
                                __u8 *last_iscsi_name,
				__u8 *tgt_qry_buf,
				__u32 *tgt_qry_buf_len)
{
	struct isns_prb *prb;
	struct isnsp_message *pdu;
	__u8 *ptr;

	prb = ql4_isns_get_prb(ha, PAGE_SIZE);
	if (!prb) {
		return;
	}

	pdu = (struct isnsp_message *) prb->pdu;
	ptr = (__u8 *) &pdu->attributes[0];

	ql4_isns_create_header(ha, &pdu->hdr, ISNS_FUNC_DevGetNext);
	/* Source Attribute */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);
	/* Key Attribute */
	if (last_iscsi_name && strlen(last_iscsi_name))
		ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
			last_iscsi_name);
	else
		/* Length must be zero in order to retrieve the first object */
		ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME, NULL);
	/* Delimiter to indicate division between Key and Operating attributes */
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_DELIMITER, 0, 0);
	/* Operating Attribute */
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ISCSI_NODE_TYPE, 4,
		ISCSI_NODE_TYPE_TARGET);

	prb->conn_id = ISNS_DEFAULT_SERVER_CONN_ID;
	prb->handle  = ql4_isns_build_iocb_handle(ha, ISNS_REQ_RSP_PDU, prb);
	prb->tx_len  = (__u16)(ptr - &prb->pdu[0]);
	prb->rx_len  = prb->pdu_buf_len;
	pdu->hdr.pdu_len = htons(prb->tx_len - sizeof(struct isnsp_header));

	/* Store ptr to last_iscsi_name in prb struct, so that
	 * next_iscsi_name can be returned to caller in
	 * dev_get_next_rsp */
	prb->tgt_qry_iscsi_name = last_iscsi_name;
	prb->tgt_qry_buf = tgt_qry_buf;
	prb->tgt_qry_buf_len = tgt_qry_buf_len;

	if (ql4_isns_send_passthru_iocb(ha, prb) != QLA_SUCCESS)
		ql4_isns_free_prb(ha, prb);

}

void ql4_isns_send_dev_attr_qry(struct scsi_qla_host *ha,
				__u8 *last_iscsi_name,
				__u8 *tgt_qry_buf,
				__u32 *tgt_qry_buf_len)
{
	struct isns_prb *prb;
	struct isnsp_message *pdu;
	__u8 *ptr;

	prb = ql4_isns_get_prb(ha, PAGE_SIZE);
	if (!prb) {
		return;
	}

	pdu = (struct isnsp_message *) prb->pdu;
	ptr = (__u8 *) &pdu->attributes[0];

	ql4_isns_create_header(ha, &pdu->hdr, ISNS_FUNC_DevAttrQry);
	/* Source Attribute */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);
	/* Key Attribute */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		last_iscsi_name);
	/* Delimiter to indicate division between Key and Operating attrs */
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_DELIMITER, 0, 0);
	/* Operating Attributes fo register */
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ENTITY_PROTOCOL, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ISCSI_NAME, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ISCSI_NODE_TYPE, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ISCSI_ALIAS, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PORTAL_IP_ADDRESS, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PORTAL_PORT, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PORTAL_SECURITY_BITMAP, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PG_ISCSI_NAME, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PG_PORTAL_IP_ADDRESS, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PG_PORTAL_PORT, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PG_TAG, 0, 0);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_DD_ID, 0, 0);

	prb->conn_id = ISNS_DEFAULT_SERVER_CONN_ID;
	prb->handle  = ql4_isns_build_iocb_handle(ha, ISNS_REQ_RSP_PDU, prb);
	prb->tx_len  = (__u16)(ptr - &prb->pdu[0]);
	prb->rx_len  = prb->pdu_buf_len;
	pdu->hdr.pdu_len = htons(prb->tx_len - sizeof(struct isnsp_header));

	/* Store ptr to tgt_qry_buf, so that data can be
	 * returned to caller in dev_attr_qry_rsp */
	prb->tgt_qry_buf = tgt_qry_buf;
	prb->tgt_qry_buf_len = tgt_qry_buf_len;

	if (ql4_isns_send_passthru_iocb(ha, prb) != QLA_SUCCESS)
		ql4_isns_free_prb(ha, prb);
}

static void ql4_isns_send_dev_attr_reg(struct scsi_qla_host *ha)
{
	struct isns_prb *prb;
	struct isnsp_message *pdu;
	__u8 *ptr;

	prb = ql4_isns_get_prb(ha, PAGE_SIZE);
	if (!prb) {
		return;
	}

	pdu = (struct isnsp_message *) prb->pdu;
	ptr = (__u8 *) &pdu->attributes[0];

	ql4_isns_create_header(ha, &pdu->hdr, ISNS_FUNC_DevAttrReg);
	/* Source Attribute */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);
	/* No Key Attribute for DevAttrReg */
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_DELIMITER, 0, 0);
	/* Operating Attributes fo register */
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ENTITY_IDENTIFIER,
		ha->isns.entity_id);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ENTITY_PROTOCOL, 4,
		ISNS_ENTITY_PROTOCOL_TPYE_ISCSI);
	ql4_isns_append_attr_ip(ha, &ptr, ISNS_ATTR_PORTAL_IP_ADDRESS,
		ha->isns.source_ip);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_PORTAL_PORT, 4,
		(__u32) ha->isns.source_port);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_SCN_PORT, 4,
		(__u32) ha->isns.scn_port);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ESI_PORT, 4,
		(__u32) ha->isns.esi_port);
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_NAME,
		ha->name_string);
	ql4_isns_append_attr(ha, &ptr, ISNS_ATTR_ISCSI_NODE_TYPE, 4,
		ISNS_ISCSI_NODE_TYPE_INITIATOR);
	ql4_isns_append_attr_str(ha, &ptr, ISNS_ATTR_ISCSI_ALIAS, ha->alias);

	prb->conn_id = ISNS_DEFAULT_SERVER_CONN_ID;
	prb->handle  = ql4_isns_build_iocb_handle(ha, ISNS_REQ_RSP_PDU, prb);
	prb->tx_len  = (__u16)(ptr - &prb->pdu[0]);
	prb->rx_len  = prb->pdu_buf_len;
	pdu->hdr.pdu_len = htons(prb->tx_len - sizeof(struct isnsp_header));

	if (ql4_isns_send_passthru_iocb(ha, prb) != QLA_SUCCESS)
		ql4_isns_free_prb(ha, prb);
}

/**********************   iSNS Parse functions   ***********************/
#if defined(QL_DEBUG_LEVEL_6)
static void ql4_isns_parse_scn(struct scsi_qla_host *ha,
			       struct isnsp_message *pdu)
{
	struct isnsp_attribute *attr =
		(struct isnsp_attribute *) &pdu->attributes[0];
	__u32 bytes_processed = 0;

	__u16 pdu_len = ntohs(pdu->hdr.pdu_len);

	DEBUG6(ql4_info(ha, "SCN Attributes:\n"));
	while ((bytes_processed + sizeof(*attr) + ntohl(attr->len)) <
	       pdu_len) {

		uint32_t tag = ntohl(attr->tag);
		uint32_t len = ntohl(attr->len);

		switch (tag) {
		case ISNS_ATTR_ISCSI_NAME:
			DEBUG6(ql4_info(ha, "\t%s \"%s\"\n",
				ql4_prn_str((int)tag, &isns_attr_str[0]),
				attr->val));
		case ISNS_ATTR_ISCSI_SCN_BITMAP:
			DEBUG6(ql4_info(ha, "\t%s = \"%s\"\n",
				ql4_prn_str((int)tag, &isns_attr_str[0]),
                                ql4_prn_str(ntohl(*(__u32 *)attr->val),
					&iscsi_scn_str[0])));
			break;
		case ISNS_ATTR_TIMESTAMP:
			DEBUG6(ql4_info(ha, "\t%s 0x%llx\n",
				ql4_prn_str((int)tag, &isns_attr_str[0]),
					be64_to_cpu(*(__u64 *)attr->val)));
		default:
			DEBUG6(ql4_info(ha, "\t%s\n",
                               ql4_prn_str((int)attr->tag, &isns_attr_str[0])));
			break;
		}

		bytes_processed += sizeof(struct isnsp_attribute) + len;
		attr = (struct isnsp_attribute *) (&attr->val[0] + len);
	}
}
#endif

static void ql4_isns_parse_dev_attr_reg_rsp(struct scsi_qla_host *ha,
					    struct isnsp_response *pdu)
{
	struct isnsp_attribute *attr =
		(struct isnsp_attribute *) &pdu->attributes[0];
	__u32 bytes_processed = 0;

	DEBUG6(ql4_info(ha, "Attributes:\n"));

	pdu->hdr.pdu_len = ntohs(pdu->hdr.pdu_len);
	while ((bytes_processed + sizeof(*attr) + ntohl(attr->len)) <
	       pdu->hdr.pdu_len) {
		__u32 val32 = ntohl(*(__u32 *)attr->val);
		attr->tag = ntohl(attr->tag);
		attr->len = ntohl(attr->len);

		switch (attr->tag) {
		case ISNS_ATTR_PORTAL_PORT:
		case ISNS_ATTR_SCN_PORT:
		case ISNS_ATTR_ESI_PORT:
		case ISNS_ATTR_REGISTRATION_PERIOD:
			DEBUG6(ql4_info(ha, "\t%s %d\n",
				ql4_prn_str((int)attr->tag, &isns_attr_str[0]),
                                val32));
			break;
		case ISNS_ATTR_ESI_INTERVAL:
			DEBUG6(ql4_info(ha, "\t%s %d\n",
				ql4_prn_str((int)attr->tag, &isns_attr_str[0]),
                                val32));
			ha->isns.esi_interval = val32;
			atomic_set(&ha->isns.esi_timer,
				ha->isns.esi_interval * 2);
			break;
		case ISNS_ATTR_ENTITY_PROTOCOL:
			DEBUG6(ql4_info(ha, "\t%s %d\n",
				ql4_prn_str((int)attr->tag, &isns_attr_str[0]),
                                val32));
			break;
		case ISNS_ATTR_ISCSI_NODE_TYPE:
			DEBUG6(ql4_info(ha, "\t%s = \"%s\"\n",
				ql4_prn_str((int)attr->tag, &isns_attr_str[0]),
                                ql4_prn_str(val32, &iscsi_node_type_str[0])));
			break;
		case ISNS_ATTR_PORTAL_IP_ADDRESS:
			if (attr->val[10] == 0xFF && attr->val[11] == 0xFF) {
				DEBUG6(ql4_info(ha, "\t%s %pI4\n",
					ql4_prn_str((int)attr->tag,
					&isns_attr_str[0]),
					&attr->val[12]));
			}
			else {
				DEBUG6(ql4_info(ha, "\t%s %pI6\n",
					ql4_prn_str((int)attr->tag,
					&isns_attr_str[0]),
                                        (void *) attr->val));
			}

			break;
		case ISNS_ATTR_ENTITY_IDENTIFIER:
		case ISNS_ATTR_ISCSI_ALIAS:
		case ISNS_ATTR_ISCSI_NAME:
			DEBUG6(ql4_info(ha, "\t%s \"%s\"\n",
				ql4_prn_str((int)attr->tag, &isns_attr_str[0]),
                                attr->val));
			break;
		default:
			DEBUG6(ql4_info(ha, "\t%s\n",
			       ql4_prn_str((int)attr->tag, &isns_attr_str[0])));
			break;
		}

		bytes_processed += sizeof(struct isnsp_attribute) + attr->len;
		attr = (struct isnsp_attribute *) (&attr->val[0] + attr->len);
	}
}

/* Remarks: Preserve endian-ness of structures as structure gets passed to
 * Application */
static void ql4_isns_parse_dev_get_next_rsp(struct scsi_qla_host *ha,
                                            struct isns_prb *prb)
{
	struct isnsp_response *pdu =
		(struct isnsp_response *) prb->pdu;
	struct isnsp_attribute *attr =
		(struct isnsp_attribute *) &pdu->attributes[0];
	__u16 pdu_len = ntohs(pdu->hdr.pdu_len);
	__u32 bytes_processed = 0;
	__u8 is_tgt = 0;
	__u8 is_node_reported = 0;
	__u8 is_ioctl = 0;

	is_ioctl = test_and_clear_bit(ISNS_FLAG_IOCTL_INVOKED_QUERY,
		    &ha->isns.flags);

	switch (ntohl(pdu->status_code)) {
	case ISNS_STS_SUCCESS:
		/* Return Next iSCSI Name to caller */
	        if (is_ioctl && prb->tgt_qry_iscsi_name)
			strcpy(prb->tgt_qry_iscsi_name, &attr->val[0]);
		break;
	case ISNS_STS_NO_SUCH_ENTRY:
		/* Return NULL iSCSI Name to caller to indicate no more tgts */
	        if (is_ioctl && prb->tgt_qry_iscsi_name)
			strcpy(prb->tgt_qry_iscsi_name, "");
                DEBUG2(ql4_info(ha, "%s: No more targets\n", __func__));
		goto exit_dev_get_next_attrs;
	default:
		DEBUG2(ql4_info(ha, "%s: Get next failed\n", __func__));
		goto exit_dev_get_next_attrs;
	}

	/* Copy the tgts buf and buf len back to the caller */
	if (prb->tgt_qry_buf && prb->tgt_qry_buf_len) {
	        *prb->tgt_qry_buf_len = pdu_len + sizeof(pdu->hdr);
		memcpy(prb->tgt_qry_buf, pdu,
			*prb->tgt_qry_buf_len);
	}


	DEBUG6(ql4_info(ha, "DevGetNextRsp Attributes:\n"));
	while ((bytes_processed + sizeof(*attr) + ntohl(attr->len)) < pdu_len) {
		__u32 tag = ntohl(attr->tag);
		__u32 len = ntohl(attr->len);

		switch (tag) {
		case ISNS_ATTR_ISCSI_NAME:
			DEBUG6(ql4_info(ha, "\t%s \"%s\"\n",
				ql4_prn_str((int)tag, &isns_attr_str[0]),
                                attr->val));
			break;
		case ISNS_ATTR_ISCSI_NODE_TYPE:
			DEBUG6(ql4_info(ha, "\t%s = \"%s\"\n",
				ql4_prn_str((int)tag, &isns_attr_str[0]),
                                ql4_prn_str(ntohl(*(__u32 *)attr->val),
					&iscsi_node_type_str[0])));
			is_node_reported = 1;
			if (*(__u32 *)attr->val == ISCSI_NODE_TYPE_TARGET)
				is_tgt = 1;
			break;
		default:
			DEBUG6(ql4_info(ha, "\t%s\n",
				ql4_prn_str((int)tag, &isns_attr_str[0])));
			break;
		}

		bytes_processed += sizeof(struct isnsp_attribute) + len;
		attr = (struct isnsp_attribute *) (&attr->val[0] + len);
	}

exit_dev_get_next_attrs:
	return;
}

/* Remarks: Preserve endian-ness of structures as structure gets passed to
 * Application */
static void ql4_isns_parse_dev_attr_qry_rsp(struct scsi_qla_host *ha,
					    struct isns_prb *prb)
{
	struct isnsp_response *pdu =
		(struct isnsp_response *) prb->pdu;
	struct isnsp_attribute *attr =
		(struct isnsp_attribute *) &pdu->attributes[0];
	__u32 bytes_processed = 0;
	__u16 pdu_len = ntohs(pdu->hdr.pdu_len);

	/* Copy the tgts buf and buf len back to the caller */
	if (prb->tgt_qry_buf && prb->tgt_qry_buf_len) {
		*prb->tgt_qry_buf_len = pdu_len + sizeof(pdu->hdr);
		memcpy(prb->tgt_qry_buf, pdu,
			*prb->tgt_qry_buf_len);
	}

	DEBUG6(ql4_info(ha, "DevAttrQryRsp Attributes:\n"));
	while ((bytes_processed + sizeof(*attr) + ntohl(attr->len)) < pdu_len) {

		__u32 tag = ntohl(attr->tag);
		__u32 len = ntohl(attr->len);

		switch (tag) {
		case ISNS_ATTR_PORTAL_PORT:
		case ISNS_ATTR_PG_PORTAL_PORT:
		case ISNS_ATTR_SCN_PORT:
		case ISNS_ATTR_ESI_PORT:
		case ISNS_ATTR_REGISTRATION_PERIOD:
		case ISNS_ATTR_ESI_INTERVAL:
		case ISNS_ATTR_ENTITY_PROTOCOL:
		case ISNS_ATTR_DD_ID:
		case ISNS_ATTR_PG_TAG:
		case ISNS_ATTR_PORTAL_SECURITY_BITMAP:
			DEBUG6(ql4_info(ha, "\t%s %d\n",
				ql4_prn_str((int)tag, &isns_attr_str[0]),
                                ntohl(*(__u32 *)attr->val)));
			break;
		case ISNS_ATTR_ISCSI_NODE_TYPE:
			DEBUG6(ql4_info(ha, "\t%s = \"%s\"\n",
				ql4_prn_str((int)tag, &isns_attr_str[0]),
                                ql4_prn_str(ntohl(*(__u32 *)attr->val),
					&iscsi_node_type_str[0])));
			break;
		case ISNS_ATTR_MGMT_IP_ADDRESS:
		case ISNS_ATTR_PORTAL_IP_ADDRESS:
		case ISNS_ATTR_PG_PORTAL_IP_ADDRESS:
			if (attr->val[10] == 0xFF && attr->val[11] == 0xFF) {
				DEBUG6(ql4_info(ha, "\t%s %pI4\n",
					ql4_prn_str((int)tag, &isns_attr_str[0]),
					&attr->val[12]));
			}
			else {
				DEBUG6(ql4_info(ha, "\t%s %pI6\n",
				       ql4_prn_str((int)tag, &isns_attr_str[0]),
                                       (void *) attr->val));
			}

			break;
		case ISNS_ATTR_ENTITY_IDENTIFIER:
		case ISNS_ATTR_ISCSI_ALIAS:
		case ISNS_ATTR_ISCSI_NAME:
		case ISNS_ATTR_PORTAL_SYMBOLIC_NAME:
		case ISNS_ATTR_PG_ISCSI_NAME:
			DEBUG6(ql4_info(ha, "\t%s \"%s\"\n",
				ql4_prn_str((int)tag, &isns_attr_str[0]),
                                attr->val));
			break;
		default:
			DEBUG6(ql4_info(ha, "\t%s\n",
				ql4_prn_str((int)tag, &isns_attr_str[0])));
			break;
		}

		bytes_processed += sizeof(struct isnsp_attribute) + len;
		attr = (struct isnsp_attribute *) (&attr->val[0] + len);
	}

	clear_bit(ISNS_FLAG_IOCTL_INVOKED_QUERY, &ha->isns.flags);
}

/**
* ql4_isns_process_response_pdu - Final processing of received PDU (Async or
* Response Msg)
*
* @ha: Pointer to Host Adapter structure
* @prb: Pointer to PDU Request Block structure
**/
static void ql4_isns_process_response_pdu(struct scsi_qla_host *ha,
					  struct isns_prb *prb)
{
	struct isnsp_header *pdu = (struct isnsp_header *) prb->pdu;
	__u16 func_id = ntohs(pdu->func_id);

	if ((func_id & ISNS_FUNC_RESPONSE) == 0) {
		/* Async Message PDU */
		switch (func_id) {
		case ISNS_FUNC_ESI:
			DEBUG2(ql4_info(ha, "ESI Message Received\n"));
			atomic_set(&ha->isns.esi_timer,
				ha->isns.esi_interval * 2);
			ql4_isns_send_async_msg_rsp(ha, prb);
			break;
		case ISNS_FUNC_SCN:
			DEBUG2(ql4_info(ha, "SCN Message Received\n"));
			DEBUG2(ql4_isns_parse_scn(ha,
				(struct isnsp_message *) pdu));
			ql4_isns_send_async_msg_rsp(ha, prb);

			/* Tell app to retrieve tgt database */
			ql4_queue_isns_sts_chg_aen(ha,
				ISNS_CHG_TGT_DATABASE);
			break;
		}
	} else {
		/* Response PDU */
		struct isnsp_response *rsp =  (struct isnsp_response *) pdu;
		__u32 status_code = ntohl(rsp->status_code);

		if (status_code)
			DEBUG6(ql4_info(ha, "%s: iSNS Error (%d) "
				"\"%s\"\n", __func__, status_code,
				ql4_prn_str(status_code,
				&isns_sts_str[0])));

		switch (func_id) {
		case ISNS_FUNC_SCNDeregRsp:
			clear_bit(ISNS_FLAG_ISNS_SCN_REGISTERED,
				&ha->isns.flags);
			ql4_isns_send_dev_dereg(ha);
			break;
		case ISNS_FUNC_DevDeregRsp:
			clear_bit(ISNS_FLAG_ISNS_SRV_REGISTERED,
				  &ha->isns.flags);
			clear_bit(ISNS_FLAG_SRV_DEREG_IN_PROGRESS,
					&ha->isns.flags);
			break;
		case ISNS_FUNC_DevAttrRegRsp:
			if (status_code) {
				clear_bit(ISNS_FLAG_ISNS_SRV_REGISTERED,
					  &ha->isns.flags);
			} else {
				set_bit(ISNS_FLAG_ISNS_SRV_REGISTERED,
					  &ha->isns.flags);
				ql4_isns_parse_dev_attr_reg_rsp(ha, rsp);
				ql4_isns_send_scn_reg(ha);
			}
			break;
		case ISNS_FUNC_SCNRegRsp:
			if (status_code) {
				clear_bit(ISNS_FLAG_ISNS_SCN_REGISTERED,
					  &ha->isns.flags);
			} else {
				set_bit(ISNS_FLAG_ISNS_SCN_REGISTERED,
					&ha->isns.flags);
				/* Tell app to retrieve tgt database */
				ql4_queue_isns_sts_chg_aen(ha,
					ISNS_CHG_TGT_DATABASE);
			}
			break;
		case ISNS_FUNC_DevGetNextRsp:
			ql4_isns_parse_dev_get_next_rsp(ha, prb);
			break;
		case ISNS_FUNC_DevAttrQryRsp:
			ql4_isns_parse_dev_attr_qry_rsp(ha, prb);
			break;
		default:
			DEBUG2(ql4_info(ha, "%s: Unknown iSNS function ID "
				"0x%x\n", __func__, func_id));
		}
	}  /* response pdu */
}

/**
 * ql4_isns_process_ip_state_chg -
 * This function is called when an IP state change has occurred
 * (i.e. initiator's IP address has changed, iSNS start/stop, etc).
 **/
void ql4_isns_process_ip_state_chg(struct scsi_qla_host *ha, __u32 *mbox_sts)
{
	uint32_t old_state = mbox_sts[2];
	uint32_t new_state = mbox_sts[3];
	uint32_t source_ip_index = mbox_sts[5] & IPADDR_STATECHG_IP_INDEX_MASK;

	DEBUG6(ql4_info(ha, "%s: old_state=%d, new_state=%d, src_ip_idx=%d"
		"is_ip4=%d\n", __func__, old_state, new_state, source_ip_index,
		is_ipv4_enabled(ha)));

	if (test_bit(ISNS_FLAG_DISABLE_IN_PROGRESS, &ha->isns.flags)) {
		DEBUG2(ql4_info(ha, "%s: ISNS_FLAG_DISABLE_IN_PROGRESS.  "
			"Do not process.\n", __func__));
		return;
	}

	if ((old_state != ACB_STATE_DEPRICATED &&
	     old_state != ACB_STATE_VALID) &&
	    (new_state == ACB_STATE_DEPRICATED ||
	     new_state == ACB_STATE_VALID) &&
	    (((source_ip_index == IP_INDEX_IPv4) && is_ipv4_enabled(ha)) ||
	     ((source_ip_index != IP_INDEX_IPv4) && is_ipv6_enabled(ha)))) {
		set_bit(DPC_ISNS_START, &ha->dpc_flags);
		DEBUG2(ql4_info(ha, "%s: START ISNS SERVICE\n", __func__));
	}

	if ((old_state == ACB_STATE_DEPRICATED ||
	     old_state == ACB_STATE_VALID) &&
	    (new_state != ACB_STATE_DEPRICATED &&
	     new_state != ACB_STATE_VALID)) {
		set_bit(DPC_ISNS_STOP, &ha->dpc_flags);
		DEBUG2(ql4_info(ha, "%s: STOP ISNS SERVICE\n", __func__));
	}

	if (((old_state != ACB_STATE_DEPRICATED &&
	      new_state == ACB_STATE_VALID) ||
	     (old_state != ACB_STATE_VALID &&
	      new_state == ACB_STATE_DEPRICATED)) &&
	    (source_ip_index != ha->isns.source_ip_index)) {
		set_bit(DPC_ISNS_REREGISTER, &ha->dpc_flags);
		DEBUG2(ql4_info(ha, "%s: Re-register with iSNS server\n",
				__func__));
	}
}

/**********************    PDU Functions    *********************/

static __u8 ql4_isns_realloc_pdu(struct scsi_qla_host *ha,
                                 struct isns_prb *prb,
                                 __u32 new_pdu_size)
{
	__u8 *new_pdu;
	dma_addr_t new_pdu_dma;

	/* Overrun condition where new PDU too large
	 * for original PDU.  Allocate larger PDU
	 * before requesting remaining data. */
	new_pdu = dma_alloc_coherent(&ha->pdev->dev,
		new_pdu_size, &new_pdu_dma, GFP_KERNEL);
	if (!new_pdu) {
		DEBUG6(ql4_info(ha, "%s: ERROR: "
			"Unable to allocate larger PDU "
			"buffer (0x%x). Discard PDU\n",
			__func__, new_pdu_size));
		return QLA_ERROR;
	}

	memcpy(new_pdu, prb->pdu, prb->offset);
	dma_free_coherent(&ha->pdev->dev, prb->pdu_buf_len,
		prb->pdu, prb->pdu_dma);
	prb->pdu = new_pdu;
	prb->pdu_dma = new_pdu_dma;
	prb->pdu_buf_len = (new_pdu_size +
		(PAGE_SIZE-1)) & ~(PAGE_SIZE-1);
	DEBUG6(ql4_info(ha, "%s: larger PDU allocated"
		" to hold larger pdu of 0x%x\n",
		__func__, new_pdu_size));
	DEBUG7(__dump_prb(ha,prb));
	return QLA_SUCCESS;
}

static __u8 ql4_isns_validate_pdu_hdr(struct scsi_qla_host *ha,
                                  struct isnsp_header *pdu,
				  __u16 seq_id, __u8 is_first_pdu)
{
	__u16 func_id = ntohs(pdu->func_id);
	__u16 trans_id = ntohs(pdu->trans_id);
	__u16 flags = ntohs(pdu->flags);
	__u8 status = QLA_ERROR;

	if (ntohs(pdu->ver) != ISNSP_VERSION) {
		DEBUG6(ql4_info(ha, "%s: ERROR: Invalid version in "
			"hdr. (%d, expecting %d).  Discard PDU\n",
			__func__, ntohs(pdu->ver), ISNSP_VERSION));
		goto exit_validate_pdu;
	}
	if (seq_id != ntohs(pdu->seq_id)) {
		DEBUG6(ql4_info(ha, "%s: ERROR: Invalid sequence # in "
			"pdu. (%d, expecting %d).  Discard PDU\n",
			__func__, ntohs(pdu->seq_id), seq_id));
		goto exit_validate_pdu;
	}

	if (!is_first_pdu) {
		/* Continue validation of succeeding pdu headers */
		if (flags & ISNSP_FLAG_FIRST_PDU) {
			DEBUG6(ql4_info(ha, "%s: ERROR: FIRST_PDU flag "
				"set in succeeding PDU.  Discard PDU\n",
				__func__));
			goto exit_validate_pdu;
		}
		if (func_id != ntohs(pdu->func_id)) {
			DEBUG6(ql4_info(ha, "%s: ERROR: Invalid "
				"function# in pdu. (%d, expecting %d)."
				"  Discard PDU\n", __func__,
				ntohs(pdu->func_id), func_id));
			goto exit_validate_pdu;
		}
		if (trans_id != ntohs(pdu->trans_id)) {
			DEBUG6(ql4_info(ha, "%s: ERROR: Invalid "
				"trans# in pdu. (%d, expecting %d)."
				"  Discard PDU\n", __func__,
				ntohs(pdu->trans_id), trans_id));
			goto exit_validate_pdu;
		}
	}

	status = QLA_SUCCESS;

exit_validate_pdu:
	return status;
}

/**
 *  ql4_isns_validate_and_reassemble_pdu -
 *
 *  iSNS messages may be packaged in one or more PDUs having the same
 *  function id and transaction id.  However, each PDU of the same message
 *  will have a unique sequence id. (RFC 4171, 5.2)
 *
 *  This function will reassemble multiple PDUs into a single PDU so that
 *  it may be processed by the driver.
 **/
static __u8 ql4_isns_validate_and_reassemble_pdu(struct scsi_qla_host *ha,
                                                 struct isns_prb *prb)
{
	struct isnsp_header *first_pdu = (struct isnsp_header *) prb->pdu;
	struct isnsp_header *pdu = first_pdu;
	__u16 seq_id = (-1);
	__u16 flags = ntohs(pdu->flags);
	__u8 status = QLA_ERROR;
	__u32 bytes_remaining;
	__u32 new_pdu_len = ntohs(first_pdu->pdu_len);

	if (prb->resid_flags & PT_STATUS_RESID_DATA_IN_OVERRUN)
		prb->offset += prb->rx_len;
	else
		prb->offset += prb->rx_len - prb->in_residual;

	bytes_remaining = prb->offset;

	do {
		__u8 is_first_pdu = (first_pdu == pdu);
		__u16 pdu_len = ntohs(pdu->pdu_len);
		__u16 pdu_size = sizeof(*pdu) + pdu_len;

		/* Sometimes the pdu_len indicates that the PDU is actually
		 * larger than the amount indicated in the original 8021 Async
		 * Data AEN.  If the original PDU buffer is not large enough,
		 * then allocate a larger PDU. */
		if (is_first_pdu && (pdu_size > prb->pdu_buf_len)) {
			if (ql4_isns_realloc_pdu(ha, prb, pdu_size)
			    == QLA_ERROR)
				goto exit_reassemble_pdu;
		}

		/* Validate pdu header */
		if (ql4_isns_validate_pdu_hdr(ha, pdu, ++seq_id, is_first_pdu)
		    == QLA_ERROR)
			goto exit_reassemble_pdu;

		/* For multiple PDUs in sequence, copy the flags and payload
		 * from the succeeding pdus to the first PDU */
		if (!is_first_pdu) {
			flags |= ntohs(pdu->flags);
			memmove(&first_pdu->payload[0] + new_pdu_len,
				&pdu->payload[0], pdu_len);

			new_pdu_len += pdu_size;
		} else if (prb->offset <= pdu_size) {
			/* If there is only one PDU and all the bytes are here,
			 * or if we are waiting for the rest of the pdu;
			 * exit as no reassembly is required */
			status = QLA_SUCCESS;
			goto exit_reassemble_pdu;
		}

		/* Check to see if there are enough bytes in the PDU and
		   adjust bytes_remaining accordingly */
		if (bytes_remaining >= pdu_size)
			bytes_remaining -= pdu_size;
		else {
			/* Malformed packet - The number of bytes doesn't
			 * add up to what's specified in the PDU. */
			DEBUG2(ql4_info(ha,
				"%s: Malformed packet size (0x%x)\n",
				__func__, pdu_size));
			goto exit_reassemble_pdu;
		}

		/* Advance to next pdu */
		pdu = (struct isnsp_header *) (&first_pdu->payload[0] +
			new_pdu_len);
	} while (bytes_remaining);

	/* Update first pdu */
	first_pdu->flags = htons(flags);
	first_pdu->pdu_len = htons(new_pdu_len);
	prb->rx_len = sizeof(*pdu) + new_pdu_len;

	status = QLA_SUCCESS;

 exit_reassemble_pdu:
	return status;
}

/**
 *  ql4_isns_is_underrun_pdu -
 *
 *  This function determines if we have an underrun/overrun condition
 *  and need to request the remaining data from the firmware via Passthru
 *  IOCB.  The firmware will not send us another 8021 Async Data AEN to
 *  inform us that there is more data to retrieve.
 *
 *  The following cases are considered underruns:
 *  1. The PDU payload contains less than the data length specified
 *     in the 8021 Async Data AEN.
 *  2. The PDU data length indicates that there is more data to be
 *     transferred than specified in the 8021 Async Data AEN.
 *  3. We only received one PDU of a message split into multiple PDUs.
 **/
static __u8 ql4_isns_is_underrun_pdu(struct scsi_qla_host *ha,
				     struct isns_prb *prb)
{
	struct isnsp_header *hdr = (struct isnsp_header *) prb->pdu;
	__u16 flags = ntohs(hdr->flags);
#if defined(QL_DEBUG_LEVEL_6)
	__u16 trans_id = ntohs(hdr->trans_id);
#endif
	__u16 pdu_size = ntohs(hdr->pdu_len) + sizeof(*hdr);
	__u8 pdu_underrun = 0;

	if (prb->offset < pdu_size) {
		DEBUG6(ql4_info(ha, "%s: tid=0x%x  cid=0x%x PDU over/underrun. "
			"Residual=%lx. Request remaining payload\n",
			__func__, trans_id, prb->conn_id,
			(u_long)(pdu_size - prb->offset) ));
		pdu_underrun = 1;
	} else if ((prb->offset == pdu_size) &&
		   !(flags & ISNSP_FLAG_LAST_PDU)) {
		/* It's possible for multiple PDUs to make up a single PDU
		 * message.  Request the remaining PDUs and reassemble them
		 * later. */
		DEBUG2(ql4_info(ha, "%s: tid=0x%x  cid=0x%x LAST_PDU flag not "
			"set. Request remaining payload\n",
			__func__, trans_id, prb->conn_id));
		pdu_underrun = 1;
	}

	return pdu_underrun;
}

/**********************    Start/Stop Functions    *********************/

void ql4_isns_populate_server_ip(struct scsi_qla_host *ha,
				 struct addr_ctrl_blk *init_fw_cb)
{
	if (init_fw_cb == NULL) {
		DEBUG2(ql4_info(ha, "%s: ERROR: NULL ifcb pointer \n",
			__func__));
		return;
	}
	ha->isns.server_port = le16_to_cpu(init_fw_cb->isns_svr_port);

	if (is_isnsv4_enabled(ha) &&
	    !ql4_is_memzero(init_fw_cb->ipv4_isns_svr_ip,
                     sizeof(init_fw_cb->ipv4_isns_svr_ip))) {

		/* encoded as IPv4-mapped IPv6 address */
		memset(&ha->isns.server_ip[0], 0, sizeof(ha->isns.server_ip));
                ha->isns.server_ip[10] = 0xFF;
                ha->isns.server_ip[11] = 0xFF;
		memcpy(&ha->isns.server_ip[12],
		       init_fw_cb->ipv4_isns_svr_ip,
                       sizeof(init_fw_cb->ipv4_isns_svr_ip));
		DEBUG2(ql4_info(ha, "%s: iSNS ENABLED. Server IP %pI4: %d\n",
			__func__, (void *) &ha->isns.server_ip[12],
			ha->isns.server_port));
	} else if (is_isnsv6_enabled(ha) &&
		   !ql4_is_memzero(init_fw_cb->ipv6_isns_svr_ip,
                            sizeof(init_fw_cb->ipv6_isns_svr_ip))) {

		memcpy(ha->isns.server_ip,
		       init_fw_cb->ipv6_isns_svr_ip,
                       sizeof(init_fw_cb->ipv6_isns_svr_ip));
		DEBUG2(ql4_info(ha, "%s: iSNS ENABLED. Server IP %pI6:"
				" %d\n", __func__,
			(void *) ha->isns.server_ip, ha->isns.server_port));
	} else {
		DEBUG2(ql4_info(ha, "%s: iSNS DISABLED \n",  __func__));
		ql4_isns_clear_flags(ha);
	}
}

/**
 * ql4_isns_populate_source_ip - Populate iSNS Source IP Address
 * @ha: Pointer to Host Adapter structure
 *
 * Fill in iSNS Source (Initiator) IP Address based on the current
 * iSNS Source IP Index
 **/
static void
ql4_isns_populate_source_ip(struct scsi_qla_host *ha)
{
       memset(ha->isns.source_ip, 0, sizeof(ha->isns.source_ip));
       if (ha->isns.source_ip_index == IP_INDEX_IPv4) {
               /* encoded as IPv4-mapped IPv6 address */
               ha->isns.source_ip[10] = 0xFF;
               ha->isns.source_ip[11] = 0xFF;
               memcpy(&ha->isns.source_ip[12], &ha->ip_address, 4);

	       DEBUG6(ql4_info(ha, "%s: iSNS Source IPv4 Address = %pI4 "
			       "idx=%d\n", __func__, ha->ip_address,
				ha->isns.source_ip_index));
       } else {
	       switch (ha->isns.source_ip_index) {
	       case IP_INDEX_IPv6_ADDR0:
		       memcpy(&ha->isns.source_ip[0], &ha->ipv6_addr0,
			      min(sizeof(ha->ipv6_addr0),
				  sizeof(ha->isns.source_ip)));
		       break;
	       case IP_INDEX_IPv6_ADDR1:
		       memcpy(&ha->isns.source_ip[0], &ha->ipv6_addr1,
			      min(sizeof(ha->ipv6_addr1),
				  sizeof(ha->isns.source_ip)));
		       break;
	       case IP_INDEX_IPv6_LINK_LOCAL:
		       memcpy(&ha->isns.source_ip[0], &ha->ipv6_link_local_addr,
			      min(sizeof(ha->ipv6_link_local_addr),
				  sizeof(ha->isns.source_ip)));
		       break;
	       }

	       DEBUG6(ql4_info(ha, "%s: iSNS Source IPv6 Address = %pI6"
			" idx=%d\n", __func__,
			(void *) ha->isns.source_ip,
			ha->isns.source_ip_index));
       }
}

static void ql4_isns_process_isns_conn_open(struct scsi_qla_host *ha,
					    __u32 *mbox_sts)
{
	__u16 conn_id		= (__u16) (mbox_sts[2] & 0x0000FFFF);
	ha->isns.source_port	= (__u16) (mbox_sts[2] >> 16);
	ha->isns.scn_port 	= (__u16) (mbox_sts[3] >> 16);
	ha->isns.esi_port 	= (__u16) (mbox_sts[4] >> 16);

	if (test_bit(ISNS_FLAG_DISABLE_IN_PROGRESS, &ha->isns.flags)) {
		DEBUG2(ql4_info(ha, "%s: ISNS_FLAG_DISABLE_IN_PROGRESS.  "
			"Do not process.\n", __func__));
		return;
	}

	if (conn_id == (__u16) -1) {
		DEBUG2(ql4_info(ha, "%s: "
			"iSNS Server refused connection!\n", __func__));
		ql4_isns_restart_service(ha);
		return;
	}

	atomic_set(&ha->isns.state, ISNS_STATE_TCP_CONNECTED);

	ha->isns.source_ip_index = mbox_sts[6];
        ql4_isns_populate_source_ip(ha);

	DEBUG2(ql4_info(ha, "%s: Entity ID \"%s\" Conn ID %d "
		"SCN Listen %d ESI Listen %d!\n",
		__func__, ha->isns.entity_id, conn_id,
		ha->isns.scn_port, ha->isns.esi_port));
	if (!ha->isns.scn_port)
		ql4_info(ha, "ERROR: SCN Listening Port is NULL! "
			"iSNS Database changes will not be detected!\n");
	if (!ha->isns.esi_port)
		ql4_info(ha, "ERROR: ESI Listening Port is NULL! "
                        "Frequent iSNS server registration will occur!\n");

	ql4_isns_register_isns_server(ha);
}

/**
 *  ql4_isns_get_remaining_payload -
 *
 *  We are retrieving the remaining data for a previous underrun pdu.
 *  The remaining data will be appended to the pdu starting at prb->offset.
 **/
static void ql4_isns_get_remaining_payload(struct scsi_qla_host *ha,
                                           struct isns_prb *prb)
{
	struct isnsp_message *msg = (struct isnsp_message *) prb->pdu;

	prb->tx_len = 0;
	prb->rx_len = ntohs(msg->hdr.pdu_len) + sizeof(*msg) - prb->offset;
	prb->handle  = ql4_isns_build_iocb_handle(ha, ISNS_ASYNC_REQ_PDU, prb);

	DEBUG6(ql4_info(ha, "%s: offset=0x%x, rx_len=0x%x\n",
		__func__, prb->offset, prb->rx_len));

	if (ql4_isns_send_passthru_iocb(ha, prb) != QLA_SUCCESS)
		ql4_isns_free_prb(ha, prb);
}

/**
 * ql4_isns_get_async_data - Request PDU payload for Async request
 *
 * Remarks: We received a *Data Received* status code from an
 *          8021h AEN, so retrieve the data (i.e. ESI or SCN) via
 *	    Passthru IOCB.
 **/
static void ql4_isns_get_async_data(struct scsi_qla_host *ha,
				__u32 conn_id, __u32 payload_len)
{
	struct isns_prb *prb;

	prb = ql4_isns_get_prb(ha, payload_len);
	if (prb) {
		prb->conn_id = (__u16) conn_id;
		prb->tx_len = 0;
		prb->rx_len = payload_len;
		prb->handle = ql4_isns_build_iocb_handle(ha,
			ISNS_ASYNC_REQ_PDU, prb);

		if (ql4_isns_send_passthru_iocb(ha, prb) != QLA_SUCCESS)
			ql4_isns_free_prb(ha, prb);
	}
}

/**
 * ql4_isns_process_passthru_sts_iocb - Performs initial processing of
 * received PDU (Async or Response Msg
 *
 * @ha: Pointer to Host Adapter structure
 * @prb: Pointer to PDU Request Block structure
 *
 * NOTE: The following passthru_status fields are NOT populated for 4032:
 *  	 - residual_flags in underrun case
 *  	 - in_residual in overrun case.
 **/
void ql4_isns_queue_passthru_sts_iocb(struct scsi_qla_host *ha,
                                        struct isns_prb *prb)
{
	struct passthru_status *sts_entry =
					(struct passthru_status *) prb->pkt;

	if (sts_entry->cmpl_status != PASSTHRU_STATUS_COMPLETE){
		DEBUG2(ql4_info(ha, "%s: ERROR: cmpl_status (0x%x)\n",
			__func__, sts_entry->cmpl_status));
		ql4_isns_free_prb(ha, prb);

		set_bit(DPC_ISNS_REREGISTER, &ha->dpc_flags);
		DEBUG2(ql4_info(ha, "%s: Re-Register with iSNS server\n",
					__func__));
		return;
	}

	if (le32_to_cpu(sts_entry->handle) != prb->handle){
		DEBUG2(ql4_info(ha, "%s: ERROR: handle mismatch iocb(0x%x)"
					" prb (0x%x)\n", __func__,
					sts_entry->handle, prb->handle));
		ql4_isns_free_prb(ha, prb);
		return;
	}

	mutex_lock(&ha->isns.prb_lock);
	list_add_tail(&prb->list, &ha->isns.rcvd_pdu_list);
	mutex_unlock(&ha->isns.prb_lock);

	queue_work(ha->pt_thread, &ha->pt_work);
}

/**
 * ql4_isns_dequeue_passthru_sts_iocb -  Process queued (Async or
 * Response Msg) PDUs.
 * @data: in our case pointer to adapter structure
 **/
void ql4_isns_dequeue_passthru_sts_iocb(struct work_struct *data)
{
	struct scsi_qla_host *ha =
		container_of(data, struct scsi_qla_host, pt_work);
	struct isns_prb *prb, *prb_tmp;

	mutex_lock(&ha->isns.prb_lock);
	list_for_each_entry_safe(prb, prb_tmp,
		&ha->isns.rcvd_pdu_list, list) {
		list_del_init(&prb->list);
		mutex_unlock(&ha->isns.prb_lock);
		ql4_isns_process_passthru_sts_iocb(ha, prb);
		mutex_lock(&ha->isns.prb_lock);
	}
	mutex_unlock(&ha->isns.prb_lock);
}

/**
 * ql4_isns_process_passthru_sts_iocb - Performs initial processing of
 * received PDU (Async or Response Msg
 *
 * @ha: Pointer to Host Adapter structure
 * @prb: Pointer to PDU Request Block structure
 *
 * NOTE: The following passthru_status fields are NOT populated for 4032:
 *  	 - residual_flags in underrun case
 *  	 - in_residual in overrun case.
 **/
void ql4_isns_process_passthru_sts_iocb(struct scsi_qla_host *ha,
					struct isns_prb *prb)
{
	struct passthru_status *sts_entry = (struct passthru_status *) prb->pkt;
#if defined(QL_DEBUG_LEVEL_6)
	struct isnsp_header *pdu = (struct isnsp_header *) prb->pdu;
	__u16 func_id = ntohs(pdu->func_id);
	__u16 pdu_len = ntohs(pdu->pdu_len);
#endif

	prb->conn_id = __le16_to_cpu(sts_entry->conn_id);
	prb->in_residual = __le32_to_cpu(sts_entry->in_residual);
	prb->resid_flags = sts_entry->residual_flags;

	DEBUG6(ql4_info(ha,"------------------------\n"));
	DEBUG6(ql4_info(ha,"Receiving tid=0x%x cid=0x%x  %s  <- rx_len=0x%x "
		"(Display MAX 100h)\n",
		ntohs(pdu->trans_id), prb->conn_id,
		ql4_prn_str(func_id, &isns_func_str[0]),
		prb->rx_len));
	DEBUG6(ql4_info(ha,"pdu_size=0x%x, in_residual=0x%x offset=0x%x "
		"actual_rx=0x%x\n",
		(__u32)(sizeof(*pdu) + pdu_len), prb->in_residual, prb->offset,
		(prb->resid_flags & PT_STATUS_RESID_DATA_IN_OVERRUN) ?
		prb->rx_len : prb->rx_len-prb->in_residual));
	DEBUG6(qla4xxx_dump_bytes(prb->pdu + prb->offset,
		min(prb->rx_len, (__u32)0x100)));
	DEBUG7(__dump_prb(ha,prb));
	DEBUG7(ql4_info(ha,"dump passthru status iocb %p\n", sts_entry));
	DEBUG7(qla4xxx_dump_bytes(sts_entry, sizeof(*sts_entry)));

	if (ql4_isns_validate_and_reassemble_pdu(ha, prb)
	    != QLA_SUCCESS) {
		ql4_isns_free_prb(ha, prb);
		set_bit(DPC_ISNS_REREGISTER, &ha->dpc_flags);
		DEBUG2(ql4_info(ha, "%s: Re-Register with iSNS server\n",
			__func__));
		return;
	}

	if (ql4_isns_is_underrun_pdu(ha, prb))
		/* If a PDU underrun has occurred, then we need to
		 * request the remaining payload from the firmware */
		ql4_isns_get_remaining_payload(ha, prb);
	else {
		ql4_isns_process_response_pdu(ha, prb);
		ql4_isns_free_prb(ha, prb);
	}
 }

/**
 * ql4_isns_process_isns_aen - Process 8021h iSNS AEN
 *
 * Remarks: We received an 8021h AEN in response to a
 *          Mailbox 21h (Enable iSNS) command, or the driver is
 *	    being notified that Asynchronous data needs to be
 *	    retrieved.
 * Context: Interrupt
 **/
void ql4_isns_process_isns_aen(struct scsi_qla_host *ha, __u32 *mbox_sts)
{
	__u32 aen_status_code = mbox_sts[1];

	switch (aen_status_code) {
	case ISNS_EVENT_DATA_RECEIVED:
	{
		__u32 conn_id = mbox_sts[2];
		__u32 payload_len = mbox_sts[3];

		DEBUG6(ql4_info(ha, "AEN %04x, iSNS Async Data Received\n",
			mbox_sts[0]));
		ql4_isns_get_async_data(ha, conn_id, payload_len);
		break;
	}
	case ISNS_EVENT_CONNECTION_OPENED:
		DEBUG2(ql4_info(ha, "AEN %04x, iSNS Server Connection Open\n",
			mbox_sts[0]));
		ql4_isns_process_isns_conn_open(ha, mbox_sts);
		break;
	case ISNS_EVENT_CONNECTION_FAILED:
		DEBUG2(ql4_info(ha,
			"AEN %04x, iSNS Service Connection FAILED!"
			" reason %04x\n", mbox_sts[0], mbox_sts[2]));

		atomic_set(&ha->isns.state, ISNS_STATE_TCP_DISCONNECTED);
		break;
	default:
		break;
	}
}

/**
 * ql4_is_isns_active -  Retrieve iSNS Server TCP Connection status
 * @ha: Pointer to Host Adapter structure
 * @return: 1=active, 0=not active
 *
 * Remarks: Sometimes the Application can stop the iSNS connection without the
 * driver's knowledge, so the driver must get real-time status.
 **/
__u8 ql4_is_isns_active(struct scsi_qla_host *ha)
{
	__u32 mbox_cmd[MBOX_REG_COUNT];
	__u32 mbox_sts[MBOX_REG_COUNT];
	__u8 isns_active  = 0xFF;

	memset(mbox_cmd, 0, sizeof(mbox_cmd));
	memset(mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_SET_ISNS_SERVICE;
	mbox_cmd[1] = ISNS_REPORT_STATUS;

	if (qla4xxx_mailbox_command(ha, 2, 6, &mbox_cmd[0], &mbox_sts[0])
	    == QLA_ERROR) {
		DEBUG2(ql4_info(ha,
			"%s: MBOX_CMD_SET_ISNS_SERVICE failed. "
			"status %04x %04x\n", __func__,
			mbox_sts[0], mbox_sts[1]));

		goto exit_get_svc_status;
	}

	isns_active = mbox_sts[5] & 0xF;

exit_get_svc_status:
	DEBUG6(ql4_info(ha, "%s (%d)\n", __func__, isns_active));
	return(isns_active);
}

/**
 * ql4_isns_deregister_isns_server - De-register with the iSNS server.
 * @ha: Pointer to Host Adapter structure
 *
 *  NOTE: This function assumes that a TCP connection to the iSNS server is
 *  currently established
 **/
__u8 ql4_isns_deregister_isns_server(struct scsi_qla_host *ha)
{
	__u8 status = QLA_SUCCESS;
	unsigned long wtime;

	DEBUG2(ql4_info(ha, "De-Register iSNS Server\n"));

	/* NOTE: scn_dereg subsequently invokes dev_dereg */
	ql4_isns_send_scn_dereg(ha);

	/* Wait for deregistration to complete */
	wtime = jiffies + (ISNS_DEREG_TOV * HZ);
	while (!time_after_eq(jiffies, wtime)) {
		if (!test_bit(ISNS_FLAG_SRV_DEREG_IN_PROGRESS, &ha->isns.flags))
			break;
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(1 * HZ);
	}

	if (test_bit (ISNS_FLAG_SRV_DEREG_IN_PROGRESS, &ha->isns.flags)) {
		DEBUG2(ql4_info(ha, " ERROR: De-Register iSNS Server\n"));
		ql4_isns_clear_flags(ha);
		status = QLA_ERROR;
	}

	return status;
}

/**
 * ql4_isns_register_isns_server - Register with the iSNS server.
 * @ha: Pointer to Host Adapter structure
 *
 *  NOTE: This function assumes that a TCP connection to the iSNS server is
 *  currently established
 **/
__u8 ql4_isns_register_isns_server(struct scsi_qla_host *ha)
{
	unsigned long wtime;
	__u8 status = QLA_ERROR;
	__u8 retry;

	clear_bit(DPC_ISNS_REREGISTER, &ha->dpc_flags);

	for (retry = 1; retry <= 2; retry++) {
		/* If iSNS is already registered, de-register before
		 * re-registering */
		if (test_bit(ISNS_FLAG_ISNS_SRV_REGISTERED, &ha->isns.flags) ||
		    retry > 1)
			ql4_isns_deregister_isns_server(ha);

		DEBUG2(ql4_info(ha, "Register iSNS Server\n"));
		ql4_isns_send_dev_attr_reg(ha);

		/* Wait for iSNS registration to complete */
		wtime = jiffies + ISNS_DEREG_TOV * HZ;
		while (!time_after_eq(jiffies, wtime)) {
			if (test_bit(ISNS_FLAG_ISNS_SCN_REGISTERED,
			    &ha->isns.flags))
				break;
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(1 * HZ);
		}

		if (test_bit(ISNS_FLAG_ISNS_SCN_REGISTERED, &ha->isns.flags)) {
			DEBUG2(ql4_info(ha, "Register iSNS Server complete\n"));
			status = QLA_SUCCESS;
			break;
		} else
			/* It's possible that there was a previous abnormal
			 * exit that prevented iSNS server deregistration
			 * (thus SRV_REGISTERED bit was not set); however,
			 * we must first de-register with the iSNS server before
			 * re-registering with it, so retry once */
			DEBUG2(ql4_info(ha, "Retry register iSNS Server\n"));
	}

	if (status == QLA_ERROR) {
			DEBUG2(ql4_info(ha, "Register iSNS Server failed\n"));
	}
	return status;
}

uint8_t ql4_isns_start_service(struct scsi_qla_host *ha)
{
	__u32 mbox_cmd[MBOX_REG_COUNT];
	__u32 mbox_sts[MBOX_REG_COUNT];
	__u8 status = QLA_ERROR;

	if (test_bit(ISNS_FLAG_DISABLE_IN_PROGRESS, &ha->isns.flags)) {
		DEBUG2(ql4_info(ha, "%s: ISNS_FLAG_DISABLE_IN_PROGRESS.  "
			"Do not process.\n", __func__));
		return status;
	}

	if (ql4_is_isns_active(ha)) {
		DEBUG2(ql4_info(ha, "%s: iSNS connection already established.  "
				"Stopping old connection first.\n", __func__));
		ql4_isns_stop_service(ha);
        }

	DEBUG2(ql4_info(ha, "Connecting to iSNS Server...\n"));
	atomic_set(&ha->isns.state, ISNS_STATE_STARTING_SRV);

	memset(mbox_cmd, 0, sizeof(mbox_cmd));
	memset(mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_SET_ISNS_SERVICE;
	mbox_cmd[3] = ha->isns.server_port;

	if (ql4_is_memzero(&ha->isns.server_ip[0], sizeof(ha->isns.server_ip))) {
		DEBUG6(ql4_info(ha, "%s: ERROR: iSNS Server IP is NULL!\n",
			__func__));
		goto exit_start_svc;
	} else if (ql4_is_memzero(&ha->name_string[0], sizeof(ha->name_string))) {
		DEBUG6(ql4_info(ha, "%s: ERROR: iSNS Name String is NULL!\n",
			__func__));
		goto exit_start_svc;
	} else if (is_isnsv4_enabled(ha)) {
		mbox_cmd[1] = ISNSv4_ENABLE;
		mbox_cmd[2] |= ha->isns.server_ip[15] << 24;
		mbox_cmd[2] |= ha->isns.server_ip[14] << 16;
		mbox_cmd[2] |= ha->isns.server_ip[13] << 8;
		mbox_cmd[2] |= ha->isns.server_ip[12];
		DEBUG6(ql4_info(ha, "%s: iSNS Server IPv4 "NIPQUAD_FMT
		", port %d\n", __func__,
		NIPQUAD(ha->isns.server_ip[12]), ha->isns.server_port));
	} else if (is_isnsv6_enabled(ha)) {
		mbox_cmd[1] = ISNSv6_ENABLE;
		memcpy(&mbox_cmd[4], ha->isns.server_ip,
		       sizeof(ha->isns.server_ip));
		DEBUG6(ql4_info(ha, "%s: iSNS Server IPv6 %pI6, port %d\n",
			__func__, (void *) ha->isns.server_ip,
			ha->isns.server_port));
	}

	ql4_isns_build_entity_id(ha);

	status = qla4xxx_mailbox_command(ha, 8, 5, &mbox_cmd[0], &mbox_sts[0]);
	if (status != QLA_SUCCESS) {
		DEBUG2(ql4_info(ha, "%s: "
				"MBOX_CMD_SET_ISNS_SERVICE failed. "
				"status %04x %04x\n", __func__,
				mbox_sts[0], mbox_sts[1]));

		/* Trigger DPC to poll for iSNS connection */
		atomic_set(&ha->isns.state, ISNS_STATE_TCP_DISCONNECTED);
	} else {
		DEBUG6(ql4_info(ha, "%s: Wait for iSNS AEN. "
				"status %04x %04x\n", __func__,
				mbox_sts[0], mbox_sts[1]));
	}

exit_start_svc:
	return status;
}

uint8_t ql4_isns_stop_service(struct scsi_qla_host *ha)
{
	__u32 mbox_cmd[MBOX_REG_COUNT];
	__u32 mbox_sts[MBOX_REG_COUNT];
	__u8 status = QLA_ERROR;

	if (test_bit(ISNS_FLAG_ISNS_SRV_REGISTERED, &ha->isns.flags))
		ql4_isns_deregister_isns_server(ha);

	if (!ql4_is_isns_active(ha)) {
		DEBUG2(ql4_info(ha, "%s: ERROR: iSNS Service not connected.\n",
			__func__));
		goto exit_stop_svc;
	}

	DEBUG2(ql4_info(ha, "Disconnecting from iSNS Server ...\n"));
	memset(mbox_cmd, 0, sizeof(mbox_cmd));
	memset(mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_SET_ISNS_SERVICE;
	mbox_cmd[1] = ISNS_DISABLE;

	status = qla4xxx_mailbox_command(ha, 2, 2, &mbox_cmd[0], &mbox_sts[0]);
	if (status != QLA_SUCCESS) {
		DEBUG2(ql4_info(ha,
			"%s: MBOX_CMD_SET_ISNS_SERVICE failed. "
			"status %04x %04x\n", __func__,
			mbox_sts[0], mbox_sts[1]));
		set_bit(DPC_ISNS_DEREGISTER, &ha->dpc_flags);
		DEBUG2(ql4_info(ha, "%s: De-Register with iSNS server\n",
				__func__));
		goto exit_stop_svc;
	}

	DEBUG2(ql4_info(ha, "iSNS Server Disconnected\n"));
	/* Notify application iSNS server is off-line */
	if (atomic_read(&ha->isns.state) != ISNS_STATE_TCP_DISCONNECTED)
		ql4_queue_isns_sts_chg_aen(ha, ISNS_CHG_SERVER_OFFLINE);

	atomic_set(&ha->isns.state, ISNS_STATE_TCP_DISCONNECTED);

	ql4_isns_clear_flags(ha);
	atomic_set(&ha->isns.esi_timer, 0);
	memset(ha->isns.entity_id, 0, sizeof(ha->isns.entity_id));

exit_stop_svc:
	return status;
}
