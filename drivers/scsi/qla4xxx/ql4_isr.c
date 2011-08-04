/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

#include "ql4_def.h"
#include "ql4_glbl.h"
#include "ql4_dbg.h"
#include "ql4_inline.h"
#include <scsi/iscsi_proto.h>

/**
 * qla4xxx_check_and_copy_sense - copy sense data into cmd sense buffer
 * @ha: Pointer to host adapter structure.
 * @sts_entry: Pointer to status entry structure.
 * @srb: Pointer to srb structure.
 **/
static void qla4xxx_check_and_copy_sense(struct scsi_qla_host *ha,
                               struct status_entry *sts_entry,
                               struct srb *srb)
{
	struct scsi_cmnd *cmd = srb->cmd;
	uint16_t sense_len;

	memset(cmd->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);
	sense_len = le16_to_cpu(sts_entry->senseDataByteCnt);
	if (sense_len == 0) {
		DEBUG2(ql4_info(ha, "%d:%d:%d: %s: sense len 0\n",
				cmd->device->channel, cmd->device->id,
				cmd->device->lun, __func__));
		ha->status_srb = NULL;
		return;
	}

	/* Save total available sense length,
	 * not to exceed cmd's sense buffer size */
	sense_len = min_t(uint16_t, sense_len, SCSI_SENSE_BUFFERSIZE);
	srb->req_sense_ptr = cmd->sense_buffer;
	srb->req_sense_len = sense_len;

	/* Copy sense from sts_entry pkt */
	sense_len = min_t(uint16_t, sense_len, IOCB_MAX_SENSEDATA_LEN);
	memcpy(cmd->sense_buffer, sts_entry->senseData, sense_len);

	DEBUG2(ql4_info(ha, "%d:%d:%d: %s: sense key = %x, "
		"ASL= %02x, ASC/ASCQ = %02x/%02x\n",
		cmd->device->channel, cmd->device->id,
		cmd->device->lun, __func__,
		sts_entry->senseData[2] & 0x0f,
		sts_entry->senseData[7],
		sts_entry->senseData[12],
		sts_entry->senseData[13]));

	DEBUG5(qla4xxx_dump_buffer(cmd->sense_buffer, sense_len));
	srb->flags |= SRB_GOT_SENSE;

	/* Update srb, in case a sts_cont pkt follows */
	srb->req_sense_ptr += sense_len;
	srb->req_sense_len -= sense_len;
	if (srb->req_sense_len != 0)
		ha->status_srb = srb;
	else
		ha->status_srb = NULL;

	if ((srb->flags & SRB_SCSI_PASSTHRU))
		return;

	/* check for vaild sense data */
	if ((sts_entry->senseData[0] & 0x70) != 0x70)
		return;

	switch (sts_entry->senseData[2] & 0x0f) {
	case UNIT_ATTENTION:
		if (sts_entry->senseData[12] == 0x3F &&
		    sts_entry->senseData[13] == 0x0E) {
			struct ddb_entry *ddb_entry;

			ddb_entry = qla4xxx_lookup_ddb_by_os_index(ha,
				cmd->device->id);
			if (ddb_entry) {
				dev_info(&ha->pdev->dev,"%s: ddb[%d] os[%d] "
					"schedule dynamic lun scan\n",
					__func__, ddb_entry->fw_ddb_index,
					ddb_entry->os_target_id);

				set_bit(DF_DYNAMIC_LUN_SCAN_NEEDED,
					&ddb_entry->flags);
				set_bit(DPC_DYNAMIC_LUN_SCAN, &ha->dpc_flags);
			}
		}
		break;
	}
}

/**
 * qla4xxx_status_cont_entry - Process a Status Continuations entry.
 * @ha: SCSI driver HA context
 * @sts_cont: Entry pointer
 *
 * Extended sense data.
 */
static void
qla4xxx_status_cont_entry(struct scsi_qla_host *ha,
			  struct status_cont_entry *sts_cont)
{
	struct srb *srb = ha->status_srb;
	struct scsi_cmnd *cmd;
	uint16_t sense_len;

	if (srb == NULL)
		return;

	cmd = srb->cmd;
	if (cmd == NULL) {
		DEBUG2(ql4_info(ha, "%s: Cmd already returned "
			"back to OS srb=%p srb->state:%d\n",
			__func__, srb, srb->state));
		ha->status_srb = NULL;
		return;
	}

	/* Copy sense data. */
	sense_len = min_t(uint16_t, srb->req_sense_len,
			  IOCB_MAX_EXT_SENSEDATA_LEN);
	memcpy(srb->req_sense_ptr, sts_cont->ext_sense_data, sense_len);
	DEBUG5(qla4xxx_dump_buffer(srb->req_sense_ptr, sense_len));

	srb->req_sense_ptr += sense_len;
	srb->req_sense_len -= sense_len;

	/* Place command on done queue. */
	if (srb->req_sense_len == 0) {
		kref_put(&srb->srb_ref, qla4xxx_srb_compl);
		ha->status_srb = NULL;
	}
}

/**
 * qla4xxx_status_entry - processes status IOCBs
 * @ha: Pointer to host adapter structure.
 * @sts_entry: Pointer to status entry structure.
 **/
static void qla4xxx_status_entry(struct scsi_qla_host *ha,
				 struct status_entry *sts_entry)
{
	uint8_t scsi_status;
	struct scsi_cmnd *cmd;
	struct srb *srb;
	struct ddb_entry *ddb_entry;
	uint32_t residual;

	srb = qla4xxx_del_from_active_array(ha, le32_to_cpu(sts_entry->handle));
	if (!srb) {
		DEBUG2(ql4_warn(ha, "%s: Status Entry invalid "
			      "handle 0x%x, sp=%p. This cmd may have already "
			      "been completed.\n", __func__,
			      le32_to_cpu(sts_entry->handle), srb));
		ql4_warn(ha, "%s invalid status entry:"
		    " handle=0x%0x\n", __func__, sts_entry->handle);
		if (is_qla8022(ha))
			set_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
		else
			set_bit(DPC_RESET_HA, &ha->dpc_flags);
		return;
	}

	cmd = srb->cmd;
	if (cmd == NULL) {
		DEBUG2(ql4_info(ha, "%s: Command already returned back to "
			      "OS pkt->handle=%d srb=%p srb->state:%d\n",
			      __func__, sts_entry->handle,
			      srb, srb->state));
		ql4_warn(ha, "Command is NULL:"
		    " already returned to OS (srb=%p)\n", srb);
		return;
	}

	ddb_entry = srb->ddb;
	if (ddb_entry == NULL) {
		cmd->result = DID_NO_CONNECT << 16;
		goto status_entry_exit;
	}

	residual = le32_to_cpu(sts_entry->residualByteCnt);

	/* Translate ISP error to a Linux SCSI error. */
	scsi_status = sts_entry->scsiStatus;
	switch (sts_entry->completionStatus) {
	case SCS_COMPLETE:

		if (sts_entry->iscsiFlags & ISCSI_FLAG_RESIDUAL_OVER) {
			cmd->result = DID_ERROR << 16;
			break;
		}

		if (sts_entry->iscsiFlags &ISCSI_FLAG_RESIDUAL_UNDER) {
			scsi_set_resid(cmd, residual);
			if (!scsi_status && ((scsi_bufflen(cmd) - residual) <
				cmd->underflow)) {

				cmd->result = DID_ERROR << 16;

				DEBUG2(ql4_info(ha, "%d:%d:%d: %s: "
					"Mid-layer Data underrun0, "
					"xferlen = 0x%x, "
					"residual = 0x%x\n",
					cmd->device->channel,
					cmd->device->id,
					cmd->device->lun, __func__,
					scsi_bufflen(cmd), residual));
				break;
			}
		}

		cmd->result = DID_OK << 16 | scsi_status;

		if (scsi_status != SCSI_CHECK_CONDITION)
			break;

		/* Copy Sense Data into sense buffer. */
		qla4xxx_check_and_copy_sense(ha, sts_entry, srb);
		break;

	case SCS_INCOMPLETE:
		/* Always set the status to DID_ERROR, since
		 * all conditions result in that status anyway */
		cmd->result = DID_ERROR << 16;
		break;

	case SCS_RESET_OCCURRED:
		DEBUG2(ql4_info(ha, "%d:%d:%d: %s: Device RESET occurred\n",
			      cmd->device->channel, cmd->device->id,
			      cmd->device->lun, __func__));

		cmd->result = DID_RESET << 16;
		break;

	case SCS_ABORTED:
		DEBUG2(ql4_info(ha, "%d:%d:%d: %s: Abort occurred\n",
			      cmd->device->channel, cmd->device->id,
			      cmd->device->lun, __func__));

		cmd->result = DID_RESET << 16;
		break;

	case SCS_TIMEOUT:
		DEBUG2(ql4_info(ha, "%d:%d:%d: Timeout\n",
			      cmd->device->channel,
			      cmd->device->id, cmd->device->lun));

		cmd->result = DID_TRANSPORT_DISRUPTED << 16;

		/*
		 * Mark device missing so that we won't continue to send
		 * I/O to this device.	We should get a ddb state change
		 * AEN soon.
		 */
		if (atomic_read(&ddb_entry->state) == DDB_STATE_ONLINE)
			qla4xxx_mark_device_missing(ha, ddb_entry);
		break;

	case SCS_DATA_UNDERRUN:
	case SCS_DATA_OVERRUN:
		if ((sts_entry->iscsiFlags & ISCSI_FLAG_RESIDUAL_OVER) ||
		     (sts_entry->completionStatus == SCS_DATA_OVERRUN)) {
			DEBUG2(ql4_info(ha, "%d:%d:%d: %s: " "Data overrun\n",
				      cmd->device->channel, cmd->device->id,
				      cmd->device->lun, __func__));

			cmd->result = DID_ERROR << 16;
			break;
		}

		scsi_set_resid(cmd, residual);

		/*
		 * If there is scsi_status, it takes precedense over
		 * underflow condition.
		 */
		if (scsi_status != 0) {
			cmd->result = DID_OK << 16 | scsi_status;

			if (scsi_status != SCSI_CHECK_CONDITION)
				break;

			/* Copy Sense Data into sense buffer. */
			qla4xxx_check_and_copy_sense(ha, sts_entry, srb);
		} else {
			/*
			 * If RISC reports underrun and target does not
			 * report it then we must have a lost frame, so
			 * tell upper layer to retry it by reporting a
			 * bus busy.
			 */
			if ((sts_entry->iscsiFlags &
			     ISCSI_FLAG_RESIDUAL_UNDER) == 0) {
				cmd->result = DID_BUS_BUSY << 16;
			} else if ((scsi_bufflen(cmd) - residual) <
				   cmd->underflow) {
				/*
				 * Handle mid-layer underflow???
				 *
				 * For kernels less than 2.4, the driver must
				 * return an error if an underflow is detected.
				 * For kernels equal-to and above 2.4, the
				 * mid-layer will appearantly handle the
				 * underflow by detecting the residual count --
				 * unfortunately, we do not see where this is
				 * actually being done.	 In the interim, we
				 * will return DID_ERROR.
				 */
				DEBUG2(ql4_info(ha, "%d:%d:%d: %s: "
					"Mid-layer Data underrun1, "
					"xferlen = 0x%x, "
					"residual = 0x%x\n",
					cmd->device->channel,
					cmd->device->id,
					cmd->device->lun, __func__,
					scsi_bufflen(cmd), residual));

				cmd->result = DID_ERROR << 16;
			} else {
				cmd->result = DID_OK << 16;
			}
		}
		break;

	case SCS_DEVICE_LOGGED_OUT:
	case SCS_DEVICE_UNAVAILABLE:
		DEBUG2(ql4_info(ha, "%d:%d:%d: SCS_DEVICE "
		    "state: 0x%x\n", cmd->device->channel, cmd->device->id,
		    cmd->device->lun, sts_entry->completionStatus));
		/*
		 * Mark device missing so that we won't continue to
		 * send I/O to this device.  We should get a ddb
		 * state change AEN soon.
		 */
		if (atomic_read(&ddb_entry->state) == DDB_STATE_ONLINE)
			qla4xxx_mark_device_missing(ha, ddb_entry);

		cmd->result = DID_TRANSPORT_DISRUPTED << 16;
		break;

	case SCS_QUEUE_FULL:
		/*
		 * SCSI Mid-Layer handles device queue full
		 */
		cmd->result = DID_OK << 16 | sts_entry->scsiStatus;
		DEBUG2(ql4_info(ha, "%d:%d: %s: QUEUE FULL detected "
			      "compl=%02x, scsi=%02x, state=%02x, iFlags=%02x,"
			      " iResp=%02x\n", cmd->device->id,
			      cmd->device->lun, __func__,
			      sts_entry->completionStatus,
			      sts_entry->scsiStatus, sts_entry->state_flags,
			      sts_entry->iscsiFlags,
			      sts_entry->iscsiResponse));
		break;

	default:
		cmd->result = DID_ERROR << 16;
		break;
	}

status_entry_exit:

	/* complete the request, if not waiting for status_continuation pkt */
	srb->cc_stat = sts_entry->completionStatus;
	if (ha->status_srb == NULL)
		kref_put(&srb->srb_ref, qla4xxx_srb_compl);
}

/**
 * qla4xxx_process_response_queue - process response queue completions
 * @ha: Pointer to host adapter structure.
 *
 * This routine process response queue completions in interrupt context.
 * Hardware_lock locked upon entry
 **/
void qla4xxx_process_response_queue(struct scsi_qla_host *ha)
{
	uint32_t count = 0;
	struct srb *srb = NULL;
	struct status_entry *sts_entry;
	struct async_pdu_iocb *apdu;
	struct iscsi_hdr *pdu_hdr;
	struct async_msg_pdu_iocb *apdu_iocb;

	/* Process all responses from response queue */
	while ((ha->response_ptr->signature != RESPONSE_PROCESSED)) {
		sts_entry = (struct status_entry *) ha->response_ptr;
		count++;

		/* Advance pointers for next entry */
		if (ha->response_out == (RESPONSE_QUEUE_DEPTH - 1)) {
			ha->response_out = 0;
			ha->response_ptr = ha->response_ring;
		} else {
			ha->response_out++;
			ha->response_ptr++;
		}

		/* process entry */
		switch (sts_entry->hdr.entry_type) {
		case ET_STATUS:
			/* Common status */
			qla4xxx_status_entry(ha, sts_entry);
			break;

		case ET_ASYNC_ISCSI_PDU:
			apdu = (struct async_pdu_iocb *)sts_entry;
			if (apdu->status != ASYNC_PDU_IOCB_STS_OK)
				break;

			pdu_hdr = (struct iscsi_hdr *)apdu->iscsi_pdu_hdr;
			if (pdu_hdr->hlength || pdu_hdr->dlength[0] ||
			    pdu_hdr->dlength[1] || pdu_hdr->dlength[2]) {
				apdu_iocb = kmalloc(
				    sizeof(struct async_msg_pdu_iocb),
				    GFP_ATOMIC);
				if (apdu_iocb) {
					memcpy(apdu_iocb->iocb, apdu,
					    sizeof(struct async_pdu_iocb));
					list_add_tail(&apdu_iocb->list,
					    &ha->async_iocb_list);
					DEBUG2(ql4_info(ha, "%s: schedule async "
						"msg pdu\n", __func__));
					set_bit(DPC_ASYNC_ISCSI_PDU,
					    &ha->dpc_flags);
				} else {
					DEBUG2(ql4_info(ha, "%s: unable to "
					    "alloc ASYNC PDU\n", __func__));
				}
			}
			break;

		case ET_STATUS_CONTINUATION:
			qla4xxx_status_cont_entry(ha,
					(struct status_cont_entry *) sts_entry);
			break;

		case ET_COMMAND:
			/* ISP device queue is full. Command not
			 * accepted by ISP.  Queue command for
			 * later */

			srb = qla4xxx_del_from_active_array(ha,
						    le32_to_cpu(sts_entry->
								handle));
			if (srb == NULL)
				goto exit_prq_invalid_handle;

			DEBUG2(ql4_info(ha, "%s: FW device queue full, "
				      "srb %p\n", __func__, srb));

			/* ETRY normally by sending it back with
			 * DID_BUS_BUSY */
			srb->cmd->result = DID_BUS_BUSY << 16;
			kref_put(&srb->srb_ref, qla4xxx_srb_compl);
			break;

		case ET_CONTINUE:
			/* Just throw away the continuation entries */
			DEBUG2(ql4_info(ha, "%s: Continuation entry - "
				      "ignoring\n", __func__));
			break;

		default:
			/*
			 * Invalid entry in response queue, reset RISC
			 * firmware.
			 */
			DEBUG2(ql4_info(ha, "%s: Invalid entry %x in "
				      "response queue \n", __func__,
				      sts_entry->hdr.entry_type));
			goto exit_prq_error;
		}
		((struct response *)sts_entry)->signature = RESPONSE_PROCESSED;
		wmb();
	}

	/*
	 * Tell ISP we're done with response(s). This also clears the interrupt.
	 */
	ha->isp_ops->complete_iocb(ha);

	return;

exit_prq_invalid_handle:
	DEBUG2(ql4_info(ha, "%s: Invalid handle(srb)=%p type=%x IOCS=%x\n",
		      __func__, srb, sts_entry->hdr.entry_type,
		      sts_entry->completionStatus));

exit_prq_error:
	ha->isp_ops->complete_iocb(ha);
	set_bit(DPC_RESET_HA, &ha->dpc_flags);
}

/**
 * qla4xxx_isr_decode_mailbox - decodes mailbox status
 * @ha: Pointer to host adapter structure.
 * @mailbox_status: Mailbox status.
 *
 * This routine decodes the mailbox status during the ISR.
 * Hardware_lock locked upon entry. runs in interrupt context.
 **/
static void qla4xxx_isr_decode_mailbox(struct scsi_qla_host * ha,
				       uint32_t mbox_status)
{
	int i;
	uint32_t mbox_sts[MBOX_REG_COUNT];

	if ((mbox_status == MBOX_STS_BUSY) ||
	    (mbox_status == MBOX_STS_INTERMEDIATE_COMPLETION) ||
	    (mbox_status >> 12 == MBOX_COMPLETION_STATUS)) {
		ha->mbox_status[0] = mbox_status;

		if (test_bit(AF_MBOX_COMMAND, &ha->flags)) {
			/*
			 * Copy all mailbox registers to a temporary
			 * location and set mailbox command done flag
			 */
			for (i = 0; i < ha->mbox_status_count; i++)
				ha->mbox_status[i] = is_qla8022(ha)
				    ? readl(&ha->qla4_8xxx_reg->mailbox_out[i])
				    : readl(&ha->reg->mailbox[i]);

			set_bit(AF_MBOX_COMMAND_DONE, &ha->flags);

			if (test_bit(AF_MBOX_COMMAND_NOPOLL, &ha->flags))
				complete(&ha->mbx_intr_comp);
		}
	} else if (mbox_status >> 12 == MBOX_ASYNC_EVENT_STATUS) {
		for (i = 0; i < MBOX_REG_COUNT; i++)
			mbox_sts[i] = is_qla8022(ha)
			    ? readl(&ha->qla4_8xxx_reg->mailbox_out[i])
			    : readl(&ha->reg->mailbox[i]);

		/* Queue all AENs into internal AEN database.  The driver will
		 * report AEN information to Application layer when requested.*/
		qla4xxx_queue_aen_log(ha, &mbox_sts[0]);

		switch (mbox_status) {
		case MBOX_ASTS_SYSTEM_ERROR:
			ql4_info(ha, "%s: System Err\n", __func__);
			qla4xxx_dump_registers(ha);

			/* Log Mailbox registers */
			ql4_info(ha, "%s: System Err\n", __func__);
			if (ql4xdontresethba) {
				DEBUG2(ql4_info(ha, "%s:Don't Reset HBA\n",
				    __func__));
			} else if (is_qla4022(ha) || is_qla4032(ha)) {
				set_bit(AF_GET_CRASH_RECORD, &ha->flags);
				set_bit(DPC_RESET_HA, &ha->dpc_flags);
			}
			/* For ISP8xxx we rely on PEG_ALIVE_COUNTER
			 * to set the flags to reset the chip
			 */
			break;

		case MBOX_ASTS_REQUEST_TRANSFER_ERROR:
		case MBOX_ASTS_RESPONSE_TRANSFER_ERROR:
		case MBOX_ASTS_NVRAM_INVALID:
		case MBOX_ASTS_IP_ADDRESS_CHANGED:
		case MBOX_ASTS_DHCP_LEASE_EXPIRED:
			DEBUG2(ql4_info(ha, "AEN %04x, ERROR Status, "
				      "Reset HA\n", mbox_status));
			if (is_qla8022(ha))
				set_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
			else
				set_bit(DPC_RESET_HA, &ha->dpc_flags);
			break;

		case MBOX_ASTS_LINK_UP:
			set_bit(AF_LINK_UP, &ha->flags);
			if (test_bit(AF_INIT_DONE, &ha->flags))
				set_bit(DPC_LINK_CHANGED, &ha->dpc_flags);

			ql4_info(ha, "%s: LINK UP\n", __func__);
			break;

		case MBOX_ASTS_LINK_DOWN:
			clear_bit(AF_LINK_UP, &ha->flags);
			if (test_bit(AF_INIT_DONE, &ha->flags))
				set_bit(DPC_LINK_CHANGED, &ha->dpc_flags);

			ql4_info(ha, "%s: LINK DOWN\n", __func__);
			break;

		case MBOX_ASTS_HEARTBEAT:
			ha->seconds_since_last_heartbeat = 0;
			break;

		case MBOX_ASTS_DHCP_LEASE_ACQUIRED:
			DEBUG2(ql4_info(ha, "AEN %04x DHCP LEASE "
				      "ACQUIRED\n", mbox_status));
			set_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags);
			break;

		case MBOX_ASTS_PROTOCOL_STATISTIC_ALARM:
		case MBOX_ASTS_SCSI_COMMAND_PDU_REJECTED: /* Target
							   * mode
							   * only */
		case MBOX_ASTS_UNSOLICITED_PDU_RECEIVED:  /* Connection mode */
		case MBOX_ASTS_IPSEC_SYSTEM_FATAL_ERROR:
		case MBOX_ASTS_SUBNET_STATE_CHANGE:
		case MBOX_ASTS_DUPLICATE_IP:
			/* No action */
			DEBUG2(ql4_info(ha, "AEN %04x\n", mbox_status));
			break;

		case MBOX_ASTS_IP_ADDR_STATE_CHANGED:
			DEBUG2(ql4_info(ha, "AEN %04x, mbox_sts[2]=%04x, "
			    "mbox_sts[3]=%04x, mbox_sts[4]=%04x\n",
			    mbox_sts[0],
			    mbox_sts[2], mbox_sts[3], mbox_sts[4]));

			if (test_bit(ISNS_FLAG_ISNS_ENABLED_IN_ISP,
			    &ha->isns.flags) &&
			    !test_bit(ISNS_FLAG_DISABLE_IN_PROGRESS,
					&ha->isns.flags)) {
				ql4_isns_process_ip_state_chg(ha, &mbox_sts[0]);
			}

			/* mbox_sts[2] = Old ACB state
			 * mbox_sts[3] = new ACB state */
			if ((mbox_sts[3] == ACB_STATE_VALID) &&
			    (mbox_sts[2] == ACB_STATE_TENTATIVE ||
			     mbox_sts[2] == ACB_STATE_ACQUIRING))
				set_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags);
			else if ((mbox_sts[3] == ACB_STATE_ACQUIRING) &&
			    (mbox_sts[2] == ACB_STATE_VALID)) {
				if (is_qla8022(ha))
					set_bit(DPC_RESET_HA_FW_CONTEXT, &ha->dpc_flags);
				else
					set_bit(DPC_RESET_HA, &ha->dpc_flags);
			}
			break;

		case MBOX_ASTS_MAC_ADDRESS_CHANGED:
		case MBOX_ASTS_DNS:
			/* No action */
			DEBUG2(ql4_info(ha, "AEN %04x, "
				      "mbox_sts[1]=%04x, mbox_sts[2]=%04x\n",
				      mbox_sts[0], mbox_sts[1], mbox_sts[2]));
			break;

		case MBOX_ASTS_SELF_TEST_FAILED:
		case MBOX_ASTS_LOGIN_FAILED:
			/* No action */
			DEBUG2(ql4_info(ha, "AEN %04x, mbox_sts[1]=%04x, "
				      "mbox_sts[2]=%04x, mbox_sts[3]=%04x\n",
				      mbox_sts[0], mbox_sts[1], mbox_sts[2],
				      mbox_sts[3]));
			break;

		case MBOX_ASTS_DATABASE_CHANGED:
		case MBOX_ASTS_ISNS:
			/* Advance pointers for next entry */
			ha->aen_in++;
			if (ha->aen_in == MAX_AEN_ENTRIES)
				ha->aen_in = 0;

			/* copy aen information to local structure */
                        for (i = 0; i < MBOX_AEN_REG_COUNT; i++)
                                ha->aen_q[ha->aen_in].mbox_sts[i] =
                                        mbox_sts[i];

			/* The DPC routine will process the aen */
			set_bit(DPC_AEN, &ha->dpc_flags);

			DEBUG2(ql4_info(ha, "scsi%ld: AEN[%d] %04x,"
				"mbox_sts[1]=%04x, mbox_sts[2]=%04x, "
				"mbox_sts[3]=%04x, mbox_sts[4]=%04x, "
				"mbox_sts[5]=%04x, mbox_sts[6]=%04x\n",
				ha->host_no, ha->aen_in, mbox_sts[0],
				mbox_sts[1], mbox_sts[2], mbox_sts[3],
				mbox_sts[4], mbox_sts[5], mbox_sts[6]));
			break;

		case MBOX_ASTS_SOCKET_IOCB:
			DEBUG2(ql4_warn(ha, "AEN %04x, mbox_sts[1]=%04x, "
				"mbox_sts[2]=%04x, mbox_sts[3]=%04x\n",
				mbox_sts[0], mbox_sts[1], mbox_sts[2],
				mbox_sts[3]));

		case MBOX_ASTS_TXSCVR_INSERTED:
			DEBUG2(ql4_warn(ha, "AEN %04x Transceiver inserted\n",
					mbox_sts[0]));
			break;

		case MBOX_ASTS_TXSCVR_REMOVED:
			DEBUG2(ql4_warn(ha, "AEN %04x Transceiver"
					" removed\n", mbox_sts[0]));
			break;

		default:
			DEBUG2(ql4_warn(ha, "AEN %04x UNKNOWN\n", mbox_sts[0]));
			break;
		}
	} else {
		DEBUG2(ql4_info(ha, "Unknown mailbox status %08X\n",
			      mbox_status));

		ha->mbox_status[0] = mbox_status;
	}
}

/**
 * qla4_8xxx_interrupt_service_routine - isr
 * @ha: pointer to host adapter structure.
 *
 * This is the main interrupt service routine.
 * hardware_lock locked upon entry. runs in interrupt context.
 **/
void qla4_8xxx_interrupt_service_routine(struct scsi_qla_host *ha,
    uint32_t intr_status)
{
	/* Process response queue interrupt. */
	if (intr_status & HSRX_RISC_IOCB_INT)
		qla4xxx_process_response_queue(ha);

	/* Process mailbox/asynch event interrupt.*/
	if (intr_status & HSRX_RISC_MB_INT)
		qla4xxx_isr_decode_mailbox(ha,
		    readl(&ha->qla4_8xxx_reg->mailbox_out[0]));

	/* clear the interrupt */
	writel(0, &ha->qla4_8xxx_reg->host_int);
	readl(&ha->qla4_8xxx_reg->host_int);
}

/**
 * qla4xxx_interrupt_service_routine - isr
 * @ha: pointer to host adapter structure.
 *
 * This is the main interrupt service routine.
 * hardware_lock locked upon entry. runs in interrupt context.
 **/
void qla4xxx_interrupt_service_routine(struct scsi_qla_host * ha,
				       uint32_t intr_status)
{
	/* Process response queue interrupt. */
	if (intr_status & CSR_SCSI_COMPLETION_INTR)
		qla4xxx_process_response_queue(ha);

	/* Process mailbox/asynch event	 interrupt.*/
	if (intr_status & CSR_SCSI_PROCESSOR_INTR) {
		qla4xxx_isr_decode_mailbox(ha,
					   readl(&ha->reg->mailbox[0]));

		/* Clear Mailbox Interrupt */
		writel(set_rmask(CSR_SCSI_PROCESSOR_INTR),
		       &ha->reg->ctrl_status);
		readl(&ha->reg->ctrl_status);
	}
}

/**
 * qla4_8xxx_spurious_interrupt - processes spurious interrupt
 * @ha: pointer to host adapter structure.
 * @reqs_count: .
 *
 **/
static void qla4_8xxx_spurious_interrupt(struct scsi_qla_host *ha,
    uint8_t reqs_count)
{
	if (reqs_count)
		return;

	DEBUG2(ql4_info(ha, "Spurious Interrupt\n"));
	if (is_qla8022(ha)) {
		writel(0, &ha->qla4_8xxx_reg->host_int);
		if (test_bit(AF_INTx_ENABLED, &ha->flags))
			qla4_8xxx_wr_32(ha, ha->nx_legacy_intr.tgt_mask_reg,
			    0xfbff);
	}
	ha->spurious_int_count++;
}

/**
 * qla4xxx_intr_handler - hardware interrupt handler.
 * @irq: Unused
 * @dev_id: Pointer to host adapter structure
 **/
irqreturn_t qla4xxx_intr_handler(int irq, void *dev_id)
{
	struct scsi_qla_host *ha;
	uint32_t intr_status;
	unsigned long flags = 0;
	uint8_t reqs_count = 0;

	ha = (struct scsi_qla_host *) dev_id;
	if (!ha) {
		DEBUG2(ql4_info(ha,
			      "qla4xxx: Interrupt with NULL host ptr\n"));
		return IRQ_NONE;
	}

	spin_lock_irqsave(&ha->hardware_lock, flags);

	ha->isr_count++;
	/*
	 * Repeatedly service interrupts up to a maximum of
	 * MAX_REQS_SERVICED_PER_INTR
	 */
	while (1) {
		/*
		 * Read interrupt status
		 */
		if (ha->isp_ops->rd_shdw_rsp_q_in(ha) !=
		    ha->response_out)
			intr_status = CSR_SCSI_COMPLETION_INTR;
		else
			intr_status = readl(&ha->reg->ctrl_status);

		if ((intr_status &
		    (CSR_SCSI_RESET_INTR|CSR_FATAL_ERROR|INTR_PENDING)) == 0) {
			if (reqs_count == 0)
				ha->spurious_int_count++;
			break;
		}

		if (intr_status & CSR_FATAL_ERROR) {
			DEBUG2(ql4_info(ha, "Fatal Error, Status 0x%04x\n",
				      readl(isp_port_error_status (ha))));

			/* Issue Soft Reset to clear this error condition.
			 * This will prevent the RISC from repeatedly
			 * interrupting the driver; thus, allowing the DPC to
			 * get scheduled to continue error recovery.
			 * NOTE: Disabling RISC interrupts does not work in
			 * this case, as CSR_FATAL_ERROR overrides
			 * CSR_SCSI_INTR_ENABLE */
			if ((readl(&ha->reg->ctrl_status) &
			     CSR_SCSI_RESET_INTR) == 0) {
				writel(set_rmask(CSR_SOFT_RESET),
				       &ha->reg->ctrl_status);
				readl(&ha->reg->ctrl_status);
			}

			writel(set_rmask(CSR_FATAL_ERROR),
			       &ha->reg->ctrl_status);
			readl(&ha->reg->ctrl_status);

			__qla4xxx_disable_intrs(ha);

			set_bit(DPC_RESET_HA, &ha->dpc_flags);

			break;
		} else if (intr_status & CSR_SCSI_RESET_INTR) {
			clear_bit(AF_ONLINE, &ha->flags);
			ql4_info(ha,"%s: Adapter OFFLINE\n", __func__);
			__qla4xxx_disable_intrs(ha);

			writel(set_rmask(CSR_SCSI_RESET_INTR),
			       &ha->reg->ctrl_status);
			readl(&ha->reg->ctrl_status);

			if (!test_bit(AF_HA_REMOVAL, &ha->flags))
				set_bit(DPC_RESET_HA_INTR, &ha->dpc_flags);

			break;
		} else if (intr_status & INTR_PENDING) {
			ha->isp_ops->interrupt_service_routine(ha, intr_status);
			ha->total_io_count++;
			if (++reqs_count == MAX_REQS_SERVICED_PER_INTR)
				break;
		}
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return IRQ_HANDLED;
}

/**
 * qla4_8xxx_intr_handler - hardware interrupt handler.
 * @irq: Unused
 * @dev_id: Pointer to host adapter structure
 **/
irqreturn_t qla4_8xxx_intr_handler(int irq, void *dev_id)
{
	struct scsi_qla_host *ha = dev_id;
	uint32_t intr_status = 0;
	uint32_t status;
	unsigned long flags = 0;
	uint8_t reqs_count = 0;

	if (unlikely(pci_channel_offline(ha->pdev)))
		return IRQ_HANDLED;

	ha->isr_count++;
	status = qla4_8xxx_rd_32(ha, ISR_INT_VECTOR);
	if (!(status & ha->nx_legacy_intr.int_vec_bit))
		return IRQ_NONE;

	status = qla4_8xxx_rd_32(ha, ISR_INT_STATE_REG);
	if (!ISR_IS_LEGACY_INTR_TRIGGERED(status)) {
		DEBUG2(ql4_info(ha,
		    "%s legacy Int not triggered\n", __func__));
		return IRQ_NONE;
	}

	/* clear the interrupt */
	qla4_8xxx_wr_32(ha, ha->nx_legacy_intr.tgt_status_reg, 0xffffffff);

	/* read twice to ensure write is flushed */
	qla4_8xxx_rd_32(ha, ISR_INT_VECTOR);
	qla4_8xxx_rd_32(ha, ISR_INT_VECTOR);

	spin_lock_irqsave(&ha->hardware_lock, flags);
	while (1) {
		if (!(readl(&ha->qla4_8xxx_reg->host_int) &
		    ISRX_82XX_RISC_INT)) {
			qla4_8xxx_spurious_interrupt(ha, reqs_count);
			break;
		}
		intr_status =  readl(&ha->qla4_8xxx_reg->host_status);
		if ((intr_status &
		    (HSRX_RISC_MB_INT | HSRX_RISC_IOCB_INT)) == 0)  {
			qla4_8xxx_spurious_interrupt(ha, reqs_count);
			break;
		}

		ha->isp_ops->interrupt_service_routine(ha, intr_status);

		/* Enable Interrupt */
		qla4_8xxx_wr_32(ha, ha->nx_legacy_intr.tgt_mask_reg, 0xfbff);

		if (++reqs_count == MAX_REQS_SERVICED_PER_INTR)
			break;
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (!irq && (test_bit(AF_EEH_BUSY, &ha->flags))) {
		DEBUG2(ql4_info(ha, "%s: status %x, intr_status"
			" %x\n", __func__, status, intr_status));
	}

	return IRQ_HANDLED;
}

irqreturn_t
qla4_8xxx_msi_handler(int irq, void *dev_id)
{
	struct scsi_qla_host *ha;

	ha = (struct scsi_qla_host *) dev_id;
	if (!ha) {
		DEBUG2(ql4_info(ha, "qla4xxx: MSIX: Interrupt with NULL host "
				" ptr\n"));
		return IRQ_NONE;
	}

	ha->isr_count++;
	/* clear the interrupt */
	qla4_8xxx_wr_32(ha, ha->nx_legacy_intr.tgt_status_reg, 0xffffffff);

	/* read twice to ensure write is flushed */
	qla4_8xxx_rd_32(ha, ISR_INT_VECTOR);
	qla4_8xxx_rd_32(ha, ISR_INT_VECTOR);

	return qla4_8xxx_default_intr_handler(irq, dev_id);
}

/**
 * qla4_8xxx_default_intr_handler - hardware interrupt handler.
 * @irq: Unused
 * @dev_id: Pointer to host adapter structure
 *
 * This interrupt handler is called directly for MSI-X, and
 * called indirectly for MSI.
 **/
irqreturn_t
qla4_8xxx_default_intr_handler(int irq, void *dev_id)
{
	struct scsi_qla_host *ha = dev_id;
	unsigned long   flags;
	uint32_t intr_status;
	uint8_t reqs_count = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	while (1) {
		if (!(readl(&ha->qla4_8xxx_reg->host_int) &
		    ISRX_82XX_RISC_INT)) {
			qla4_8xxx_spurious_interrupt(ha, reqs_count);
			break;
		}

		intr_status =  readl(&ha->qla4_8xxx_reg->host_status);
		if ((intr_status &
		    (HSRX_RISC_MB_INT | HSRX_RISC_IOCB_INT)) == 0) {
			qla4_8xxx_spurious_interrupt(ha, reqs_count);
			break;
		}

		ha->isp_ops->interrupt_service_routine(ha, intr_status);

		if (++reqs_count == MAX_REQS_SERVICED_PER_INTR)
			break;
	}

	ha->isr_count++;
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	return IRQ_HANDLED;
}

irqreturn_t
qla4_8xxx_msix_rsp_q(int irq, void *dev_id)
{
	struct scsi_qla_host *ha = dev_id;
	unsigned long flags;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	qla4xxx_process_response_queue(ha);
	writel(0, &ha->qla4_8xxx_reg->host_int);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	ha->isr_count++;
	return IRQ_HANDLED;
}

/**
 * qla4xxx_process_aen - processes AENs generated by firmware
 * @ha: pointer to host adapter structure.
 * @process_aen: type of AENs to process
 *
 * Processes specific types of Asynchronous Events generated by firmware.
 * The type of AENs to process is specified by process_aen and can be
 *	PROCESS_ALL_AENS	 0
 *	FLUSH_DDB_CHANGED_AENS	 1
 **/
void qla4xxx_process_aen(struct scsi_qla_host * ha, uint8_t process_aen)
{
	uint32_t mbox_sts[MBOX_AEN_REG_COUNT];
	struct aen *aen;
	int i;
	unsigned long flags;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	while (ha->aen_out != ha->aen_in) {
		/* Advance pointers for next entry */
		ha->aen_out++;
		if (ha->aen_out == MAX_AEN_ENTRIES)
			ha->aen_out = 0;

		/* copy aen information to local structure */
		aen = &ha->aen_q[ha->aen_out];
		for (i = 0; i < MBOX_AEN_REG_COUNT; i++)
			mbox_sts[i] = aen->mbox_sts[i];

		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		switch (mbox_sts[0]) {
		case MBOX_ASTS_ISNS:
			ql4_isns_process_isns_aen(ha, &mbox_sts[0]);
			break;
		case MBOX_ASTS_DATABASE_CHANGED:
			switch(process_aen )  {
			case FLUSH_DDB_CHANGED_AENS:
				DEBUG2(ql4_info(ha, "AEN[%d] %04x, index "
					      "[%d] state=%04x FLUSHED!\n",
					      ha->aen_out, mbox_sts[0],
					      mbox_sts[2], mbox_sts[3]));
				break;
			case PROCESS_ALL_AENS:
			default:
				/* WARNING: Post init only */

				DEBUG2(ql4_info(ha, "AEN[%d] %04x %s: "
					"mb1:0x%04x mb2:0x%04x mb3:0x%04x "
					"mb4:0x%08x ddb 0x%p\n",
					ha->aen_out, mbox_sts[0], __func__,
					mbox_sts[1], mbox_sts[2], mbox_sts[3],
					mbox_sts[4],
					qla4xxx_lookup_ddb_by_fw_index(ha,
					mbox_sts[2])));

				if (mbox_sts[1] == 0) {
					/* Global DB change. */
					qla4xxx_reinitialize_ddb_list(ha);
				} else if (mbox_sts[1] == 1) {
					/* Specific device. */
					qla4xxx_process_ddb_changed(ha,
						mbox_sts[2],
						mbox_sts[3], mbox_sts[4]);
				}
				break;
			} /* switch process_aen */
			break;
		} /* switch mbox_sts[0] */
		spin_lock_irqsave(&ha->hardware_lock, flags);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}

int qla4xxx_request_irqs(struct scsi_qla_host *ha)
{
	int ret;

	if (!is_qla8022(ha) || ql4xenablemsix == 0)
		goto try_intx;

	if (ql4xenablemsix == 2)
		goto try_msi;

	/* Trying MSI-X */
	ret = qla4_8xxx_enable_msix(ha);
	if (!ret) {
		DEBUG2(ql4_info(ha, "MSI-X: Enabled (0x%X).\n",
					ha->revision_id));
		goto irq_attached;
	}

	ql4_warn(ha, "MSI-X: Falling back-to MSI mode -- %d.\n", ret);

try_msi:
	/* Trying MSI */
	ret = pci_enable_msi(ha->pdev);
	if (!ret) {
		ret = request_irq(ha->pdev->irq, qla4_8xxx_msi_handler,
			IRQF_DISABLED, DRIVER_NAME, ha);
		if (!ret) {
			DEBUG2(ql4_info(ha, "MSI: Enabled.\n"));
			set_bit(AF_MSI_ENABLED, &ha->flags);
			goto irq_attached;
		} else {
			ql4_warn(ha, "MSI: Failed to reserve interrupt %d "
			    "already in use.\n", ha->pdev->irq);
			pci_disable_msi(ha->pdev);
		}
	}

	#if MIXED_INTR_MODE_WORKAROUND
	goto irq_not_attached;
	#else
	ql4_warn(ha, "MSI: Falling back-to INTx mode -- %d.\n", ret);
	#endif

try_intx:
	/* Trying INTx */
	ret = request_irq(ha->pdev->irq, ha->isp_ops->intr_handler,
	    IRQF_DISABLED|IRQF_SHARED, DRIVER_NAME, ha);
	if (!ret) {
		DEBUG2(ql4_info(ha, "INTx: Enabled.\n"));
		set_bit(AF_INTx_ENABLED, &ha->flags);
		goto irq_attached;

	} else {
		ql4_warn(ha, "INTx: Failed to reserve interrupt %d already in"
		         " use.\n", ha->pdev->irq);
		goto irq_not_attached;
	}

irq_attached:
	set_bit(AF_IRQ_ATTACHED, &ha->flags);
	ha->host->irq = ha->pdev->irq;
	ql4_info(ha, "IRQ %d attached\n", ha->pdev->irq);
	return ret;

irq_not_attached:
	ql4_warn(ha, "IRQ not attached -- %d.\n", ret);
	return ret;
}

void qla4xxx_free_irqs(struct scsi_qla_host *ha)
{
	if (test_bit(AF_MSIX_ENABLED, &ha->flags))
		qla4_8xxx_disable_msix(ha);
	else if (test_and_clear_bit(AF_MSI_ENABLED, &ha->flags)) {
		free_irq(ha->pdev->irq, ha);
		pci_disable_msi(ha->pdev);
	} else if (test_and_clear_bit(AF_INTx_ENABLED, &ha->flags))
		free_irq(ha->pdev->irq, ha);
}
