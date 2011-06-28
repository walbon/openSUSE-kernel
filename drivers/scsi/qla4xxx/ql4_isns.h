/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2010 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

#ifndef __QL4_ISNS_H
#define __QL4_ISNS_H
#include <linux/dmapool.h>

/* NOTE: ALL PDUs tx in Network Byte Order (NBO) */
struct isnsp_header {
	__u16 ver;	/* 00-01 */
        #define ISNSP_VERSION           	0x0001

	__u16 func_id;	/* 02-03 */
	__u16 pdu_len;	/* 04-05 pdu length does not include header */
	__u16 flags;	/* 06-07 */
	/* The following #defines are in Host Byte Order (HBO),
	 * as all NBO structs are converted to HBO before use */
	#define ISNSP_FLAG_CLIENT_SENDER         0x8000
	#define ISNSP_FLAG_SERVER_SENDER         0x4000
	#define ISNSP_FLAG_AUTH_BLOCK_PRESENT    0x2000
	#define ISNSP_FLAG_REPLACE_FLAG          0x1000 /* for DevAttrReg */
	#define ISNSP_FLAG_LAST_PDU              0x0800
	#define ISNSP_FLAG_FIRST_PDU             0x0400

	__u16 trans_id;	/* 08-09 */
	__u16 seq_id;	/* 0A-0B */
	__u8 payload[0];
};

struct isnsp_message {
	struct isnsp_header hdr;
	__u8 attributes[0];
};

struct isnsp_response {
	struct isnsp_header hdr;
	__u32 status_code;
	__u8  attributes[0];
};

struct isnsp_attribute {
	uint32_t tag;
	uint32_t len;
	__u8  val[0];
};

/* iSNS Attribute Tags */
#define ISNS_ATTR_DELIMITER                     0   /* x00 */
#define ISNS_ATTR_ENTITY_IDENTIFIER             1   /* x01 */
#define ISNS_ATTR_ENTITY_PROTOCOL               2   /* x02 */
#define ISNS_ATTR_MGMT_IP_ADDRESS               3   /* x03 */
#define ISNS_ATTR_TIMESTAMP                     4   /* x04 */
#define ISNS_ATTR_REGISTRATION_PERIOD           6   /* x06 */
#define ISNS_ATTR_PORTAL_IP_ADDRESS             16  /* x10 */
#define ISNS_ATTR_PORTAL_PORT                   17  /* x11 */
#define ISNS_ATTR_PORTAL_SYMBOLIC_NAME          18  /* x12 */
#define ISNS_ATTR_ESI_INTERVAL                  19  /* x13 */
#define ISNS_ATTR_ESI_PORT                      20  /* x14 */
#define ISNS_ATTR_PORTAL_GROUP                  21  /* x15 */
#define ISNS_ATTR_PORTAL_INDEX                  22  /* x16 */
#define ISNS_ATTR_SCN_PORT                      23  /* x17 */
#define ISNS_ATTR_PORTAL_SECURITY_BITMAP	27  /* x1B */
#define ISNS_ATTR_ISCSI_NAME                    32  /* x20 */
#define ISNS_ATTR_ISCSI_NODE_TYPE               33  /* x21 */
#define ISNS_ATTR_ISCSI_ALIAS                   34  /* x22 */
#define ISNS_ATTR_ISCSI_SCN_BITMAP              35  /* x23 */
#define ISNS_ATTR_PG_ISCSI_NAME                 48  /* x30 */
#define ISNS_ATTR_PG_PORTAL_IP_ADDRESS          49  /* x31 */
#define ISNS_ATTR_PG_PORTAL_PORT                50  /* x32 */
#define ISNS_ATTR_PG_TAG                        51  /* x33 */
#define ISNS_ATTR_DD_ID                         2065 /* x811 */

/* iSNS Message Function ID codes */
#define ISNS_FUNC_DevAttrReg      0x0001      /* Device Attribute Registration Request */
#define ISNS_FUNC_DevAttrQry      0x0002      /* Device Attribute Query Request */
#define ISNS_FUNC_DevGetNext      0x0003      /* Device Get Next Request  */
#define ISNS_FUNC_DevDereg        0x0004      /* Device Deregister Request */
#define ISNS_FUNC_SCNReg          0x0005      /* SCN Register Request */
#define ISNS_FUNC_SCNDereg        0x0006      /* SCN Deregister Request */
#define ISNS_FUNC_SCNEvent        0x0007      /* SCN Event */
#define ISNS_FUNC_SCN             0x0008      /* State Change Notification */
#define ISNS_FUNC_ESI             0x000D      /* Entity Status Inquiry  */

/* iSNS Response Function ID codes */
#define ISNS_FUNC_RESPONSE   	  0x8000      /* Response Function ID Mask */
#define ISNS_FUNC_DevAttrRegRsp   0x8001      /* Device Attribute Registration Response */
#define ISNS_FUNC_DevAttrQryRsp   0x8002      /* Device Attribute Query Response */
#define ISNS_FUNC_DevGetNextRsp   0x8003      /* Device Get Next Response */
#define ISNS_FUNC_DevDeregRsp     0x8004      /* Deregister Device Response */
#define ISNS_FUNC_SCNRegRsp       0x8005      /* SCN Register Response */
#define ISNS_FUNC_SCNDeregRsp     0x8006      /* SCN Deregister Response */
#define ISNS_FUNC_SCNEventRsp     0x8007      /* SCN Event Response */
#define ISNS_FUNC_SCNRsp          0x8008      /* SCN Response */
#define ISNS_FUNC_DDRegRsp        0x8009      /* DD Register Response */
#define ISNS_FUNC_DDDeregRsp      0x800A      /* DD Deregister Response */
#define ISNS_FUNC_DDSRegRsp       0x800B      /* DDS Register Response */
#define ISNS_FUNC_DDSDeregRsp     0x800C      /* DDS Deregister Response */
#define ISNS_FUNC_ESIRsp          0x800D      /* Entity Status Inquiry Response */

/* iSNSP Response Status Codes */
#define ISNS_STS_SUCCESS                    0   /* Successful */
#define ISNS_STS_UNKNOWN                    1   /* Unknown Error */
#define ISNS_STS_MSG_FORMAT                 2   /* Message Format Error */
#define ISNS_STS_INVALID_REG                3   /* Invalid Registration */
#define ISNS_STS_INVALID_QUERY              5   /* Invalid Query */
#define ISNS_STS_SOURCE_UNKNOWN             6   /* Source Unknown */
#define ISNS_STS_SOURCE_ABSENT              7   /* Source Absent */
#define ISNS_STS_SOURCE_UNAUTHORIZED        8   /* Source Unauthorized */
#define ISNS_STS_NO_SUCH_ENTRY              9   /* No Such Entry */
#define ISNS_STS_VER_NOT_SUPPORTED          10  /* Version Not Supported */
#define ISNS_STS_INTERNAL_ERROR             11  /* Internal Error */
#define ISNS_STS_BUSY                       12  /* Busy */
#define ISNS_STS_OPT_NOT_UNDERSTOOD         13  /* Option Not Understood */
#define ISNS_STS_INVALID_UPDATE             14  /* Invalid Update */
#define ISNS_STS_MSG_NOT_SUPPORTED          15  /* Message (FUNCTION_ID) Not Supported */
#define ISNS_STS_SCN_EVENT_REJECTED         16  /* SCN Event Rejected */
#define ISNS_STS_SCN_REG_REJECTED           17  /* SCN Registration Rejected */
#define ISNS_STS_ATTR_NOT_IMPLEMENTED       18  /* Attribute Not Implemented */
#define ISNS_STS_FC_DOMAIN_ID_NOT_AVAIL     19  /* FC_DOMAIN_ID Not Available */
#define ISNS_STS_FC_DOMAIN_ID_NOT_ALLOC     20  /* FC_DOMAIN_ID Not Allocated */
#define ISNS_STS_ESI_NOT_AVAILABLE          21  /* ESI Not Available */
#define ISNS_STS_INVALID_DEREG              22  /* Invalid Deregistration */
#define ISNS_STS_REG_FEATURES_NOT_SUPPORTED 23  /* Registration Features Not Supported */

/* iSNS Entity Protocol Type */
#define ISNS_ENTITY_PROTOCOL_TPYE_ISCSI		2

/* iSNS iSCSI Node Type */
#define ISNS_ISCSI_NODE_TYPE_INITIATOR		2

/* iSCSI Node Types */
#define ISCSI_NODE_TYPE_TARGET                  0x00000001
#define ISCSI_NODE_TYPE_INITIATOR               0x00000002
#define ISCSI_NODE_TYPE_CONTROL                 0x00000004

/* iSCSI Node SCN Bitmap */
#define ISCSI_SCN_OBJECT_UPDATED                0x00000004
#define ISCSI_SCN_OBJECT_ADDED                  0x00000008
#define ISCSI_SCN_OBJECT_REMOVED                0x00000010
#define ISCSI_SCN_TARGET_AND_SELF_INFO_ONLY     0x00000040

/* Structure used for printing string values */
struct prn_str_tbl
{
	int val;
	const char *s;
};

/*
 * Driver defined fields used for iSNS Passthru handle
 */
#define IOCB_ISNS_PT_PDU_TYPE(x)        ((x) & 0x0F000000)
#define IOCB_ISNS_PT_PDU_INDEX(x)       ((x) & (MAX_PDU_ENTRIES-1))

#define ISNS_ASYNC_REQ_PDU              0x01000000 /* Request Data from
						      ASYNC PDU */
#define ISNS_ASYNC_RSP_PDU              0x02000000
#define ISNS_REQ_RSP_PDU                0x03000000

/* Pseudo DDB index for Passthru */
#define ISNS_DEVICE_INDEX               MAX_DEV_DB_ENTRIES

/* The default iSNS Connection ID is used to allow the firmware to
 * automatically reopen the connection after an iSNS server FIN has occurred.
 * Only PDUs generated by our driver use the default iSNS Connection ID,
 * PDUs generated by the iSNS server use different Connection IDs. */
#define ISNS_DEFAULT_SERVER_CONN_ID     ((uint16_t)0x8000)

/* iSNS PDU Request Block - local structure used to send and receive PDUs */
struct isns_prb {
	struct list_head list;

	/* Ptrs to PDU buffer */
	dma_addr_t pdu_dma;
	__u8 *pdu;

	/* Ptrs to IOCB struct */
	dma_addr_t pkt_dma;
	__u8 *pkt;

	/* Ptrs needed to return isns tgt query info back to caller */
	__u8 *tgt_qry_iscsi_name;
	__u8 *tgt_qry_buf;
	__u32 *tgt_qry_buf_len;

	/* Offset to indicate the end of the pdu data received.
	 * Used to solicit remainder of PDU */
	__u32 offset;

	/* Length of allocated PDU buffer */
	__u32 pdu_buf_len;

	/* Stored variables used to build passthsu IOCB */
	__u32 tx_len;
	__u32 rx_len;
	__u32 handle;

	/* Cached variables from sts_entry */
	__u32 in_residual; /* over/underrun amt based on resid_flags */
	__u16 conn_id;
	__u8  resid_flags; /* see passthsu_status struct for definition */

	/* Housekeeping variable to indicate this prb is being used */
	__u8 prb_in_use;
	__u8 resvd[8]; /* pad for structure alignment */
};

struct isns {
	unsigned long   flags;

	/* The ISNS_FLAG_ISNS_ENABLED_IN_ISP flag is set when iSNS
	 * is enabled in the firmware.  This flag is used as a shortcut to
	 * minimize having to check both ipv4 and ipv6 tcp options in the ifcb
	 * at multiple places in the code. */
	#define ISNS_FLAG_ISNS_ENABLED_IN_ISP   0  /* 0x00000001 */

	/* The ISNS_FLAG_DISABLE_IN_PROGRESS flag is set in the IOCTL Module
	 * to indicate that iSNS is being disabled by the user.
	 * Since the MBOX_ASTS_IP_ADDR_STATE_CHANGED AEN can occur
	 * simultaneously and attempt to start the iSNS server,
	 * the ISNS_FLAG_DISABLE_IN_PROGRESS flag is checked multiple
	 * places in the MBOX_ASTS_IP_ADDR_STATE_CHANGED path. */
	#define ISNS_FLAG_DISABLE_IN_PROGRESS   1  /* 0x00000002 */

	/* The ISNS_FLAG_ISNS_SRV_REGISTERED flag is set to indicate that
	 * the driver has registered the initiator with the iSNS server
	 * (DevAttrReg)*/
	#define ISNS_FLAG_ISNS_SRV_REGISTERED   2  /* 0x00000004 */

	/* The ISNS_FLAG_ISNS_SCN_REGISTERED flag is set to indicate that
	 * the driver has registered for State Change Notification (SCN)
	 * messages from the iSNS server (SCNReg)*/
	#define ISNS_FLAG_ISNS_SCN_REGISTERED   4  /* 0x00000010 */

	/* The ISNS_FLAG_SRV_DEREG_IN_PROGRESS flag is set to indicate that
	 * the driver is in the process of de-registering with the iSNS
	 * server (DevDereg).  This flag is used to wait until the de-
	 * registration process has completed (i.e. DevDeregRsp received)*/
	#define ISNS_FLAG_SRV_DEREG_IN_PROGRESS 6  /* 0x00000040 */

	/* The ISNS_FLAG_IOCTL_INVOKED_QUERY flag is used to communicate to
	 * the IOCTL module that (DevGetNext & DevAttrQry) iSNS transactions
	 * have completed.  This flag is set in the IOCTL module and cleared
	 * in the driver*/
	#define ISNS_FLAG_IOCTL_INVOKED_QUERY   8  /* 0x00000100 */

	/* State of iSNS Server connection */
	atomic_t   	state;
	#define ISNS_STATE_TCP_DISCONNECTED 	0
	#define ISNS_STATE_TCP_CONNECTED   	1
	#define ISNS_STATE_STARTING_SRV   	2
	#define ISNS_STATE_RESTART_SRV_WAIT   	3

	/* Timer used to restart the iSNS server */
	atomic_t restart_timer;
	#define ISNS_RESTART_SVR_TOV	5 	/* almost immediate restart */
	#define ISNS_POLL_SVR_TOV	60	/* polling interval */

	/* Variables used to monitor ESI timer functionality */
	atomic_t esi_timer;
	__u32    esi_interval;

	/* Lock to protect prb structure */
	struct mutex  prb_lock;

	/* List containing received PDUs (Async and Response Msg),
	 * where processing is delayed to DPC */
	struct list_head rcvd_pdu_list;

	/* Cached iSNS Server connection info */
	__u16 esi_port;
	__u16 scn_port;
	__u16 source_port;
	__u16 server_port;

	/* Driver generated transaction ID (unique per transaction) */
	__u16 trans_id;

	__u16 resvd1;
	__u8  resvd2;

	/* PDU Housekeeping variables */
	__u8 curr_pdu;
	__u8 active_pdus;

	/* More cached iSNS Server connection info */
	__u8  source_ip_index;
	__u8  source_ip[16];
	__u8  server_ip[16];
	__u8  entity_id[256];

	/* Array of prb structures, used to store all information related to
	 * iSNS PDU transactions */
	struct isns_prb prb_array[MAX_PDU_ENTRIES];
};

#endif /* QL4_ISNS_H */
