/*
 *	SGI UltraViolet TLB flush routines.
 *
 *	(c) 2008-2010 Cliff Wickman <cpw@sgi.com>, SGI.
 *
 *	This code is released under the GNU General Public License version 2 or
 *	later.
 */
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>

#include <asm/mmu_context.h>
#include <asm/uv/uv.h>
#include <asm/uv/uv_mmrs.h>
#include <asm/uv/uv_hub.h>
#include <asm/uv/uv_bau.h>
#include <asm/apic.h>
#include <asm/idle.h>
#include <asm/tsc.h>
#include <asm/irq_vectors.h>
#include <asm/timer.h>

#define UV_INTD_SOFT_ACK_TIMEOUT_PERIOD	0x000000000bUL

static int uv_bau_max_concurrent __read_mostly;

static int nobau;
static int __init setup_nobau(char *arg)
{
	nobau = 1;
	return 0;
}
early_param("nobau", setup_nobau);

/* base pnode in this partition */
static int uv_partition_base_pnode __read_mostly;
/* position of pnode (which is nasid>>1): */
static int uv_nshift __read_mostly;
static unsigned long uv_mmask __read_mostly;

static DEFINE_PER_CPU(struct ptc_stats, ptcstats);
static DEFINE_PER_CPU(struct bau_control, bau_control);
static DEFINE_PER_CPU(cpumask_var_t, uv_flush_tlb_mask);

struct reset_args {
	int sender;
};

/*
 * Determine the first node on a blade.
 */
static int __init blade_to_first_node(int blade)
{
	int node, b;

	for_each_online_node(node) {
		b = uv_node_to_blade_id(node);
		if (blade == b)
			return node;
	}
	return -1;
}

/*
 * Determine the apicid of the first cpu on a blade.
 */
static int __init blade_to_first_apicid(int blade)
{
	int cpu;

	for_each_present_cpu(cpu)
		if (blade == uv_cpu_to_blade_id(cpu))
			return per_cpu(x86_cpu_to_apicid, cpu);
	return -1;
}

/*
 * Free a software acknowledge hardware resource by clearing its Pending
 * bit. This will return a reply to the sender.
 * If the message has timed out, a reply has already been sent by the
 * hardware but the resource has not been released. In that case our
 * clear of the Timeout bit (as well) will free the resource. No reply will
 * be sent (the hardware will only do one reply per message).
 */
static inline void uv_reply_to_message(int msg_slot, int resource,
		struct bau_payload_queue_entry *msg,
		struct bau_control *bcp)
{
	unsigned long dw;

	dw = (msg->sw_ack_vector << UV_SW_ACK_NPENDING) | msg->sw_ack_vector;
	msg->replied_to = 1;
	msg->sw_ack_vector = 0;
	uv_write_local_mmr(UVH_LB_BAU_INTD_SOFTWARE_ACKNOWLEDGE_ALIAS, dw);
}

/*
 * Do all the things a cpu should do for a TLB shootdown message.
 * Other cpu's may come here at the same time for this message.
 */
static void uv_bau_process_message(struct bau_payload_queue_entry *msg,
			int msg_slot, int sw_ack_slot, struct bau_control *bcp,
			struct bau_payload_queue_entry *va_queue_first,
			struct bau_payload_queue_entry *va_queue_last)
{
	int i;
	int sending_cpu;
	int msg_ack_count;
	int slot2;
	int cancel_count = 0;
	unsigned char this_sw_ack_vector;
	short socket_ack_count = 0;
	unsigned long mmr = 0;
	unsigned long msg_res;
	struct ptc_stats *stat;
	struct bau_payload_queue_entry *msg2;
	struct bau_control *smaster = bcp->socket_master;

	/*
	 * This must be a normal message, or retry of a normal message
	 */
	stat = &per_cpu(ptcstats, bcp->cpu);
	if (msg->address == TLB_FLUSH_ALL) {
		local_flush_tlb();
		stat->d_alltlb++;
	} else {
		__flush_tlb_one(msg->address);
		stat->d_onetlb++;
	}
	stat->d_requestee++;

	/*
	 * One cpu on each blade has the additional job on a RETRY
	 * of releasing the resource held by the message that is
	 * being retried.  That message is identified by sending
	 * cpu number.
	 */
	if (msg->msg_type == MSG_RETRY && bcp == bcp->pnode_master) {
		sending_cpu = msg->sending_cpu;
		this_sw_ack_vector = msg->sw_ack_vector;
		stat->d_retries++;
		/*
		 * cancel any from msg+1 to the retry itself
		 */
		bcp->retry_message_scans++;
		for (msg2 = msg+1, i = 0; i < DEST_Q_SIZE; msg2++, i++) {
			if (msg2 > va_queue_last)
				msg2 = va_queue_first;
			if (msg2 == msg)
				break;

			/* uv_bau_process_message: same conditions
			   for cancellation as uv_do_reset */
			if ((msg2->replied_to == 0) &&
			    (msg2->canceled == 0) &&
			    (msg2->sw_ack_vector) &&
			    ((msg2->sw_ack_vector &
				this_sw_ack_vector) == 0) &&
			    (msg2->sending_cpu == sending_cpu) &&
			    (msg2->msg_type != MSG_NOOP)) {
				bcp->retry_message_actions++;
				slot2 = msg2 - va_queue_first;
				mmr = uv_read_local_mmr
				(UVH_LB_BAU_INTD_SOFTWARE_ACKNOWLEDGE);
				msg_res = ((msg2->sw_ack_vector << 8) |
					   msg2->sw_ack_vector);
				/*
				 * If this message timed out elsewhere
				 * so that a retry was broadcast, it
				 * should have timed out here too.
				 * It is not 'replied_to' so some local
				 * cpu has not seen it.  When it does
				 * get around to processing the
				 * interrupt it should skip it, as
				 * it's going to be marked 'canceled'.
				 */
				msg2->canceled = 1;
				cancel_count++;
				/*
				 * this is a message retry; clear
				 * the resources held by the previous
				 * message or retries even if they did
				 * not time out
				 */
				if (mmr & msg_res) {
					stat->d_canceled++;
					uv_write_local_mmr(
			    UVH_LB_BAU_INTD_SOFTWARE_ACKNOWLEDGE_ALIAS,
						msg_res);
				}
			}
		}
		if (!cancel_count)
			stat->d_nocanceled++;
	}

	/*
	 * This is a sw_ack message, so we have to reply to it.
	 * Count each responding cpu on the socket. This avoids
	 * pinging the count's cache line back and forth between
	 * the sockets.
	 */
	socket_ack_count = atomic_add_short_return(1, (struct atomic_short *)
				&smaster->socket_acknowledge_count[msg_slot]);
	if (socket_ack_count == bcp->cpus_in_socket) {
		/*
		 * Both sockets dump their completed count total into
		 * the message's count.
		 */
		smaster->socket_acknowledge_count[msg_slot] = 0;
		msg_ack_count = atomic_add_short_return(socket_ack_count,
				(struct atomic_short *)&msg->acknowledge_count);

		if (msg_ack_count == bcp->cpus_in_blade) {
			/*
			 * All cpus in blade saw it; reply
			 */
			uv_reply_to_message(msg_slot, sw_ack_slot, msg, bcp);
		}
	}

	return;
}

/*
 * Determine the first cpu on a blade.
 */
static int blade_to_first_cpu(int blade)
{
	int cpu;
	for_each_present_cpu(cpu)
		if (blade == uv_cpu_to_blade_id(cpu))
			return cpu;
	return -1;
}

/*
 * Last resort when we get a large number of destination timeouts is
 * to clear resources held by a given cpu.
 * Do this with IPI so that all messages in the BAU message queue
 * can be identified by their nonzero sw_ack_vector field.
 *
 * This is entered for a single cpu on the blade.
 * The sender want's this blade to free a specific message's
 * sw_ack resources.
 */
static void
uv_do_reset(void *ptr)
{
	int i;
	int slot;
	int count = 0;
	unsigned long mmr;
	unsigned long msg_res;
	struct bau_control *bcp;
	struct reset_args *rap;
	struct bau_payload_queue_entry *msg;
	struct ptc_stats *stat;

	bcp = (struct bau_control *)&per_cpu(bau_control, smp_processor_id());
	rap = (struct reset_args *)ptr;
	stat = &per_cpu(ptcstats, bcp->cpu);
	stat->d_resets++;

	/*
	 * We're looking for the given sender, and
	 * will free its sw_ack resource.
	 * If all cpu's finally responded after the timeout, its
	 * message 'replied_to' was set.
	 */
	for (msg = bcp->va_queue_first, i = 0; i < DEST_Q_SIZE; msg++, i++) {
		/* uv_do_reset: same conditions for cancellation as
		   uv_bau_process_message */
		if ((msg->replied_to == 0) &&
		    (msg->canceled == 0) &&
		    (msg->sending_cpu == rap->sender) &&
		    (msg->sw_ack_vector) &&
		    (msg->msg_type != MSG_NOOP)) {
			/*
			 * make everyone else ignore this message
			 */
			msg->canceled = 1;
			slot = msg - bcp->va_queue_first;
			count++;
			/*
			 * only reset the resource if it is still
			 * pending
			 */
			mmr = uv_read_local_mmr
					(UVH_LB_BAU_INTD_SOFTWARE_ACKNOWLEDGE);
			msg_res = ((msg->sw_ack_vector << 8) |
						   msg->sw_ack_vector);
			/*
			 * this is an ipi-method reset; clear the resources
			 * held by previous message or retries even if they
			 * did not time out
			 */
			if (mmr & msg_res) {
				stat->d_rcanceled++;
				uv_write_local_mmr(
				    UVH_LB_BAU_INTD_SOFTWARE_ACKNOWLEDGE_ALIAS,
							msg_res);
			}
		}
	}
	return;
}

/*
 * Use IPI to get all target pnodes to release resources held by
 * a given sending cpu number.
 */
static void uv_reset_with_ipi(struct bau_target_nodemask *distribution,
		int sender)
{
	int blade;
	int cpu;
	cpumask_t mask;
	struct reset_args reset_args;

	reset_args.sender = sender;

	cpus_clear(mask);
	/* find a single cpu for each blade in this distribution mask */
	for (blade = 0;
		    blade < sizeof(struct bau_target_nodemask) * BITSPERBYTE;
		    blade++) {
		if (!bau_node_isset(blade, distribution))
			continue;
		/* find a cpu for this blade */
		cpu = blade_to_first_cpu(blade);
		cpu_set(cpu, mask);
	}
	/* IPI all cpus; Preemption is already disabled */
	smp_call_function_many(&mask, uv_do_reset, (void *)&reset_args, 1);
	return;
}

/*
 * The UVH_LB_BAU_SB_ACTIVATION_STATUS_0|1 status for this broadcast has
 * stayed busy beyond a sane timeout period.  Quiet BAU activity on this
 * blade and reset the status to idle.
 */
static void
uv_reset_busy(struct bau_control *bcp, unsigned long mmr_offset,
		int right_shift, struct ptc_stats *stat)
{
	short busy;
	struct bau_control *pmaster;
	unsigned long mmr;
	unsigned long mask = 0UL;

	pmaster = bcp->pnode_master;
	atomic_add_short_return(1,
		(struct atomic_short *)&pmaster->pnode_quiesce);
	printk(KERN_INFO "cpu %d bau quiet, reset mmr\n", bcp->cpu);
	while (atomic_read_short(
		(struct atomic_short *)&pmaster->pnode_active_count) >
		atomic_read_short(
		(struct atomic_short *)&pmaster->pnode_quiesce)) {
		cpu_relax();
	}
	spin_lock(&pmaster->quiesce_lock);
	mmr = uv_read_local_mmr(mmr_offset);
	mask |= (3UL < right_shift);
	mask = ~mask;
	mmr &= mask;
	uv_write_local_mmr(mmr_offset, mmr);
	spin_unlock(&pmaster->quiesce_lock);
	atomic_add_short_return(-1,
		(struct atomic_short *)&pmaster->pnode_quiesce);
	stat->s_busy++;
	/* wait for all to finish */
	do {
		busy = atomic_read_short
			((struct atomic_short *)&pmaster->pnode_quiesce);
	} while (busy);
}

/*
 * Wait for completion of a broadcast software ack message
 * return COMPLETE, RETRY or GIVEUP
 */
static int uv_wait_completion(struct bau_desc *bau_desc,
	unsigned long mmr_offset, int right_shift, int this_cpu,
	struct bau_control *bcp, struct bau_control *smaster, long try)
{
	long relaxes = 0;
	long source_timeouts = 0;
	unsigned long descriptor_status;
	unsigned long long otime, ntime;
	unsigned long long timeout_time;
	struct ptc_stats *stat = &per_cpu(ptcstats, this_cpu);

	otime = get_cycles();
	timeout_time = otime + bcp->timeout_interval;

	/* spin on the status MMR, waiting for it to go idle */
	while ((descriptor_status = (((unsigned long)
		uv_read_local_mmr(mmr_offset) >>
			right_shift) & UV_ACT_STATUS_MASK)) !=
			DESC_STATUS_IDLE) {
		/*
		 * Our software ack messages may be blocked because there are
		 * no swack resources available.  As long as none of them
		 * has timed out hardware will NACK our message and its
		 * state will stay IDLE.
		 */
		if (descriptor_status == DESC_STATUS_SOURCE_TIMEOUT) {
			source_timeouts++;
			stat->s_stimeout++;
			if (source_timeouts > SOURCE_TIMEOUT_LIMIT) {
				source_timeouts = 0;
				printk(KERN_INFO
			   "uv_wait_completion dest cpus done; FLUSH_RETRY\n");
			}
			udelay(1000); /*source side timeouts are long*/
			return FLUSH_RETRY;
		} else if (descriptor_status ==
					DESC_STATUS_DESTINATION_TIMEOUT) {
			stat->s_dtimeout++;
			ntime = get_cycles();
			/*
			 * Our retries may be blocked by all destination
			 * swack resources being consumed, and a timeout
			 * pending.  In that case hardware returns the
			 * ERROR that looks like a destination timeout.
			 * After 1000 retries clear this situation
			 * with an IPI message.
			 */

			if (bcp->timeout_retry_count >= 1000) {
				bcp->timeout_retry_count = 0;
				stat->s_resets++;
				uv_reset_with_ipi(&bau_desc->distribution,
							this_cpu);
			}
			bcp->timeout_retry_count++;
			return FLUSH_RETRY;
		} else {
			/*
			 * descriptor_status is still BUSY
			 */
			cpu_relax();
			relaxes++;
			if (relaxes >= 1000000) {
				relaxes = 0;
				if (get_cycles() > timeout_time) {
					uv_reset_busy(bcp, mmr_offset,
							right_shift, stat);
					/* The message probably was broadcast
					 * and completed.  But not for sure.
					 * Use an IPI to clear things.
					 */
					return FLUSH_GIVEUP;
				}
			}
		}
	}
	return FLUSH_COMPLETE;
}

/**
 * uv_flush_send_and_wait
 *
 * Send a broadcast and wait for a broadcast message to complete.
 *
 * The flush_mask contains the cpus the broadcast was sent to.
 *
 * Returns NULL if all remote flushing was done. The mask is zeroed.
 * Returns @flush_mask if some remote flushing remains to be done. The
 * mask will have some bits still set.
 */
const struct cpumask *uv_flush_send_and_wait(struct bau_desc *bau_desc,
					     struct cpumask *flush_mask,
					     struct bau_control *bcp)
{
	int right_shift;
	int pnode;
	int bit;
	int completion_status = 0;
	int seq_number = 0;
	long try = 0;
	int cpu = bcp->blade_cpu;
	int this_cpu = bcp->cpu;
	int this_pnode = bcp->pnode;
	unsigned long mmr_offset;
	unsigned long index;
	cycles_t time1;
	cycles_t time2;
	struct ptc_stats *stat = &per_cpu(ptcstats, bcp->cpu);
	struct bau_control *smaster = bcp->socket_master;
	struct bau_control *pmaster = bcp->pnode_master;

	/* spin here while there are bcp->max_concurrent active descriptors */
	while (!atomic_add_unless(&pmaster->active_descripter_count, 1,
						pmaster->max_concurrent)) {
		cpu_relax();
	}

	if (cpu < UV_CPUS_PER_ACT_STATUS) {
		mmr_offset = UVH_LB_BAU_SB_ACTIVATION_STATUS_0;
		right_shift = cpu * UV_ACT_STATUS_SIZE;
	} else {
		mmr_offset = UVH_LB_BAU_SB_ACTIVATION_STATUS_1;
		right_shift =
		    ((cpu - UV_CPUS_PER_ACT_STATUS) * UV_ACT_STATUS_SIZE);
	}
	bcp->timeout_retry_count = 0;
	time1 = get_cycles();
	do {
		/*
		 * Every message from any given cpu gets a unique message
		 * number. But retries use that same number.
		 * Our message may have timed out at the destination because
		 * all sw-ack resources are in use and there is a timeout
		 * pending there.  In that case, our last send never got
		 * placed into the queue and we need to persist until it
		 * does.
		 * The uv_wait_completion() function will take care of
		 * sending the occasional reset message to clear this
		 * message number and the resource it is using.
		 *
		 * Make any retry a type MSG_RETRY so that the destination will
		 * free any resource held by a previous message from this cpu.
		 */
		if (try == 0) {
			/* use message type set by the caller the first time */
			/* sequence number plays no role in the logic */
			seq_number = bcp->message_number++;
		} else {
			/* use RETRY type on all the rest; same sequence */
			bau_desc->header.msg_type = MSG_RETRY;
		}
		bau_desc->header.sequence = seq_number;
		index = (1UL << UVH_LB_BAU_SB_ACTIVATION_CONTROL_PUSH_SHFT) |
			bcp->blade_cpu;

		uv_write_local_mmr(UVH_LB_BAU_SB_ACTIVATION_CONTROL, index);

		try++;
		completion_status = uv_wait_completion(bau_desc, mmr_offset,
			right_shift, this_cpu, bcp, smaster, try);
	} while (completion_status == FLUSH_RETRY);
	time2 = get_cycles();
	atomic_dec(&pmaster->active_descripter_count);

	/* guard against cycles wrap */
	if (time2 > time1)
		stat->s_time += (time2 - time1);
	else
		stat->s_requestor--; /* don't count this one */
	if (completion_status == FLUSH_COMPLETE && try > 1)
		stat->s_retriesok++;
	else if (completion_status == FLUSH_GIVEUP) {
		/*
		 * Cause the caller to do an IPI-style TLB shootdown on
		 * the target cpu's, all of which are still in the mask.
		 */
		stat->s_giveup++;
		return flush_mask;
	}

	/*
	 * Success, so clear the remote cpu's from the mask so we don't
	 * use the IPI method of shootdown on them.
	 */
	for_each_cpu(bit, flush_mask) {
		pnode = uv_cpu_to_pnode(bit);
		if (pnode == this_pnode)
			continue;
		cpumask_clear_cpu(bit, flush_mask);
	}
	if (!cpumask_empty(flush_mask))
		return flush_mask;

	return NULL;
}

/**
 * uv_flush_tlb_others - globally purge translation cache of a virtual
 * address or all TLB's
 * @cpumask: mask of all cpu's in which the address is to be removed
 * @mm: mm_struct containing virtual address range
 * @va: virtual address to be removed (or TLB_FLUSH_ALL for all TLB's on cpu)
 * @cpu: the current cpu
 *
 * This is the entry point for initiating any UV global TLB shootdown.
 *
 * Purges the translation caches of all specified processors of the given
 * virtual address, or purges all TLB's on specified processors.
 *
 * The caller has derived the cpumask from the mm_struct.  This function
 * is called only if there are bits set in the mask. (e.g. flush_tlb_page())
 *
 * The cpumask is converted into a nodemask of the nodes containing
 * the cpus.
 *
 * Note that this function should be called with preemption disabled.
 *
 * Returns NULL if all remote flushing was done.
 * Returns pointer to cpumask if some remote flushing remains to be
 * done.  The returned pointer is valid till preemption is re-enabled.
 */
const struct cpumask *uv_flush_tlb_others(const struct cpumask *cpumask,
					  struct mm_struct *mm,
					  unsigned long va, unsigned int cpu)
{
	int i;
	int bit;
	int pnode;
	int locals = 0;
	struct bau_desc *bau_desc;
	struct cpumask *flush_mask;
	struct ptc_stats *stat;
	struct bau_control *bcp;

	if (nobau)
		return cpumask;

	bcp = &per_cpu(bau_control, cpu);
	/*
	 * Each sending cpu has a cpu mask which it fills from the caller's
	 * cpu mask.  Only remote cpus are converted to pnodes and copied.
	 */
	flush_mask = (struct cpumask *)per_cpu(uv_flush_tlb_mask, cpu);
	/* removes current cpu: */
	cpumask_andnot(flush_mask, cpumask, cpumask_of(cpu));
	if (cpu_isset(cpu, *cpumask))
		locals++;  /* current cpu is targeted */

	bau_desc = bcp->descriptor_base;
	bau_desc += UV_ITEMS_PER_DESCRIPTOR * bcp->blade_cpu;

	bau_nodes_clear(&bau_desc->distribution, UV_DISTRIBUTION_SIZE);
	i = 0;
	for_each_cpu(bit, flush_mask) {
		pnode = uv_cpu_to_pnode(bit);
		BUG_ON(pnode > (UV_DISTRIBUTION_SIZE - 1));
		if (pnode == bcp->pnode) {
			locals++;
			continue;
		}
		bau_node_set(pnode - uv_partition_base_pnode,
				&bau_desc->distribution);
		i++;
	}
	if (i == 0) {
		/*
		 * No off_node flushing; return status for local node
		 * Return the caller's mask if all were local (the current
		 * cpu may be in that mask).
		 */
		if (locals)
			return cpumask;
		else
			return NULL;
	}
	stat = &per_cpu(ptcstats, cpu);
	stat->s_requestor++;
	stat->s_ntargcpu += i;
	stat->s_ntargpnod += bau_node_weight(&bau_desc->distribution);

	bau_desc->payload.address = va;
	bau_desc->payload.sending_cpu = cpu;

	/*
	 * uv_flush_send_and_wait returns null if all cpu's were messaged, or
	 * the adjusted flush_mask if any cpu's were not messaged.
	 */
	return uv_flush_send_and_wait(bau_desc, flush_mask, bcp);
}

/*
 * The BAU message interrupt comes here. (registered by set_intr_gate)
 * See entry_64.S
 *
 * We received a broadcast assist message.
 *
 * Interrupts may have been disabled; this interrupt could represent
 * the receipt of several messages.
 *
 * All cores/threads on this node get this interrupt.
 * The last one to see it does the s/w ack.
 * (the resource will not be freed until noninterruptable cpus see this
 *  interrupt; hardware will timeout the s/w ack and reply ERROR)
 */
void uv_bau_message_interrupt(struct pt_regs *regs)
{
	int msg_slot;
	int sw_ack_slot;
	int fw;
	int count = 0;
	int this_cpu;
	cycles_t time1;
	cycles_t time2;
	struct bau_payload_queue_entry *va_queue_first;
	struct bau_payload_queue_entry *va_queue_last;
	struct bau_payload_queue_entry *msg;
	struct pt_regs *old_regs = set_irq_regs(regs);
	struct bau_control *bcp;
	struct ptc_stats *stat;

	local_irq_disable();
	ack_APIC_irq();

	time1 = get_cycles();

	this_cpu = smp_processor_id();
	bcp = &per_cpu(bau_control, this_cpu);
	stat = &per_cpu(ptcstats, this_cpu);
	va_queue_first = bcp->va_queue_first;
	va_queue_last = bcp->va_queue_last;

	msg = bcp->bau_msg_head;
	while (msg->sw_ack_vector) {
		if (msg->canceled)
			goto nextmsg;
		count++;
		fw = msg->sw_ack_vector;
		msg_slot = msg - va_queue_first;
		sw_ack_slot = ffs(fw) - 1;

		uv_bau_process_message(msg, msg_slot, sw_ack_slot, bcp,
					va_queue_first, va_queue_last);
nextmsg:
		msg++;
		if (msg > va_queue_last)
			msg = va_queue_first;
		bcp->bau_msg_head = msg;
	}
	if (!count)
		stat->d_nomsg++;
	else if (count > 1)
		stat->d_multmsg++;

	time2 = get_cycles();
	stat->d_time += (time2 - time1);

	local_irq_enable();
	set_irq_regs(old_regs);
}

/*
 * uv_enable_timeouts
 *
 * Each target blade (i.e. a blade that has no cpu's) needs to have
 * shootdown message timeouts enabled.  The timeout does not cause
 * an interrupt, but causes an error message to be returned to
 * the sender.
 */
static void uv_enable_timeouts(void)
{
	int blade;
	int nblades;
	int pnode;
	unsigned long mmr_image;

	nblades = uv_num_possible_blades();

	for (blade = 0; blade < nblades; blade++) {
		if (!uv_blade_nr_possible_cpus(blade))
			continue;

		pnode = uv_blade_to_pnode(blade);
		mmr_image =
		    uv_read_global_mmr64(pnode, UVH_LB_BAU_MISC_CONTROL);
		/*
		 * Set the timeout period and then lock it in, in three
		 * steps; captures and locks in the period.
		 *
		 * To program the period, the SOFT_ACK_MODE must be off.
		 */
		mmr_image &= ~((unsigned long)1 <<
		    UVH_LB_BAU_MISC_CONTROL_ENABLE_INTD_SOFT_ACK_MODE_SHFT);
		uv_write_global_mmr64
		    (pnode, UVH_LB_BAU_MISC_CONTROL, mmr_image);
		/*
		 * Set the 4-bit period.
		 */
		mmr_image &= ~((unsigned long)0xf <<
		     UVH_LB_BAU_MISC_CONTROL_INTD_SOFT_ACK_TIMEOUT_PERIOD_SHFT);
		mmr_image |= (UV_INTD_SOFT_ACK_TIMEOUT_PERIOD <<
		     UVH_LB_BAU_MISC_CONTROL_INTD_SOFT_ACK_TIMEOUT_PERIOD_SHFT);
		uv_write_global_mmr64
		    (pnode, UVH_LB_BAU_MISC_CONTROL, mmr_image);
		/*
		 * Subsequent reversals of the timebase bit (3) cause an
		 * immediate timeout of one or all INTD resources as
		 * indicated in bits 2:0 (7 causes all of them to timeout).
		 */
		mmr_image |= ((unsigned long)1 <<
		    UVH_LB_BAU_MISC_CONTROL_ENABLE_INTD_SOFT_ACK_MODE_SHFT);
		uv_write_global_mmr64
		    (pnode, UVH_LB_BAU_MISC_CONTROL, mmr_image);
	}
}

static void *uv_ptc_seq_start(struct seq_file *file, loff_t *offset)
{
	if (*offset < num_possible_cpus())
		return offset;
	return NULL;
}

static void *uv_ptc_seq_next(struct seq_file *file, void *data, loff_t *offset)
{
	(*offset)++;
	if (*offset < num_possible_cpus())
		return offset;
	return NULL;
}

static void uv_ptc_seq_stop(struct seq_file *file, void *data)
{
}

static inline unsigned long
cycles_2_us(unsigned long long cyc)
{
	unsigned long long ns;
	unsigned long flags, us;
	local_irq_save(flags);
	ns =  (cyc * per_cpu(cyc2ns, smp_processor_id()))
						>> CYC2NS_SCALE_FACTOR;
	us = ns / 1000;
	local_irq_restore(flags);
	return us;
}

static inline unsigned long long
millisec_2_cycles(unsigned long millisec)
{
	unsigned long flags;
	unsigned long ns;
	unsigned long long cyc;

	ns = millisec * 1000;
	local_irq_save(flags);
	cyc = (ns << CYC2NS_SCALE_FACTOR)/(per_cpu(cyc2ns, smp_processor_id()));
	local_irq_restore(flags);
	return cyc;
}

/*
 * Display the statistics thru /proc.
 * 'data' points to the cpu number
 */
static int uv_ptc_seq_show(struct seq_file *file, void *data)
{
	struct ptc_stats *stat;
	int cpu;

	cpu = *(loff_t *)data;

	if (!cpu) {
		seq_printf(file,
	"# cpu sent stime numnodes numcpus dto retried resets giveup sto bz ");
		seq_printf(file,
	   "sw_ack recv rtime all one mult none retry canc nocan reset rcan\n");
	}
	if (cpu < num_possible_cpus() && cpu_online(cpu)) {
		stat = &per_cpu(ptcstats, cpu);
		seq_printf(file,
			   "cpu %d %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld ",
			   cpu, stat->s_requestor, cycles_2_us(stat->s_time),
			   stat->s_ntargpnod, stat->s_ntargcpu,
			   stat->s_dtimeout, stat->s_retriesok, stat->s_resets,
			   stat->s_giveup, stat->s_stimeout, stat->s_busy);
		seq_printf(file,
			   "%lx %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld\n",
			   uv_read_global_mmr64(uv_cpu_to_pnode(cpu),
					UVH_LB_BAU_INTD_SOFTWARE_ACKNOWLEDGE),
			   stat->d_requestee, cycles_2_us(stat->d_time),
			   stat->d_alltlb, stat->d_onetlb, stat->d_multmsg,
			   stat->d_nomsg, stat->d_retries, stat->d_canceled,
			   stat->d_nocanceled, stat->d_resets,
			   stat->d_rcanceled);
	}


	return 0;
}

/*
 * -1: resetf the statistics
 *  0: display meaning of the statistics
 * >0: maximum concurrent active descriptors per blade (throttle)
 */
static ssize_t uv_ptc_proc_write(struct file *file, const char __user *user,
				 size_t count, loff_t *data)
{
	int cpu;
	long input_arg;
	char optstr[64];
	struct ptc_stats *stat;
	struct bau_control *bcp;

	if (count == 0 || count > sizeof(optstr))
		return -EINVAL;
	if (copy_from_user(optstr, user, count))
		return -EFAULT;
	optstr[count - 1] = '\0';
	if (strict_strtol(optstr, 10, &input_arg) < 0) {
		printk(KERN_DEBUG "%s is invalid\n", optstr);
		return -EINVAL;
	}

	if (input_arg == 0) {
		printk(KERN_DEBUG "# cpu:      cpu number\n");
		printk(KERN_DEBUG "Sender statistics:\n");
		printk(KERN_DEBUG
		"sent:     number of shootdown messages sent\n");
		printk(KERN_DEBUG
		"stime:    time spent sending messages\n");
		printk(KERN_DEBUG
		"numnodes: number of pnodes targeted with shootdown\n");
		printk(KERN_DEBUG
		"numcpus:  number of cpus targeted with shootdown\n");
		printk(KERN_DEBUG
		"dto:      number of destination timeouts\n");
		printk(KERN_DEBUG
		"retried:  destination timeouts sucessfully retried\n");
		printk(KERN_DEBUG
		"resets:   ipi-style resource resets done\n");
		printk(KERN_DEBUG
		"giveup:   fall-backs to ipi-style shootdowns\n");
		printk(KERN_DEBUG
		"sto:      number of source timeouts\n");
		printk(KERN_DEBUG "Destination side statistics:\n");
		printk(KERN_DEBUG
		"sw_ack:   image of UVH_LB_BAU_INTD_SOFTWARE_ACKNOWLEDGE\n");
		printk(KERN_DEBUG
		"recv:     shootdown messages received\n");
		printk(KERN_DEBUG
		"rtime:    time spent processing messages\n");
		printk(KERN_DEBUG
		"all:      shootdown all-tlb messages\n");
		printk(KERN_DEBUG
		"one:      shootdown one-tlb messages\n");
		printk(KERN_DEBUG
		"mult:     interrupts that found multiple messages\n");
		printk(KERN_DEBUG
		"none:     interrupts that found no messages\n");
		printk(KERN_DEBUG
		"retry:    number of retry messages processed\n");
		printk(KERN_DEBUG
		"canc:     number messages canceled by retries\n");
		printk(KERN_DEBUG
		"nocan:    number retries that found nothing to cancel\n");
		printk(KERN_DEBUG
		"reset:    number of ipi-style reset requests processed\n");
		printk(KERN_DEBUG
		"rcan:     number messages canceled by reset requests\n");
	} else if (input_arg == -1) {
		for_each_present_cpu(cpu) {
			stat = &per_cpu(ptcstats, cpu);
			memset(stat, 0, sizeof(struct ptc_stats));
		}
	} else {
		uv_bau_max_concurrent = input_arg;
		printk(KERN_DEBUG "Set BAU max concurrent:%d\n",
		       uv_bau_max_concurrent);
		for_each_present_cpu(cpu) {
			bcp = &per_cpu(bau_control, cpu);
			bcp->max_concurrent = uv_bau_max_concurrent;
		}
	}

	return count;
}

static const struct seq_operations uv_ptc_seq_ops = {
	.start		= uv_ptc_seq_start,
	.next		= uv_ptc_seq_next,
	.stop		= uv_ptc_seq_stop,
	.show		= uv_ptc_seq_show
};

static int uv_ptc_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &uv_ptc_seq_ops);
}

static const struct file_operations proc_uv_ptc_operations = {
	.open		= uv_ptc_proc_open,
	.read		= seq_read,
	.write		= uv_ptc_proc_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init uv_ptc_init(void)
{
	struct proc_dir_entry *proc_uv_ptc;

	if (!is_uv_system())
		return 0;

	proc_uv_ptc = proc_create(UV_PTC_BASENAME, 0444, NULL,
				  &proc_uv_ptc_operations);
	if (!proc_uv_ptc) {
		printk(KERN_ERR "unable to create %s proc entry\n",
		       UV_PTC_BASENAME);
		return -EINVAL;
	}
	return 0;
}

/*
 * initialize the sending side's sending buffers
 */
static void
uv_activation_descriptor_init(int node, int pnode)
{
	int i;
	int cpu;
	unsigned long pa;
	unsigned long m;
	unsigned long n;
	struct bau_desc *bau_desc;
	struct bau_desc *bd2;
	struct bau_control *bcp;

	/*
	 * each bau_desc is 64 bytes; there are 8 (UV_ITEMS_PER_DESCRIPTOR)
	 * per cpu; and up to 32 (UV_ADP_SIZE) cpu's per blade
	 */
	bau_desc = (struct bau_desc *)kmalloc_node(sizeof(struct bau_desc)*
		UV_ADP_SIZE*UV_ITEMS_PER_DESCRIPTOR, GFP_KERNEL, node);
	BUG_ON(!bau_desc);

	pa = uv_gpa(bau_desc); /* need the real nasid*/
	n = pa >> uv_nshift;
	m = pa & uv_mmask;

	uv_write_global_mmr64(pnode, UVH_LB_BAU_SB_DESCRIPTOR_BASE,
			      (n << UV_DESC_BASE_PNODE_SHIFT | m));

	/*
	 * initializing all 8 (UV_ITEMS_PER_DESCRIPTOR) descriptors for each
	 * cpu even though we only use the first one; one descriptor can
	 * describe a broadcast to 256 nodes.
	 */
	for (i = 0, bd2 = bau_desc; i < (UV_ADP_SIZE*UV_ITEMS_PER_DESCRIPTOR);
		i++, bd2++) {
		memset(bd2, 0, sizeof(struct bau_desc));
		bd2->header.sw_ack_flag = 1;
		/*
		 * base_dest_nodeid is the first node in the partition, so
		 * the bit map will indicate partition-relative node numbers.
		 * note that base_dest_nodeid is actually a nasid.
		 */
		bd2->header.base_dest_nodeid = uv_partition_base_pnode << 1;
		bd2->header.dest_subnodeid = 0x10; /* the LB */
		bd2->header.command = UV_NET_ENDPOINT_INTD;
		bd2->header.int_both = 1;
		/*
		 * all others need to be set to zero:
		 *   fairness chaining multilevel count replied_to
		 */
	}
	for_each_present_cpu(cpu) {
		if (pnode != uv_blade_to_pnode(uv_cpu_to_blade_id(cpu)))
			continue;
		bcp = &per_cpu(bau_control, cpu);
		bcp->descriptor_base = bau_desc;
	}
}

/*
 * initialize the destination side's receiving buffers
 * entered for each pnode (node is the first node on the blade)
 */
static void
uv_payload_queue_init(int node, int pnode)
{
	int pn;
	int cpu;
	char *cp;
	unsigned long pa;
	struct bau_payload_queue_entry *pqp;
	struct bau_payload_queue_entry *pqp_malloc;
	struct bau_control *bcp;

	pqp = (struct bau_payload_queue_entry *) kmalloc_node(
		(DEST_Q_SIZE + 1) * sizeof(struct bau_payload_queue_entry),
		GFP_KERNEL, node);
	BUG_ON(!pqp);
	pqp_malloc = pqp;

	cp = (char *)pqp + 31;
	pqp = (struct bau_payload_queue_entry *)(((unsigned long)cp >> 5) << 5);

	for_each_present_cpu(cpu) {
		if (pnode != uv_cpu_to_pnode(cpu))
			continue;
		/* for every cpu on this pnode: */
		bcp = &per_cpu(bau_control, cpu);
		bcp->va_queue_first = pqp;
		bcp->bau_msg_head = pqp;
		bcp->va_queue_last = pqp + (DEST_Q_SIZE - 1);
		bcp->timeout_interval = millisec_2_cycles(1);
		spin_lock_init(&bcp->quiesce_lock);
	}
	/*
	 * need the pnode of where the memory was really allocated
	 */
	pa = uv_gpa(pqp);
	pn = pa >> uv_nshift;
	uv_write_global_mmr64(pnode,
			      UVH_LB_BAU_INTD_PAYLOAD_QUEUE_FIRST,
			      ((unsigned long)pn << UV_PAYLOADQ_PNODE_SHIFT) |
			      uv_physnodeaddr(pqp));
	uv_write_global_mmr64(pnode, UVH_LB_BAU_INTD_PAYLOAD_QUEUE_TAIL,
			      uv_physnodeaddr(pqp));
	uv_write_global_mmr64(pnode, UVH_LB_BAU_INTD_PAYLOAD_QUEUE_LAST,
			      (unsigned long)
			      uv_physnodeaddr(pqp + (DEST_Q_SIZE - 1)));
	/* in effect, all msg_type's are set to MSG_NOOP */
	memset(pqp, 0, sizeof(struct bau_payload_queue_entry) * DEST_Q_SIZE);
}

/*
 * Initialization of each UV blade's structures
 */
static void __init uv_init_blade(int blade, int vector)
{
	int node;
	int pnode;
	unsigned long apicid;

	node = blade_to_first_node(blade);
	pnode = uv_blade_to_pnode(blade);
	uv_activation_descriptor_init(node, pnode);
	uv_payload_queue_init(node, pnode);
	/*
	 * the below initialization can't be in firmware because the
	 * messaging IRQ will be determined by the OS
	 */
	apicid = blade_to_first_apicid(blade);
	uv_write_global_mmr64(pnode, UVH_BAU_DATA_CONFIG,
				      ((apicid << 32) | vector));
}

/*
 * initialize the bau_control structure for each cpu
 */
static void uv_init_per_cpu(int nblades)
{
	int i, j, k;
	int cpu;
	int pnode;
	int blade;
	short socket = 0;
	struct bau_control *bcp;
	struct blade_desc *bdp;
	struct socket_desc *sdp;
	struct bau_control *pmaster = NULL;
	struct bau_control *smaster = NULL;
	struct socket_desc {
		short num_cpus;
		short cpu_number[16];
	};
	struct blade_desc {
		short num_sockets;
		short num_cpus;
		short pnode;
		struct socket_desc socket[2];
	};
	struct blade_desc *blade_descs;

	blade_descs = (struct blade_desc *)
		kmalloc(nblades * sizeof(struct blade_desc), GFP_KERNEL);
	memset(blade_descs, 0, nblades * sizeof(struct blade_desc));
	for_each_present_cpu(cpu) {
		bcp = &per_cpu(bau_control, cpu);
		memset(bcp, 0, sizeof(struct bau_control));
		bcp->max_concurrent = uv_bau_max_concurrent;
		pnode = uv_cpu_hub_info(cpu)->pnode;
		blade = uv_cpu_hub_info(cpu)->numa_blade_id;
		bdp = &blade_descs[blade];
		bdp->num_cpus++;
		bdp->pnode = pnode;
		/* kludge: assume uv_hub.h is constant */
		socket = (cpu_physical_id(cpu)>>5)&1;
		if (socket >= bdp->num_sockets)
			bdp->num_sockets = socket+1;
		sdp = &bdp->socket[socket];
		sdp->cpu_number[sdp->num_cpus] = cpu;
		sdp->num_cpus++;
	}
	socket = 0;
	for_each_possible_blade(blade) {
		bdp = &blade_descs[blade];
		for (i = 0; i < bdp->num_sockets; i++) {
			sdp = &bdp->socket[i];
			for (j = 0; j < sdp->num_cpus; j++) {
				cpu = sdp->cpu_number[j];
				bcp = &per_cpu(bau_control, cpu);
				bcp->cpu = cpu;
				if (j == 0) {
					smaster = bcp;
					if (i == 0)
						pmaster = bcp;
				}
				bcp->cpus_in_blade = bdp->num_cpus;
				bcp->cpus_in_socket = sdp->num_cpus;
				bcp->socket_master = smaster;
				bcp->pnode_master = pmaster;
				for (k = 0; k < DEST_Q_SIZE; k++)
					bcp->socket_acknowledge_count[k] = 0;
				bcp->pnode = bdp->pnode;
				bcp->blade_cpu =
				  uv_cpu_hub_info(cpu)->blade_processor_id;
			}
			socket++;
		}
	}
	kfree(blade_descs);
}

/*
 * Initialization of BAU-related structures
 */
static int __init uv_bau_init(void)
{
	int blade;
	int pnode;
	int nblades;
	int cur_cpu;
	int vector;
	unsigned long mmr;

	if (!is_uv_system())
		return 0;

	if (nobau)
		return 0;

	for_each_possible_cpu(cur_cpu)
		zalloc_cpumask_var_node(&per_cpu(uv_flush_tlb_mask, cur_cpu),
				       GFP_KERNEL, cpu_to_node(cur_cpu));

	uv_bau_max_concurrent = MAX_BAU_CONCURRENT;
	uv_nshift = uv_hub_info->m_val;
	uv_mmask = (1UL << uv_hub_info->m_val) - 1;
	nblades = uv_num_possible_blades();

	uv_init_per_cpu(nblades);

	uv_partition_base_pnode = 0x7fffffff;
	for (blade = 0; blade < nblades; blade++)
		if (uv_blade_nr_possible_cpus(blade) &&
			(uv_blade_to_pnode(blade) < uv_partition_base_pnode))
			uv_partition_base_pnode = uv_blade_to_pnode(blade);

	vector = UV_BAU_MESSAGE;
	for_each_possible_blade(blade)
		if (uv_blade_nr_possible_cpus(blade))
			uv_init_blade(blade, vector);

	uv_enable_timeouts();
	alloc_intr_gate(vector, uv_bau_message_intr1);

	for_each_possible_blade(blade) {
		pnode = uv_blade_to_pnode(blade);
		/* INIT the bau */
		uv_write_global_mmr64(pnode, UVH_LB_BAU_SB_ACTIVATION_CONTROL,
				      ((unsigned long)1 << 63));
		mmr = 1; /* should be 1 to broadcast to both sockets */
		uv_write_global_mmr64(pnode, UVH_BAU_DATA_BROADCAST, mmr);
	}

	return 0;
}
__initcall(uv_bau_init);
__initcall(uv_ptc_init);
