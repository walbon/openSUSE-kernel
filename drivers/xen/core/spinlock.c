/*
 *	Xen spinlock functions
 *
 *	See arch/x86/xen/smp.c for copyright and credits for derived
 *	portions of this file.
 */
#define XEN_SPINLOCK_SOURCE
#include <linux/spinlock_types.h>

#ifdef TICKET_SHIFT

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/hardirq.h>
#include <xen/clock.h>
#include <xen/evtchn.h>

struct spinning {
	arch_spinlock_t *lock;
	unsigned int ticket;
	struct spinning *prev;
};
static DEFINE_PER_CPU(struct spinning *, _spinning);
static DEFINE_PER_CPU_READ_MOSTLY(evtchn_port_t, poll_evtchn);
/*
 * Protect removal of objects: Addition can be done lockless, and even
 * removal itself doesn't need protection - what needs to be prevented is
 * removed objects going out of scope (as they're allocated on the stack).
 */
struct rm_seq {
	unsigned int idx;
	atomic_t ctr[2];
};
static DEFINE_PER_CPU(struct rm_seq, rm_seq);

int __cpuinit xen_spinlock_init(unsigned int cpu)
{
	struct evtchn_bind_ipi bind_ipi;
	int rc;

	setup_runstate_area(cpu);

 	WARN_ON(per_cpu(poll_evtchn, cpu));
	bind_ipi.vcpu = cpu;
	rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_ipi, &bind_ipi);
	if (!rc)
	 	per_cpu(poll_evtchn, cpu) = bind_ipi.port;
	else
		pr_warning("No spinlock poll event channel for CPU#%u (%d)\n",
			   cpu, rc);

	return rc;
}

void __cpuinit xen_spinlock_cleanup(unsigned int cpu)
{
	struct evtchn_close close;

	close.port = per_cpu(poll_evtchn, cpu);
 	per_cpu(poll_evtchn, cpu) = 0;
	WARN_ON(HYPERVISOR_event_channel_op(EVTCHNOP_close, &close));
}

#ifdef CONFIG_PM_SLEEP
#include <linux/syscore_ops.h>

static void __cpuinit spinlock_resume(void)
{
	unsigned int cpu;

	for_each_online_cpu(cpu) {
		per_cpu(poll_evtchn, cpu) = 0;
		xen_spinlock_init(cpu);
	}
}

static struct syscore_ops __cpuinitdata spinlock_syscore_ops = {
	.resume	= spinlock_resume
};

static int __init spinlock_register(void)
{
	if (!is_initial_xendomain())
		register_syscore_ops(&spinlock_syscore_ops);
	return 0;
}
core_initcall(spinlock_register);
#endif

#if CONFIG_XEN_SPINLOCK_ACQUIRE_NESTING
static unsigned int spin_adjust(struct spinning *spinning,
				const arch_spinlock_t *lock,
				unsigned int ticket)
{
	for (; spinning; spinning = spinning->prev) {
		unsigned int old = spinning->ticket;

		if (spinning->lock != lock)
			continue;
		while (likely(old + 1)) {
			unsigned int cur;

#if CONFIG_XEN_SPINLOCK_ACQUIRE_NESTING > 1
			ticket = spin_adjust(spinning->prev, lock, ticket);
#endif
			cur = cmpxchg(&spinning->ticket, old, ticket);
			if (cur == old)
				return cur;
			old = cur;
		}
#if CONFIG_XEN_SPINLOCK_ACQUIRE_NESTING == 1
		break;
#endif
	}
	return ticket;
}

unsigned int xen_spin_adjust(const arch_spinlock_t *lock, unsigned int token)
{
	token = spin_adjust(percpu_read(_spinning), lock,
			    token >> TICKET_SHIFT);
	return (token << TICKET_SHIFT) | lock->cur;
}
#endif

unsigned int xen_spin_wait(arch_spinlock_t *lock, unsigned int *ptok,
			   unsigned int flags)
{
	unsigned int rm_idx, cpu = raw_smp_processor_id();
	bool rc;
	typeof(vcpu_info(0)->evtchn_upcall_mask) upcall_mask
		= arch_local_save_flags();
	struct spinning spinning, *other;

	/* If kicker interrupt not initialized yet, just spin. */
	if (unlikely(!cpu_online(cpu)) || unlikely(!percpu_read(poll_evtchn)))
		return UINT_MAX;

	/* announce we're spinning */
	spinning.ticket = *ptok >> TICKET_SHIFT;
	spinning.lock = lock;
	spinning.prev = percpu_read(_spinning);
	smp_wmb();
	percpu_write(_spinning, &spinning);

	do {
#if CONFIG_XEN_SPINLOCK_ACQUIRE_NESTING
		int nesting = CONFIG_XEN_SPINLOCK_ACQUIRE_NESTING;
#endif

		clear_evtchn(percpu_read(poll_evtchn));

		/*
		 * Check again to make sure it didn't become free while
		 * we weren't looking.
		 */
		if (lock->cur == spinning.ticket) {
			lock->owner = cpu;
			/*
			 * If we interrupted another spinlock while it was
			 * blocking, make sure it doesn't block (again)
			 * without rechecking the lock.
			 */
			if (spinning.prev)
				set_evtchn(percpu_read(poll_evtchn));
			rc = true;
			break;
		}

#if CONFIG_XEN_SPINLOCK_ACQUIRE_NESTING
		for (other = spinning.prev; other; other = other->prev) {
			if (other->lock == lock)
				--nesting;
			else {
				/*
				 * Return the ticket if we now own the lock.
				 * While just being desirable generally (to
				 * reduce latency on other CPUs), this is
				 * essential in the case where interrupts
				 * get re-enabled below.
				 * Try to get a new ticket right away (to
				 * reduce latency after the current lock was
				 * released), but don't acquire the lock.
				 */
				arch_spinlock_t *lock = other->lock;

				arch_local_irq_disable();
				while (lock->cur == other->ticket) {
					unsigned int token;
					bool kick, free;

					lock->owner = cpu;
					other->ticket = -1;
					__ticket_spin_unlock_body;
					if (!kick)
						break;
					xen_spin_kick(lock, token);
					__ticket_spin_lock_preamble;
					if (!free)
						token = spin_adjust(
							other->prev, lock,
							token);
					other->ticket = token >> TICKET_SHIFT;
					smp_mb();
				}
			}
		}

		arch_local_irq_restore(nesting <= 0 ? upcall_mask : flags);
#endif

		if ((rc = !test_evtchn(percpu_read(poll_evtchn))) &&
		    HYPERVISOR_poll_no_timeout(&__get_cpu_var(poll_evtchn), 1))
			BUG();

		vcpu_info_write(evtchn_upcall_mask, upcall_mask);

		if (rc && !(rc = !test_evtchn(percpu_read(poll_evtchn))))
			inc_irq_stat(irq_lock_count);
	} while (spinning.prev || rc);

	/*
	 * Leave the event pending so that any interrupted blocker will
	 * re-check.
	 */

	/* announce we're done */
	other = spinning.prev;
	percpu_write(_spinning, other);
	arch_local_irq_disable();
	rm_idx = percpu_read(rm_seq.idx);
	smp_wmb();
	percpu_write(rm_seq.idx, rm_idx + 1);
	smp_mb();

#if CONFIG_XEN_SPINLOCK_ACQUIRE_NESTING
	/*
	 * Obtain new tickets for (or acquire) all those locks where
	 * above we avoided acquiring them.
	 */
	if (other) {
		do {
			unsigned int token;
			bool free;

			if (other->ticket + 1)
				continue;
			lock = other->lock;
			__ticket_spin_lock_preamble;
			if (!free)
				token = spin_adjust(other->prev, lock, token);
			other->ticket = token >> TICKET_SHIFT;
			if (lock->cur == other->ticket)
				lock->owner = cpu;
		} while ((other = other->prev) != NULL);
		lock = spinning.lock;
	}
#endif

	rm_idx &= 1;
	while (percpu_read(rm_seq.ctr[rm_idx].counter))
		cpu_relax();
	arch_local_irq_restore(upcall_mask);
	*ptok = lock->cur | (spinning.ticket << TICKET_SHIFT);

	return rc ? 0 : 1 << 10;
}

void xen_spin_kick(arch_spinlock_t *lock, unsigned int token)
{
	unsigned int cpu = raw_smp_processor_id(), anchor = cpu;

	if (unlikely(!cpu_online(cpu)))
		cpu = -1, anchor = nr_cpu_ids;

	token &= (1U << TICKET_SHIFT) - 1;
	while ((cpu = cpumask_next(cpu, cpu_online_mask)) != anchor) {
		unsigned int flags;
		atomic_t *rm_ctr;
		struct spinning *spinning;

		if (cpu >= nr_cpu_ids) {
			if (anchor == nr_cpu_ids)
				return;
			cpu = cpumask_first(cpu_online_mask);
			if (cpu == anchor)
				return;
		}

		flags = arch_local_irq_save();
		for (;;) {
			unsigned int rm_idx = per_cpu(rm_seq.idx, cpu);

			rm_ctr = per_cpu(rm_seq.ctr, cpu) + (rm_idx & 1);
			atomic_inc(rm_ctr);
#ifdef CONFIG_X86 /* atomic ops are full CPU barriers */
			barrier();
#else
			smp_mb();
#endif
			spinning = per_cpu(_spinning, cpu);
			smp_rmb();
			if (rm_idx == per_cpu(rm_seq.idx, cpu))
				break;
			atomic_dec(rm_ctr);
		}

		while (spinning) {
			if (spinning->lock == lock && spinning->ticket == token)
				break;
			spinning = spinning->prev;
		}

		atomic_dec(rm_ctr);
		arch_local_irq_restore(flags);

		if (unlikely(spinning)) {
			notify_remote_via_evtchn(per_cpu(poll_evtchn, cpu));
			return;
		}
	}
}
EXPORT_SYMBOL(xen_spin_kick);

#endif /* TICKET_SHIFT */
