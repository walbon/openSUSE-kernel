/*
 * Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 * Manage RMBE
 * copy new RMBE data into user space
 *
 * Copyright IBM Corp. 2016
 *
 * Author(s):  Ursula Braun <ursula.braun@de.ibm.com>
 */

#include <linux/net.h>
#include <linux/rcupdate.h>
#include <net/sock.h>

#include "smc.h"
#include "smc_core.h"
#include "smc_cdc.h"
#include "smc_tx.h" /* smc_tx_consumer_update() */
#include "smc_rx.h"

/* callback implementation for sk.sk_data_ready()
 * to wakeup rcvbuf consumers that blocked with smc_rx_wait_data().
 * indirectly called by smc_cdc_msg_recv_action().
 */
static void smc_rx_data_ready(struct sock *sk)
{
	struct socket_wq *wq;

	/* derived from sock_def_readable() */
	/* called already in smc_listen_worker() */
	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLIN | POLLPRI |
						POLLRDNORM | POLLRDBAND);
	if ((sk->sk_shutdown == SHUTDOWN_MASK) ||
	    (sk->sk_state == SMC_CLOSED))
		sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_HUP);
	else
		sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	rcu_read_unlock();
}

/* blocks rcvbuf consumer until >=len bytes available or timeout or interrupted
 *   @smc    smc socket
 *   @len    num bytes to wait for
 *   @timeo  max seconds to wait, 0 for no timeout
 * Returns:
 * 1 if at least len bytes available in rcvbuf.
 * -EAGAIN in case timeout expired.
 * 0 otherwise (neither enough bytes in rcvbuf nor timeout, e.g. interrupted).
 */
static int smc_rx_wait_data(struct smc_sock *smc, int len, long timeo)
{
	struct smc_connection *conn = &smc->conn;
	struct sock *sk = &smc->sk;
	DEFINE_WAIT(wait);
	int rc;

	if (atomic_read(&conn->bytes_to_rcv) >= len)
		return 1;
	prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	rc = sk_wait_event(sk, &timeo,
			   sk->sk_err ||
			   sk->sk_shutdown & RCV_SHUTDOWN ||
			   sock_flag(sk, SOCK_DONE) ||
			   (atomic_read(&conn->bytes_to_rcv) >= len) ||
			   smc_stop_received(conn));
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	finish_wait(sk_sleep(sk), &wait);
	return (rc || timeo) ? rc : -EAGAIN;
}

/* rcvbuf consumer: main API called by socket layer */
int smc_rx_recvmsg(struct smc_sock *smc, struct msghdr *msg, size_t len,
		   int flags)
{
	size_t read_done = 0, read_remaining = len;
	struct smc_connection *conn = &smc->conn;
	union smc_host_cursor_ovl prod, cons;
	size_t readable, chunk;
	char *rcvbuf_base;
	int to_read;
	long timeo;
	int target;		/* Read at least these many bytes */
	int rc;

	msg->msg_namelen = 0;
	rcvbuf_base = conn->rmb_desc->cpu_addr;
	read_remaining = min_t(size_t, len, conn->rmbe_size); /* cap rx len */

again:
	target = sock_rcvlowat(&smc->sk, flags & MSG_WAITALL, read_remaining);
	timeo = sock_rcvtimeo(&smc->sk, flags & MSG_DONTWAIT);
	if (signal_pending(current))
		return timeo ? -EINTR : -EAGAIN;
	rc = smc_rx_wait_data(smc, target, timeo);
	if ((rc == -EAGAIN) || (rc == -EINTR))
		return rc;
	if (!rc)
		goto again;
	to_read = atomic_read(&conn->bytes_to_rcv);

	if ((to_read <= 0) &&
	    (smc->sk.sk_err ||
	     smc->sk.sk_shutdown & RCV_SHUTDOWN ||
	     sock_flag(&smc->sk, SOCK_DONE) ||
	     smc_stop_received(conn)))
		return sock_error(&smc->sk);

	if (to_read <= 0)
		goto check_repeat;

	if ((to_read < target) && !smc_stop_received(conn))
		goto check_repeat;

	prod.acurs = smc_curs_read(conn->local_rx_ctrl.prod.acurs);
	cons.acurs = smc_curs_read(conn->local_tx_ctrl.cons.acurs);
	if (prod.curs.wrap == cons.curs.wrap) {
		/* unwrapped case: copy 1 single chunk */
		readable = prod.curs.count - cons.curs.count;
		chunk = min(read_remaining, readable);
		if (!(flags & MSG_TRUNC)) {
			if (memcpy_to_msg(msg, rcvbuf_base + cons.curs.count,
					  chunk))
				return -EFAULT;
		}
		read_remaining -= chunk;
		read_done += chunk;
	} else {
		/* wrapped case: top chunk */
		readable = conn->rmbe_size - cons.curs.count;
		if (readable) {
			chunk = min(read_remaining, readable);
			if (!(flags & MSG_TRUNC)) {
				if (memcpy_to_msg(msg,
						  rcvbuf_base + cons.curs.count,
						  chunk))
					return -EFAULT;
			}
			read_remaining -= chunk;
			read_done += chunk;
		}
		/* wrapped case: bottom chunk (if any) */
		if (read_remaining) {
			readable = prod.curs.count;
			chunk = min(read_remaining, readable);
			if (!(flags & MSG_TRUNC)) {
				if (memcpy_to_msg(msg, rcvbuf_base, chunk))
					return -EFAULT;
			}
			read_remaining -= chunk;
			read_done += chunk;
		}
	}

	/* update cursors */
	if (!(flags & MSG_PEEK)) {
		smc_curs_add(conn->rmbe_size, &cons.curs, read_done);
		smp_mb__before_atomic();
		atomic_sub(read_done, &conn->bytes_to_rcv);
		smp_mb__after_atomic();
		xchg(&conn->local_tx_ctrl.cons.acurs, cons.acurs);
		/* send consumer cursor update if required */
		/* analogon to advertising a new TCP rcv_wnd if required */
		smc_tx_consumer_update(conn);
	}
check_repeat:
	if ((to_read < target) &&
	    !smc_stop_received(conn) &&
	    !conn->local_tx_ctrl.conn_state_flags.abnormal_close) {
		goto again;
	}

	return read_done;
}

/* Initialize receive properties on connection establishment. NB: not __init! */
void smc_rx_init(struct smc_sock *smc)
{
	smc->sk.sk_data_ready = smc_rx_data_ready;
}
