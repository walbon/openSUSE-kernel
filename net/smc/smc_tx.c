/*
 * Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 * Manage send buffer.
 * Producer:
 * Copy user space data into send buffer, if send buffer space available.
 * Consumer:
 * Trigger RDMA write into RMBE of peer and send CDC, if RMBE space available.
 *
 * Copyright IBM Corp. 2016
 *
 * Author(s):  Ursula Braun <ursula.braun@de.ibm.com>
 */

#include <linux/net.h>
#include <linux/rcupdate.h>
#include <net/sock.h>

#include "smc.h"
#include "smc_wr.h"
#include "smc_cdc.h"
#include "smc_tx.h"

/***************************** sndbuf producer *******************************/

/* callback implementation for sk.sk_write_space()
 * to wakeup sndbuf producers that blocked with smc_tx_wait_memory()
 */
static void smc_tx_write_space(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;
	struct smc_sock *smc = smc_sk(sk);
	struct socket_wq *wq;

	/* similar to sk_stream_write_space */
	if (atomic_read(&smc->conn.sndbuf_space) && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);
		rcu_read_lock();
		wq = rcu_dereference(sk->sk_wq);
		if (wq_has_sleeper(wq))
			wake_up_interruptible_poll(&wq->wait,
						   POLLOUT | POLLWRNORM |
						   POLLWRBAND);
		if (wq && wq->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
			sock_wake_async(wq, SOCK_WAKE_SPACE, POLL_OUT);
		rcu_read_unlock();
	}
}

/* Wakeup sndbuf producers that blocked with smc_tx_wait_memory().
 * Cf. tcp_data_snd_check()=>tcp_check_space()=>tcp_new_space().
 */
void smc_tx_sndbuf_nonfull(struct smc_sock *smc)
{
	if (smc->sk.sk_socket &&
	    atomic_read(&smc->conn.sndbuf_space) &&
	    test_bit(SOCK_NOSPACE, &smc->sk.sk_socket->flags))
		smc->sk.sk_write_space(&smc->sk);
}

/* sndbuf producer */
static inline int smc_tx_give_up_send(struct smc_sock *smc, int copied)
{
	struct smc_connection *conn = &smc->conn;

	if (smc->sk.sk_shutdown & SEND_SHUTDOWN ||
	    conn->local_tx_ctrl.conn_state_flags.abnormal_close)
		return -EPIPE;
	if (conn->local_rx_ctrl.conn_state_flags.abnormal_close ||
	    conn->local_rx_ctrl.conn_state_flags.closed_conn)
		return copied ? copied : -ECONNRESET;
	return 0;
}

/* blocks sndbuf producer until at least one byte of free space available */
static int smc_tx_wait_memory(struct smc_sock *smc, int flags)
{
	struct smc_connection *conn = &smc->conn;
	struct sock *sk = &smc->sk;
	DEFINE_WAIT(wait);
	long timeo;
	int rc = 0;

	/* similar to sk_stream_wait_memory */
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
	prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN) ||
	    conn->local_tx_ctrl.conn_state_flags.sending_done) {
		rc = -EPIPE;
		goto out;
	}
	if (conn->local_rx_ctrl.conn_state_flags.abnormal_close) {
		rc = -ECONNRESET;
		goto out;
	}
	if (!timeo) {
		rc = -EAGAIN;
		goto out;
	}
	if (signal_pending(current)) {
		rc = -EINTR;
		goto out;
	}
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);
	if (atomic_read(&conn->sndbuf_space))
		goto out;
	set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
	rc = sk_wait_event(sk, &timeo,
			   sk->sk_err ||
			   (sk->sk_shutdown & SEND_SHUTDOWN) ||
			   smc_stop_received(conn) ||
			   atomic_read(&conn->sndbuf_space));
	clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN) ||
	    conn->local_tx_ctrl.conn_state_flags.sending_done) {
		rc = -EPIPE;
	}
	if (conn->local_rx_ctrl.conn_state_flags.abnormal_close)
		rc = -ECONNRESET;
out:
	finish_wait(sk_sleep(sk), &wait);
	return rc;
}

/* sndbuf producer: main API called by socket layer */
int smc_tx_sendmsg(struct smc_sock *smc, struct msghdr *msg, size_t len)
{
	size_t chunk_len, send_done = 0, send_remaining = len;
	struct smc_connection *conn = &smc->conn;
	union smc_host_cursor_ovl prep;
	int tx_top, tx_bot;
	char *sndbuf_base;
	int tx_cnt_prep;
	int writespace;
	int rc;

again:
	if (smc->sk.sk_state == SMC_INIT)
		return -ENOTCONN;
	if (smc->sk.sk_state != SMC_ACTIVE)
		return -ECONNRESET;
	rc = smc_tx_give_up_send(smc, send_done);
	if (rc)
		return rc;
	/* what to do in case of smc->sk.sk_err ??? */

	writespace = atomic_read(&conn->sndbuf_space);
	if (!writespace) {
		int wait_rc;

		wait_rc = smc_tx_wait_memory(smc, msg->msg_flags);
		if (wait_rc < 0)
			return ((send_done && (wait_rc == -EAGAIN))
			       ? send_done : wait_rc);
		if (!wait_rc) {
			rc = smc_tx_give_up_send(smc, send_done);
			if (rc)
				return rc;
			if (msg->msg_flags & MSG_DONTWAIT)
				return send_done ? send_done : -EAGAIN;
			if (smc->sk.sk_err)
				return send_done ? send_done : -EPIPE;
			goto again;
		}
	}
	if (smc->sk.sk_err)
		return -EPIPE;
	rc = smc_tx_give_up_send(smc, send_done);
	if (rc)
		return rc;

	/* re-calc, could be just 1 byte after smc_tx_wait_memory above */
	writespace = atomic_read(&conn->sndbuf_space);
	chunk_len = min_t(size_t, send_remaining, writespace);
	/* determine start of sndbuf */
	prep.acurs = smc_curs_read(conn->tx_curs_prep.acurs);
	tx_cnt_prep = prep.curs.count;
	sndbuf_base = conn->sndbuf_desc->cpu_addr;
	/* determine sndbuf chunks - top and bottom of sndbuf */
	if (tx_cnt_prep + chunk_len <= conn->sndbuf_size) {
		tx_top = 0;
		tx_bot = chunk_len;
		if (memcpy_from_msg(sndbuf_base + tx_cnt_prep, msg, chunk_len))
			return -EFAULT;
	} else {
		tx_bot = conn->sndbuf_size - tx_cnt_prep;
		tx_top = chunk_len - tx_bot;
		if (memcpy_from_msg(sndbuf_base + tx_cnt_prep, msg, tx_bot))
			return -EFAULT;
		if (memcpy_from_msg(sndbuf_base, msg, tx_top))
			return -EFAULT;
	}
	smc_curs_add(conn->sndbuf_size, &prep.curs, chunk_len);
	xchg(&conn->tx_curs_prep.acurs, prep.acurs);
	smp_mb__before_atomic();
	atomic_sub(chunk_len, &conn->sndbuf_space);
	smp_mb__after_atomic();

	/* since we just produced more new data into sndbuf,
	 * trigger sndbuf consumer: RDMA write into peer RMBE and CDC
	 */
	rc = smc_tx_sndbuf_nonempty(conn);
	if (rc)
		return rc;

	send_done += chunk_len;
	send_remaining -= chunk_len;
	if (send_done < len)
		goto again;

	return send_done;
}

/***************************** sndbuf consumer *******************************/

/* sndbuf consumer: actual data transfer of one target chunk with RDMA write */
static int smc_tx_rdma_write(struct smc_connection *conn, int peer_rmbe_offset,
			     int num_sges, struct ib_sge sges[])
{
	struct smc_link_group *lgr = conn->lgr;
	struct ib_send_wr *failed_wr = NULL;
	struct ib_rdma_wr rdma_wr;
	struct smc_link *link;
	int i, rc;

	memset(&rdma_wr, 0, sizeof(rdma_wr));
	link = &lgr->lnk[SMC_SINGLE_LINK];
	for (i = 0; i < num_sges; i++) {
		sges[i].addr =
			conn->sndbuf_desc->dma_addr[SMC_SINGLE_LINK] +
			sges[i].addr;
		sges[i].lkey = link->mr_tx->lkey;
	}
	rdma_wr.wr.wr_id = smc_wr_tx_get_next_wr_id(link);
	rdma_wr.wr.sg_list = sges;
	rdma_wr.wr.num_sge = num_sges;
	rdma_wr.wr.opcode = IB_WR_RDMA_WRITE;
	rdma_wr.remote_addr =
		lgr->rtokens[conn->rtoken_idx][SMC_SINGLE_LINK].dma_addr +
		peer_rmbe_offset +
		((conn->peer_conn_idx - 1) * (conn->peer_rmbe_len));
	rdma_wr.rkey = lgr->rtokens[conn->rtoken_idx][SMC_SINGLE_LINK].rkey;
	rc = ib_post_send(link->roce_qp, &rdma_wr.wr, &failed_wr);
	if (rc)
		conn->local_tx_ctrl.conn_state_flags.abnormal_close = 1;
	return rc;
}

/* sndbuf consumer */
static inline void smc_tx_fill_sges(int *num_sges, struct ib_sge sges[],
				    u64 sge_offset1, u32 sge_len1,
				    u64 sge_offset2, u32 sge_len2)
{
	memset(sges, 0, SMC_IB_MAX_SEND_SGE * sizeof(sges[0]));
	sges[0].addr = sge_offset1;
	sges[0].length = sge_len1;
	if (sge_len2) {
		*num_sges = 2;
		sges[1].addr = sge_offset2;
		sges[1].length = sge_len2;
	} else {
		*num_sges = 1;
	}
}

/* sndbuf consumer */
static inline void smc_tx_advance_cursors(struct smc_connection *conn,
					  union smc_host_cursor_ovl *prod,
					  union smc_host_cursor_ovl *sent,
					  size_t len)
{
	smc_curs_add(conn->peer_rmbe_len, &prod->curs, len);
	smp_mb__before_atomic();
	/* data in flight reduces usable snd_wnd */
	atomic_sub(len, &conn->peer_rmbe_space);
	smp_mb__after_atomic();
	smc_curs_add(conn->sndbuf_size, &sent->curs, len);
}

/* sndbuf consumer: prepare all necessary (src&dst) chunks of data transmit;
 * usable snd_wnd as max transmit
 */
static int smc_tx_rdma_writes(struct smc_connection *conn)
{
	union smc_host_cursor_ovl sent, prep, prod, cons;
	size_t to_copy, space1, space2, send_len;
	struct ib_sge sges[SMC_IB_MAX_SEND_SGE];
	size_t tx_top1, tx_top2;
	size_t tx_bot1, tx_bot2;
	size_t tx_top,  tx_bot;
	int to_send, rmbespace;
	int num_sges;
	int rc;

	sent.acurs = smc_curs_read(conn->tx_curs_sent.acurs);
	prep.acurs = smc_curs_read(conn->tx_curs_prep.acurs);

	/* cf. wmem_alloc - (snd_max - snd_una) */
	to_send = smc_curs_diff(conn->sndbuf_size, &sent, &prep);
	if (to_send <= 0)
		return 0;

	/* cf. snd_wnd */
	rmbespace = atomic_read(&conn->peer_rmbe_space);
	if (rmbespace <= 0)
		return 0;

	if (to_send >= rmbespace)
		conn->local_tx_ctrl.prod_flags.write_blocked = 1;
	else
		conn->local_tx_ctrl.prod_flags.write_blocked = 0;

	/* cf. usable snd_wnd */
	to_copy = min(to_send, rmbespace);

	if (sent.curs.count + to_copy <= conn->peer_rmbe_len) {
		tx_top = 0;
		tx_bot = to_copy;
	} else {
		tx_bot = conn->sndbuf_size - sent.curs.count;
		tx_top = to_copy - tx_bot;
	}
	prod.acurs = smc_curs_read(conn->local_tx_ctrl.prod.acurs);
	cons.acurs = smc_curs_read(conn->local_rx_ctrl.cons.acurs);
	if (prod.curs.wrap == cons.curs.wrap) {
		space1 = conn->peer_rmbe_len - prod.curs.count;
		space2 = cons.curs.count;

		send_len = min(to_copy, space1);
		if (send_len <= tx_bot) {
			tx_bot1 = send_len;
			tx_bot2 = tx_bot - tx_bot1;
			tx_top1 = 0;
			tx_top2 = tx_top;
		} else {
			tx_bot1 = tx_bot;
			tx_bot2 = 0;
			tx_top1 = send_len - tx_bot;
			tx_top2 = tx_top - tx_top1;
		}
		smc_tx_fill_sges(&num_sges, sges, sent.curs.count, tx_bot1, 0,
				 tx_top1);
		rc = smc_tx_rdma_write(conn, prod.curs.count, num_sges, sges);
		if (rc)
			return rc;
		to_copy -= send_len;
		smc_tx_advance_cursors(conn, &prod, &sent, send_len);

		if (to_copy && space2 && (tx_bot2 + tx_top2 > 0)) {
			send_len = min(to_copy, space2);
			if (tx_bot2 > send_len) {
				tx_bot2 = send_len;
				tx_top2 = 0;
			} else {
				if (tx_bot2 + tx_top2 > send_len)
					tx_top2 = send_len - tx_bot2;
			}
			if (tx_bot2)
				smc_tx_fill_sges(&num_sges, sges,
						 sent.curs.count,
						 tx_bot2, tx_top1, tx_top2);
			else if (tx_top2)
				smc_tx_fill_sges(&num_sges, sges, tx_top1,
						 tx_top2, 0, 0);
			rc = smc_tx_rdma_write(conn, 0, num_sges, sges);
			if (rc)
				return rc;
			smc_tx_advance_cursors(conn, &prod, &sent,
					       tx_bot2 + tx_top2);
		}
	} else {
		space1 = cons.curs.count - prod.curs.count;
		send_len = min(to_copy, space1);
		if (send_len <= tx_bot) {
			tx_bot = send_len;
			tx_top = 0;
		} else {
			if ((send_len - tx_bot) <= tx_top)
				tx_top = send_len - tx_bot;
		}
		smc_tx_fill_sges(&num_sges, sges, sent.curs.count, tx_bot, 0,
				 tx_top);
		rc = smc_tx_rdma_write(conn, prod.curs.count, num_sges, sges);
		if (rc)
			return rc;
		smc_tx_advance_cursors(conn, &prod, &sent, send_len);
	}
	xchg(&conn->local_tx_ctrl.prod.acurs, prod.acurs);
	xchg(&conn->tx_curs_sent.acurs, sent.acurs);

	return 0;
}

/* Wakeup sndbuf consumers from any context (IRQ or process)
 * since there is more data to transmit; usable snd_wnd as max transmit
 */
int smc_tx_sndbuf_nonempty(struct smc_connection *conn)
{
	struct smc_cdc_tx_pend *pend;
	struct smc_wr_buf *wr_buf;
	int rc;

	spin_lock_bh(&conn->send_lock);
	rc = smc_cdc_get_free_slot(&conn->lgr->lnk[SMC_SINGLE_LINK], &wr_buf,
				   &pend);
	if (rc < 0) {
		schedule_delayed_work(&conn->tx_work, HZ / 10);
		goto out_unlock;
	}

	rc = smc_tx_rdma_writes(conn);
	if (rc) {
		smc_wr_tx_put_slot(&conn->lgr->lnk[SMC_SINGLE_LINK],
				   (struct smc_wr_tx_pend_priv *)pend);
		goto out_unlock;
	}

	rc = smc_cdc_msg_send(conn, wr_buf, pend);

out_unlock:
	spin_unlock_bh(&conn->send_lock);
	return rc;
}

int smc_tx_close_wr(struct smc_connection *conn)
{
	struct smc_cdc_tx_pend *pend;
	struct smc_wr_buf *wr_buf;
	int rc;

	conn->local_tx_ctrl.conn_state_flags.sending_done = 1;

	rc = smc_cdc_get_free_slot(&conn->lgr->lnk[SMC_SINGLE_LINK], &wr_buf,
				   &pend);

	rc = smc_cdc_msg_send(conn, wr_buf, pend);

	return rc;
}

int smc_tx_close(struct smc_connection *conn)
{
	struct smc_cdc_tx_pend *pend;
	struct smc_wr_buf *wr_buf;
	int rc;

	if (atomic_read(&conn->bytes_to_rcv))
		conn->local_tx_ctrl.conn_state_flags.abnormal_close = 1;
	else
		conn->local_tx_ctrl.conn_state_flags.closed_conn = 1;

	rc = smc_cdc_get_free_slot(&conn->lgr->lnk[SMC_SINGLE_LINK], &wr_buf,
				   &pend);

	rc = smc_cdc_msg_send(conn, wr_buf, pend);

	return rc;
}

/* Wakeup sndbuf consumers from process context
 * since there is more data to transmit
 */
static void smc_tx_worker(struct work_struct *work)
{
	struct smc_connection *conn = container_of(to_delayed_work(work),
						   struct smc_connection,
						   tx_work);
	struct smc_sock *smc = container_of(conn, struct smc_sock, conn);

	lock_sock(&smc->sk);
	smc_tx_sndbuf_nonempty(conn);
	release_sock(&smc->sk);
}

void smc_tx_consumer_update(struct smc_connection *conn)
{
	union smc_host_cursor_ovl cfed, cons;
	struct smc_cdc_tx_pend *pend;
	struct smc_wr_buf *wr_buf;
	int to_confirm, rc;

	cons.acurs = smc_curs_read(conn->local_tx_ctrl.cons.acurs);
	cfed.acurs = smc_curs_read(conn->rx_curs_confirmed.acurs);
	to_confirm = smc_curs_diff(conn->rmbe_size, &cfed, &cons);

	if (conn->local_rx_ctrl.prod_flags.cons_curs_upd_req ||
	    ((to_confirm > conn->rmbe_update_limit) &&
	     ((to_confirm / (conn->rmbe_size / 2) > 0) ||
	      conn->local_rx_ctrl.prod_flags.write_blocked))) {
		rc = smc_cdc_get_free_slot(&conn->lgr->lnk[SMC_SINGLE_LINK],
					   &wr_buf, &pend);
		if (!rc)
			rc = smc_cdc_msg_send(conn, wr_buf, pend);
		if (rc < 0) {
			schedule_delayed_work(&conn->tx_work, HZ / 10);
			return;
		}
		xchg(&conn->rx_curs_confirmed.acurs,
		     smc_curs_read(conn->local_tx_ctrl.cons.acurs));
		conn->local_rx_ctrl.prod_flags.cons_curs_upd_req = 0;
	}
	if (conn->local_rx_ctrl.prod_flags.write_blocked &&
	    !atomic_read(&conn->bytes_to_rcv))
		conn->local_rx_ctrl.prod_flags.write_blocked = 0;
}

/***************************** send initialize *******************************/

/* Initialize send properties on connection establishment. NB: not __init! */
void smc_tx_init(struct smc_sock *smc)
{
	smc->sk.sk_write_space = smc_tx_write_space;
	INIT_DELAYED_WORK(&smc->conn.tx_work, smc_tx_worker);
	spin_lock_init(&smc->conn.send_lock);
}
