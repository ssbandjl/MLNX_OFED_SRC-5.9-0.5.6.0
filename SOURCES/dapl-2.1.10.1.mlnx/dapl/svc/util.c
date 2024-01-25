/*
 * Copyright (c) 2012-2014 Intel Corporation. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/*
 * mpxyd service - util.c
 *
 * 	helper functions
 *
 */
#include "mpxyd.h"

/*
 * Service options - set through mpxyd.conf file.
 */
char *opts_file = MPXYD_CONF;
char log_file[128] = "/tmp/mpxyd.log";
int log_level = 0;
char lock_file[128] = "/var/run/mpxyd.pid";
char gid_str[INET6_ADDRSTRLEN];
int mcm_profile = 0;
FILE *logfile;
mpxy_lock_t flock;

/* mcm.c */
extern int mcm_depth;
extern int mcm_size;
extern int mcm_signal;
extern int mcm_max_rcv;
extern int mcm_retry;
extern int mcm_disc_retry;
extern int mcm_rep_ms;
extern int mcm_rtu_ms;
extern int mcm_dreq_ms;
extern int mcm_proxy_in;
extern int mcm_mic0_mss;
extern int mcm_mic1_mss;

/* mix.c */
extern int mix_align;
extern int mix_buffer_sg_cnt;
extern int mix_cmd_depth;
extern int mix_cmd_size;
extern int mix_shared_buffer;
extern int mix_max_msg_mb;
extern int mix_inline_threshold;
extern int mix_eager_completion;

extern int mcm_ib_inline;
extern int mcm_rw_signal;
extern int mcm_rr_signal;
extern int mcm_rr_max;
extern int mcm_wr_max;
extern int mcm_wc_max;
extern int mcm_tx_entries;
extern int mcm_rx_entries;
extern int mcm_rx_cq_size;

/* mpxyd.c */
extern short scif_sport;
extern int scif_listen_qlen;
extern int mix_buffer_mb;
extern int mix_buffer_sg;
extern int mix_buffer_sg_po2;
extern int mcm_affinity;
extern int mcm_affinity_base_mic;
extern int mcm_affinity_base_hca;
extern int mcm_op_poll;
extern int mcm_counters;

/* Counters */
static char *mcm_cntr_names[] = {
	"MCM_IA_OPEN",
	"MCM_IA_CLOSE",
	"MCM_PD_CREATE",
	"MCM_PD_FREE",
	"MCM_MR_CREATE",
	"MCM_MR_FREE",
	"MCM_CQ_CREATE",
	"MCM_CQ_FREE",
	"MCM_CQ_POLL",
	"MCM_CQ_REARM",
	"MCM_CQ_EVENT",
	"MCM_MX_SEND",
	"MCM_MX_SEND_INLINE",
	"MCM_MX_WRITE",
	"MCM_MX_WRITE_SEG",
	"MCM_MX_WRITE_INLINE",
	"MCM_MX_WR_STALL",
	"MCM_MX_MR_STALL",
	"MCM_MX_RR_STALL",
	"MCM_QP_CREATE",
	"MCM_QP_SEND",
	"MCM_QP_SEND_INLINE",
	"MCM_QP_WRITE",
	"MCM_QP_WRITE_INLINE",
	"MCM_QP_WRITE_DONE",
	"MCM_QP_READ",
	"MCM_QP_READ_DONE",
	"MCM_QP_RECV",
	"MCM_QP_FREE",
	"MCM_QP_EVENT",
	"MCM_SRQ_CREATE",
	"MCM_SRQ_FREE",
	"MCM_MEM_ALLOC",
	"MCM_MEM_ALLOC_DATA",
	"MCM_MEM_FREE",
	"MCM_ASYNC_ERROR",
	"MCM_ASYNC_QP_ERROR",
	"MCM_ASYNC_CQ_ERROR",
	"MCM_SCIF_SEND",
	"MCM_SCIF_RECV",
	"MCM_SCIF_READ_FROM",
	"MCM_SCIF_READ_FROM_DONE",
	"MCM_SCIF_WRITE_TO",
	"MCM_SCIF_WRITE_TO_DONE",
	"MCM_SCIF_SIGNAL",
	"MCM_LISTEN_CREATE",
	"MCM_LISTEN_CREATE_ANY",
	"MCM_LISTEN_FREE",
	"MCM_CM_CONN_EVENT",
	"MCM_CM_DISC_EVENT",
	"MCM_CM_TIMEOUT_EVENT",
	"MCM_CM_ERR_EVENT",
	"MCM_CM_TX_POLL",
	"MCM_CM_RX_POLL",
	"MCM_CM_MSG_OUT",
	"MCM_CM_MSG_IN",
	"MCM_CM_MSG_POST",
	"MCM_CM_REQ_OUT",
	"MCM_CM_REQ_IN",
	"MCM_CM_REQ_ACCEPT",
	"MCM_CM_REP_OUT",
	"MCM_CM_REP_IN",
	"MCM_CM_RTU_OUT",
	"MCM_CM_RTU_IN",
	"MCM_CM_REJ_OUT",
	"MCM_CM_REJ_IN",
	"MCM_CM_REJ_USER_OUT",
	"MCM_CM_REJ_USER_IN",
	"MCM_CM_ACTIVE_EST",
	"MCM_CM_PASSIVE_EST",
	"MCM_CM_AH_REQ_OUT",
	"MCM_CM_AH_REQ_IN",
	"MCM_CM_AH_RESOLVED",
	"MCM_CM_DREQ_OUT",
	"MCM_CM_DREQ_IN",
	"MCM_CM_DREQ_DUP",
	"MCM_CM_DREP_OUT",
	"MCM_CM_DREP_IN",
	"MCM_CM_MRA_OUT",
	"MCM_CM_MRA_IN",
	"MCM_CM_REQ_FULLQ_POLL",
	"MCM_CM_ERR",
	"MCM_CM_ERR_REQ_FULLQ",
	"MCM_CM_ERR_REQ_DUP",
	"MCM_CM_ERR_REQ_RETRY",
	"MCM_CM_ERR_REP_DUP",
	"MCM_CM_ERR_REP_RETRY",
	"MCM_CM_ERR_RTU_DUP",
	"MCM_CM_ERR_RTU_RETRY",
	"MCM_CM_ERR_REFUSED",
	"MCM_CM_ERR_RESET",
	"MCM_CM_ERR_TIMEOUT",
	"MCM_CM_ERR_REJ_TX",
	"MCM_CM_ERR_REJ_RX",
	"MCM_CM_ERR_DREQ_DUP",
	"MCM_CM_ERR_DREQ_RETRY",
	"MCM_CM_ERR_DREP_DUP",
	"MCM_CM_ERR_DREP_RETRY",
	"MCM_CM_ERR_MRA_DUP",
	"MCM_CM_ERR_MRA_RETRY",
	"MCM_CM_ERR_UNEXPECTED_STATE",
	"MCM_CM_ERR_UNEXPECTED_MSG",
};

void mpxy_write(int level, const char *format, ...)
{
	va_list args;
	uint32_t ts;

	if (level && !(level & log_level))
		return;

	ts = mcm_ts_us();
	va_start(args, format);
	mpxy_lock(&flock);
	fprintf(logfile, " %x:%u: ", (unsigned)pthread_self(), ts);
	vfprintf(logfile, format, args);
	fflush(logfile);
	mpxy_unlock(&flock);
	va_end(args);
}

void md_cntr_log(mcm_ib_dev_t *md, int counter, int reset) {
	int i;

	mlog(0, "MPXYD Device Counters:\n");
	for (i = 0; i < MCM_ALL_COUNTERS; i++) {
		if ((counter == i) || (counter == MCM_ALL_COUNTERS)) {
			if (((uint64_t *)md->cntrs)[i]) {
				mlog(0, "%s = %llu\n", mcm_cntr_names[i], ((uint64_t *)md->cntrs)[i]);
				if (reset)
					((uint64_t *)md->cntrs)[i] = 0;
			}
		}
	}
	mlog(0, "return:\n");
}

/* FD and thread helper resources */
struct mcm_fd_set *mcm_alloc_fd_set(void)
{
	return malloc(sizeof(struct mcm_fd_set));
}

void mcm_fd_zero(struct mcm_fd_set *set)
{
	set->index = 0;
}

int mcm_fd_set(int fd, struct mcm_fd_set *set, int event)
{
	if (set->index == MCM_FD_SETSIZE - 1) {
		mlog(0," mcm exceeded FD_SETSIZE %d\n", MCM_FD_SETSIZE);
		return -1;
	}
	set->set[set->index].fd = fd;
	set->set[set->index].revents = 0;
	set->set[set->index++].events = event;
	return 0;
}

int mcm_config_fd(int fd)
{
	int opts;

	opts = fcntl(fd, F_GETFL);
	if (opts < 0 || fcntl(fd, F_SETFL, opts | O_NONBLOCK) < 0) {
		mlog(0, " config_fd: fcntl on fd %d ERR %d %s\n", fd, opts, strerror(errno));
		return errno;
	}
	return 0;
}

int mcm_poll(int fd, int event)
{
	struct pollfd fds;
	int ret;

	fds.fd = fd;
	fds.events = event;
	fds.revents = 0;
	ret = poll(&fds, 1, 0);

	if (ret == 0)
		return 0;
	else if (fds.revents & (POLLERR | POLLHUP | POLLNVAL))
		return POLLERR;
	else
		return fds.revents;
}

int mcm_select(struct mcm_fd_set *set, int time_ms)
{
	int ret, i;

	if (time_ms != -1)
		sched_yield();

	mlog(0x20, " sleep, fds=%d\n", set->index);
	ret = poll(set->set, set->index, time_ms);
	if (ret > 0) {
		for (i=0;i<set->index;i++) {
			mlog(0x20, " wakeup, set[%d].fd %d = %d\n",
				   i, set->set[i].fd, set->set[i].revents);
		}
	}
	return ret;
}

/* MCM 16-bit port space */
uint16_t mcm_get_port(uint64_t *p_port, uint16_t port, uint64_t ctx)
{
	int i = 0;

	/* get specific port */
	if (port) {
		if (p_port[port] == 0) {
			p_port[port] = ctx;
			i = port;
		}
		goto done;
	}

	/* get first free port */
	for (i = MCM_PORT_SPACE; i > 0; i--) {
		if (p_port[i] == 0) {
			p_port[i] = ctx;
			break;
		}
	}
done:
	return i;
}

uint64_t mcm_get_port_ctx(uint64_t *p_port, uint16_t port)
{
	return p_port[port];
}

FILE *mpxy_open_log(void)
{
	FILE *f;

	if (!strcasecmp(log_file, "stdout"))
		return stdout;

	if (!strcasecmp(log_file, "stderr"))
		return stderr;

	if (!(f = fopen(log_file, "w")))
		f = stdout;

	return f;
}

void mpxy_set_options( int debug_mode )
{
	FILE *f;
	char s[120];
	char opt[32], value[128];

	if (!(f = fopen(opts_file, "r")))
		return;

	while (fgets(s, sizeof s, f)) {
		if (s[0] == '#')
			continue;

		if (sscanf(s, "%32s%128s", opt, value) != 2)
			continue;

		if (!strcasecmp("log_file", opt))
			strcpy(log_file, value);
		else if (!strcasecmp("log_level", opt))
			log_level = strtol(value,NULL,0);
		else if (!strcasecmp("lock_file", opt))
			strcpy(lock_file, value);
		else if (!strcasecmp("max_message_mb", opt))
			mix_max_msg_mb = atoi(value);
		else if (!strcasecmp("buffer_pool_mb", opt))
			mix_buffer_mb = atoi(value);
		else if (!strcasecmp("buffer_segment_size", opt))
		{
			int i = 0, ssize = atoi(value); /* power of 2 */
			mix_buffer_sg = 1;
			while ((mix_buffer_sg < ssize) &&
			       (mix_buffer_sg < DAT_MIX_RDMA_MAX)) {
				mix_buffer_sg <<= 1;
				i++;
			}
			mix_buffer_sg_po2 = i;
		}
		else if (!strcasecmp("buffer_alignment", opt))
			mix_align = atoi(value);
		else if (!strcasecmp("buffer_inline_threshold", opt))
		{
			mix_inline_threshold = atoi(value);
			if (mix_inline_threshold > DAT_MIX_INLINE_MAX)
				mix_inline_threshold = DAT_MIX_INLINE_MAX;
		}
		else if (!strcasecmp("mcm_depth", opt))
			mcm_depth = atoi(value);
		else if (!strcasecmp("scif_port_id", opt))
			scif_sport = (short) atoi(value);
		else if (!strcasecmp("scif_listen_qlen", opt))
			scif_listen_qlen = atoi(value);
		else if (!strcasecmp("mcm_rr_signal_rate", opt))
			mcm_rr_signal = atoi(value);
		else if (!strcasecmp("mcm_rw_signal_rate", opt))
			mcm_rw_signal = atoi(value);
		else if (!strcasecmp("mcm_rr_max_pending", opt))
			mcm_rr_max = atoi(value);
		else if (!strcasecmp("mcm_wr_max", opt))
			mcm_wr_max = atoi(value);
		else if (!strcasecmp("mcm_wc_max", opt))
			mcm_wc_max = atoi(value);
		else if (!strcasecmp("mcm_req_timeout_ms", opt))
			mcm_rep_ms = atoi(value);
		else if (!strcasecmp("mcm_rep_timeout_ms", opt))
			mcm_rtu_ms = atoi(value);
		else if (!strcasecmp("mcm_retry_count", opt))
			mcm_retry = atoi(value);
		else if (!strcasecmp("mcm_affinity", opt)) {
			mcm_affinity = atoi(value);
			if (mcm_affinity == 2)
				mcm_op_poll = 1;
		} else if (!strcasecmp("mcm_affinity_base_hca", opt))
			mcm_affinity_base_hca = atoi(value);
		else if (!strcasecmp("mcm_affinity_base_mic", opt))
			mcm_affinity_base_mic = atoi(value);
		else if (!strcasecmp("mcm_ib_inline", opt)) {
			mcm_ib_inline = atoi(value);
			if (mcm_ib_inline)
				mcm_ib_inline = max(atoi(value), MCM_IB_INLINE);
		}
		else if (!strcasecmp("mcm_perf_profile", opt))
			mcm_profile = atoi(value);
		else if (!strcasecmp("mcm_eager_completion", opt))
			mix_eager_completion = atoi(value);
		else if (!strcasecmp("mcm_counters", opt))
			mcm_counters = atoi(value);
		else if (!strcasecmp("mcm_proxy_in", opt))
			mcm_proxy_in = atoi(value);
		else if (!strcasecmp("mcm_op_poll", opt))
			mcm_op_poll = atoi(value);
		else if (!strcasecmp("proxy_tx_depth", opt))
		{
			int tsize = atoi(value); /* power of 2 */
			mcm_tx_entries = 1;
			while (mcm_tx_entries < tsize)
				mcm_tx_entries <<= 1;
		}
		else if (!strcasecmp("proxy_rx_depth", opt))
		{
			int rsize = atoi(value); /* power of 2 */
			mcm_rx_entries = 1;
			while (mcm_rx_entries < rsize)
				mcm_rx_entries <<= 1;
		}
		else if (!strcasecmp("mcm_mic0_mss", opt))
			mcm_mic0_mss = atoi(value);
		else if (!strcasecmp("mcm_mic1_mss", opt))
			mcm_mic1_mss = atoi(value);
	}

	fclose(f);

	if (debug_mode) {
		sprintf(log_file, "/tmp/mpxyd.log.pid.%d", getuid());
		sprintf(lock_file, "/tmp/mpxyd.pid.%d", getuid());
	}
}

void mpxy_log_options(void)
{
	mlog(0, "log level 0x%x\n", log_level);
	mlog(0, "lock file %s\n", lock_file);
	mlog(0, "configuration file %s\n", opts_file);
	mlog(0, "SCIF server_port %d%s\n", scif_sport, scif_sport?"":"(auto)");
	mlog(0, "SCIF listen queue length %d\n", scif_listen_qlen);
	mlog(0, "CPU affinity enabled %d\n", mcm_affinity);
	mlog(0, "CPU affinity base core_id for MICs %d\n", mcm_affinity_base_mic);
	mlog(0, "OP thread polling %s\n", mcm_op_poll ? "enabled":"disabled");
	mlog(0, "RDMA buffer pool size %d MB\n", mix_buffer_mb);
	mlog(0, "RDMA buffer segment size %d\n", mix_buffer_sg);
	mlog(0, "RDMA buffer alignment %d\n", mix_align);
	mlog(0, "RDMA Proxy TX queue depth %d\n", mcm_tx_entries);
	mlog(0, "RDMA Proxy RX queue depth %d\n", mcm_rx_entries);
	mlog(0, "RDMA SCIF inline threshold %d\n", mix_inline_threshold);
	mlog(0, "RDMA IB inline threshold %d\n", mcm_ib_inline);
	mlog(0, "RDMA eager completion %d\n", mix_eager_completion);
	mlog(0, "RDMA proxy-out signal rate %d\n", mcm_rw_signal);
	mlog(0, "RDMA proxy-out/in max WR processing %d\n", mcm_wr_max);
	mlog(0, "RDMA proxy-out/in max WC processing %d\n", mcm_wc_max);
	mlog(0, "RDMA proxy-in %s\n", mcm_proxy_in ? "enabled":"disabled");
	if (mcm_proxy_in) {
		mlog(0, "RDMA proxy-in signal rate %d\n", mcm_rr_signal);
		mlog(0, "RDMA proxy-in max reads outstanding %d\n", mcm_rr_max);
	}
	mlog(0, "Maximum message size %d MB\n", mix_max_msg_mb);
	mlog(0, "CM msg queue depth %d\n", mcm_depth);
	mlog(0, "CM msg completion signal rate %d\n", mcm_signal);
	mlog(0, "CM msg reply timeout %d ms\n", mcm_rep_ms);
	mlog(0, "CM msg rtu timeout %d ms\n", mcm_rtu_ms);
	mlog(0, "CM msg retry count %d\n", mcm_retry);
	mlog(0, "Performance Profiling == %d\n", mcm_profile);
	mlog(0, "MPXYD log device counters (print at close) == %d\n", mcm_counters);
}

int lock_fd;
int mpxy_open_lock_file(void)
{
	int rc;
	char pid[16];

	lock_fd = open(lock_file, O_RDWR | O_CREAT | O_EXCL, 0640);
	if (lock_fd < 0) {
		perror(lock_file);
		return lock_fd;
	}

	if (lockf(lock_fd, F_TLOCK, 0)) {
		perror(lock_file);
		close(lock_fd);
		return -1;
	}

	rc = sprintf(pid, "%d", getpid());

	if (write(lock_fd, pid, strlen(pid)) != rc) {
		perror(lock_file);
		return -1;
	}

	return 0;
}

void mpxyd_release_lock_file( void )
{
	lockf(lock_fd, F_ULOCK, 0);
	close(lock_fd);
	unlink(lock_file);
}

int rd_dev_file(char *path, char *file, char *v_str, int len)
{
	char *f_path;
	int fd;

	if (asprintf(&f_path, "%s/%s", path, file) < 0)
		return -1;

	fd = open(f_path, O_RDONLY);
	if (fd < 0) {
		free(f_path);
		return -1;
	}

	len = read(fd, v_str, len);

	if ((len > 0) && (v_str[--len] == '\n'))
		v_str[len] = '\0';

	close(fd);
	free(f_path);
	return 0;
}

int mpxy_cpuinfo_atoi(const char *v_str)
{
	char r_buf[500];
	char *f_path = "/proc/cpuinfo";
	char *token = ":";
	int i, ii, fd, len, v_len, r_len;
	int val = 0;

	fd = open(f_path, O_RDONLY);
	if (fd < 0)
		return val;

	v_len = strlen(v_str);
	r_len = sizeof(r_buf) - 1;
	len = read(fd, r_buf, r_len);

	if (len < 1)
		return val;

	/* get value pattern followed by : followed by value */
	for (i=0; i < len; i++) {
		for (ii=0; ii < v_len && i < len; ii++, i++) {
			if ((v_str[ii] == r_buf[i]) && (ii == v_len-1))
				for (; i < len; i++) {
					if (!strncmp(&r_buf[i], token, 1)) {
						val = atoi(&r_buf[i+1]);
						i = len;
					}
				}
			else if (v_str[ii] != r_buf[i])
				break;
		}
	}

	close(fd);
	return val;
}

#ifdef MCM_PROFILE
void mcm_qp_prof_pr(struct mcm_qp *m_qp, int type)
{
	if ((m_qp->ts.wt.min) &&
	    (type == MCM_QP_WT || type == MCM_QP_ALL))
		mlog(0, " QP (%p) PERF scif_WT() times (usecs):"
			" max %u min %u avg %u ttime %u cnt %u - et %u avg %u\n",
			m_qp, m_qp->ts.wt.max, m_qp->ts.wt.min,
			m_qp->ts.wt.avg, m_qp->ts.wt.all, m_qp->ts.wt.cnt,
			m_qp->ts.wt.stop - m_qp->ts.wt.start,
			(m_qp->ts.wt.stop - m_qp->ts.wt.start)/m_qp->ts.wt.cnt);

	if ((m_qp->ts.rf.min) &&
	    (type == MCM_QP_RF || type == MCM_QP_ALL))
		mlog(0, " QP (%p) PERF scif_RF() times (usecs):"
			" max %u min %u avg %u ttime %u cnt %u - et %u avg %u\n",
			m_qp, m_qp->ts.rf.max, m_qp->ts.rf.min,
			m_qp->ts.rf.avg, m_qp->ts.rf.all, m_qp->ts.rf.cnt,
			m_qp->ts.rf.stop - m_qp->ts.rf.start,
			(m_qp->ts.rf.stop - m_qp->ts.rf.start)/m_qp->ts.rf.cnt);

	if ((m_qp->ts.rw.min) &&
	    (type == MCM_QP_IB_RW || type == MCM_QP_ALL))
		mlog(0, " QP (%p) PERF %s times (usecs):"
			" max %u min %u avg %u ttime %u cnt %u - et %u avg %u\n",
			m_qp, "ib_RW or RW_imm+RR",
			m_qp->ts.rw.max, m_qp->ts.rw.min,
			m_qp->ts.rw.avg, m_qp->ts.rw.all, m_qp->ts.rw.cnt,
			m_qp->ts.rw.stop - m_qp->ts.rw.start,
			(m_qp->ts.rw.stop - m_qp->ts.rw.start)/m_qp->ts.rw.cnt);

	if ((m_qp->ts.rr.min) &&
	    (type == MCM_QP_IB_RR || type == MCM_QP_ALL))
		mlog(0, " QP (%p) PERF ib_RR() times (usecs):"
			" max %u min %u avg %u ttime %u cnt %u - et %u avg %u\n",
			m_qp, m_qp->ts.rr.max, m_qp->ts.rr.min,
			m_qp->ts.rr.avg, m_qp->ts.rr.all, m_qp->ts.rr.cnt,
			m_qp->ts.rr.stop - m_qp->ts.rr.start,
			(m_qp->ts.rr.stop - m_qp->ts.rr.start)/m_qp->ts.rr.cnt);

	if ((m_qp->ts.ps.min) &&
	    (type == MCM_QP_PO_POST || type == MCM_QP_ALL))
		mlog(0, " QP (%p) PERF send_post() times:"
			" (usecs): max %u min %u avg %u ttime %u cnt %u - et %u avg %u\n",
			m_qp, m_qp->ts.ps.max, m_qp->ts.ps.min,
			m_qp->ts.ps.avg, m_qp->ts.ps.all, m_qp->ts.ps.cnt,
			m_qp->ts.ps.stop - m_qp->ts.ps.start,
			(m_qp->ts.ps.stop - m_qp->ts.ps.start)/m_qp->ts.ps.cnt);

	if ((m_qp->ts.po.min) &&
	    (type == MCM_QP_PO_PI_RW || type == MCM_QP_ALL))
		mlog(0, " QP (%p) PERF IO: Proxy-out -> Proxy-in: FS to LS times"
			" (usecs): max %u min %u avg %u ttime %u cnt %u et %u\n",
			m_qp, m_qp->ts.po.max, m_qp->ts.po.min,
			m_qp->ts.po.avg, m_qp->ts.po.all, m_qp->ts.po.cnt,
			m_qp->ts.po.stop - m_qp->ts.po.start,
			(m_qp->ts.po.stop - m_qp->ts.po.start)/m_qp->ts.po.cnt);
}

void mcm_qp_prof_ts(struct mcm_qp *m_qp, int type, uint32_t start, uint32_t que, uint32_t cmp)
{
	uint32_t diff, stop = mcm_ts_us();
	uint32_t *min, *max, *avg, *all, *cnt, *begin, *end, qcnt, ccnt;
	char *type_str;

	diff = stop - start;
	ccnt = cmp ? cmp:1;
	qcnt = que ? que:1;

	switch (type) {
	case MCM_QP_WT:
		type_str = "MCM_QP_WT";
		min = &m_qp->ts.wt.min;
		max = &m_qp->ts.wt.max;
		avg = &m_qp->ts.wt.avg;
		all = &m_qp->ts.wt.all;
		cnt = &m_qp->ts.wt.cnt;
		begin = &m_qp->ts.wt.start;
		end = &m_qp->ts.wt.stop;
		diff = diff/qcnt;
		break;
	case MCM_QP_RF:
		type_str = "MCM_QP_RF";
		min = &m_qp->ts.rf.min;
		max = &m_qp->ts.rf.max;
		avg = &m_qp->ts.rf.avg;
		all = &m_qp->ts.rf.all;
		cnt = &m_qp->ts.rf.cnt;
		begin = &m_qp->ts.rf.start;
		end = &m_qp->ts.rf.stop;
		diff = diff/qcnt;
		break;
	case MCM_QP_IB_RW:
		type_str = "MCM_QP_IB_RW";
		min = &m_qp->ts.rw.min;
		max = &m_qp->ts.rw.max;
		avg = &m_qp->ts.rw.avg;
		all = &m_qp->ts.rw.all;
		cnt = &m_qp->ts.rw.cnt;
		begin = &m_qp->ts.rw.start;
		end = &m_qp->ts.rw.stop;
		diff = diff/qcnt;
		break;
	case MCM_QP_IB_RR:
		type_str = "MCM_QP_IB_RR";
		min = &m_qp->ts.rr.min;
		max = &m_qp->ts.rr.max;
		avg = &m_qp->ts.rr.avg;
		all = &m_qp->ts.rr.all;
		cnt = &m_qp->ts.rr.cnt;
		begin = &m_qp->ts.rr.start;
		end = &m_qp->ts.rr.stop;
		diff = diff/qcnt;
		break;
	case MCM_QP_PO_POST:
		type_str = "MCM_QP_PO_POST";
		min = &m_qp->ts.ps.min;
		max = &m_qp->ts.ps.max;
		avg = &m_qp->ts.ps.avg;
		all = &m_qp->ts.ps.all;
		cnt = &m_qp->ts.ps.cnt;
		begin = &m_qp->ts.ps.start;
		end = &m_qp->ts.ps.stop;
		break;
	case MCM_QP_PO_PI_RW:
		type_str = "MCM_QP_PO_PI_RW";
		min = &m_qp->ts.po.min;
		max = &m_qp->ts.po.max;
		avg = &m_qp->ts.po.avg;
		all = &m_qp->ts.po.all;
		cnt = &m_qp->ts.po.cnt;
		begin = &m_qp->ts.po.start;
		end = &m_qp->ts.po.stop;
		break;
	default:
		return;
	}

	if (*cnt == 0)
		*begin = start;

	diff = diff/ccnt;
	*cnt += ccnt;
	*all += diff;
	*end = stop;
	if (*min == 0 || diff < *min)
		*min = diff;
	if (*max == 0 || diff > *max)
		*max = diff;
	if (*avg == 0)
		*avg = diff;
	else
		*avg = (*all / *cnt);

	if (log_level == 0x10)
		mlog(0x10, "us(%u-%u=%u,%d,%d) %s: io %d: mx %u mn %u av %u tt %u et %u "
			   "TX tl %d hd %d RX tl %d w_tl %d hd %d rr %d wt %d\n",
			start, stop, diff, qcnt, ccnt, type_str, *cnt, *max, *min, *avg, *all,
			*end - *begin, m_qp->wr_tl, m_qp->wr_hd, m_qp->wr_tl_r,
			m_qp->wr_tl_r_wt, m_qp->wr_hd_r, m_qp->pi_rr_cnt, m_qp->post_cnt_wt);
	else if (log_level == 0x1 && !(*cnt % 100))
		mlog(0x1, "us(%u-%u=%u,%d,%d) %s: io %d: mx %u mn %u av %u tt %u et %u "
			   "TX tl %d hd %d RX tl %d w_tl %d hd %d rr %d wt %d\n",
			start, stop, diff, qcnt, ccnt, type_str, *cnt, *max, *min, *avg, *all,
			*end - *begin, m_qp->wr_tl, m_qp->wr_hd, m_qp->wr_tl_r,
			m_qp->wr_tl_r_wt, m_qp->wr_hd_r, m_qp->pi_rr_cnt, m_qp->post_cnt_wt);

}
#endif








