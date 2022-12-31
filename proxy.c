
/*
 * Copyright (c) 2022 David Gwynne <david@gwynne.id.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/tftp.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <syslog.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <err.h>

#include <event.h>

#include "log.h"
#include "filter.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#define PF_DEVNAME	"/dev/pf"
#define NX_PROXY_PORT	"1717"
#define NX_PROXY_USER	"_nx_proxy"

static const struct timeval proxy_tmo_tv = { 17, 0 };

static inline struct sockaddr *
sin2sa(const struct sockaddr_in *sin)
{
	return ((struct sockaddr *)sin);
}

struct proxy;

struct proxy_listener {
	struct proxy			*pl_proxy;
	struct event			 pl_ev;
	TAILQ_ENTRY(proxy_listener)	 pl_entry;
};
TAILQ_HEAD(proxy_listeners, proxy_listener);

struct proxy_conn {
	unsigned int		 pc_id;
	struct sockaddr_in	 pc_remote;
	struct sockaddr_in	 pc_internal;
	struct sockaddr_in	 pc_external;
};

struct proxy_msg {
	struct proxy_conn	 pm_conn;
#define pm_id			 pm_conn.pc_id
#define pm_remote		 pm_conn.pc_remote
#define pm_internal		 pm_conn.pc_internal
#define pm_external		 pm_conn.pc_external

	struct proxy		*pm_proxy;
	RBT_ENTRY(proxy_msg)	 pm_entry;

	int			 pm_remote_fd;
	struct event		 pm_ev;
	struct event		 pm_tmo;
};
RBT_HEAD(proxy_msgs, proxy_msg);
RBT_HEAD(proxy_msgs_rem, proxy_msg);

static inline int
proxy_msg_compare(const struct proxy_msg *a, const struct proxy_msg *b)
{
	int rv;

	rv = memcmp(&a->pm_remote, &b->pm_remote,
	    sizeof(a->pm_remote));
	if (rv == 0) {
		rv = memcmp(&a->pm_internal, &b->pm_internal,
		    sizeof(a->pm_internal));
	}
	return (rv);
}

RBT_PROTOTYPE(proxy_msgs, proxy_msg, pm_entry, proxy_msg_compare);

static inline int
proxy_msg_rem_compare(const struct proxy_msg *a, const struct proxy_msg *b)
{
	int rv;

	rv = memcmp(&a->pm_remote, &b->pm_remote,
	    sizeof(a->pm_remote));
	return (rv);
}

RBT_PROTOTYPE(proxy_msgs_rem, proxy_msg, pm_entry, proxy_msg_rem_compare);

struct proxy {
	unsigned int			 p_id;

	const char			*p_saddr;
	const char			*p_laddr;
	const char			*p_lport;
	struct proxy_listeners		 p_listeners;
	int				 p_pf_fd;
	struct proxy_msgs		 p_msgs;
};

struct sockname {
	char				sn_host[NI_MAXHOST];
	char				sn_port[NI_MAXSERV];
};

static void __dead
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-a address] [-l address] [-p port]\n",
	    __progname);
	exit(1);
}

static void		proxy_listen(struct proxy *);
static void		proxy_listener_events(struct proxy *);

static void		proxy_recv(int, short, void *);

int
main(int argc, char *argv[])
{
	struct proxy _proxy = {
		.p_id = arc4random(),

		.p_saddr = NULL,
		.p_laddr = "localhost",
		.p_lport = NX_PROXY_PORT,
		.p_listeners = TAILQ_HEAD_INITIALIZER(_proxy.p_listeners),
		.p_pf_fd = -1,
		.p_msgs = RBT_INITIALIZER(_proxy.p_msgs),
	};
	struct proxy *p = &_proxy;

	const char *user = NX_PROXY_USER;
	struct passwd *pw;

	int ch;

	while ((ch = getopt(argc, argv, "l:p:u:")) != -1) {
		switch (ch) {
		case 'a':
			p->p_saddr = optarg;
			break;
		case 'l':
			p->p_laddr = optarg;
			break;
		case 'p':
			p->p_lport = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (geteuid() != 0)
		errx(1, "need root privileges");

	pw = getpwnam(user);
	if (pw == NULL)
		errx(1, "user %s not found", user);

#if 0
	p->p_pf_fd = open(PF_DEVNAME, O_RDWR);
	if (p->p_pf_fd == -1)
		err(1, "%s", PF_DEVNAME);
#else
	init_filter(NULL, 1);
#endif

	proxy_listen(p); /* proxy_listen err()s on failure(s) */

	event_init();

	proxy_listener_events(p);

	event_dispatch();

	return (0);
}

static int
setsockbool(int fd, int level, int optname, int val)
{
	return (setsockopt(fd, level, optname, &val, sizeof(val)));
}

static void
proxy_sockname(struct sockname *sn, const struct sockaddr_in *sin)
{
	int error;

	error = getnameinfo(sin2sa(sin), sizeof(*sin),
	    sn->sn_host, sizeof(sn->sn_host), sn->sn_port, sizeof(sn->sn_port),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (error != 0)
		lerrx(1, "%s %s", __func__, gai_strerror(error));
}

static int
proxy_bind(struct proxy *p, const struct addrinfo *res, const char **cause)
{
	struct proxy_listener *pl;
	int s;
	int serrno;

	s = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
	    res->ai_protocol);
	if (s == -1) {
		*cause = "socket";
		return (errno);
	}

	if (setsockbool(s, SOL_SOCKET, SO_BINDANY, 1) == -1)
		err(1, "enable bindany");
	if (setsockbool(s, SOL_SOCKET, SO_REUSEADDR, 1) == -1)
		err(1, "enable reuseaddr");
	if (setsockbool(s, SOL_SOCKET, SO_REUSEADDR, 1) == -1)
		err(1, "enable reuseport");
	if (setsockbool(s, IPPROTO_IP, IP_RECVDSTADDR, 1) == -1)
		err(1, "enable recvdstaddr");
	if (setsockbool(s, IPPROTO_IP, IP_RECVDSTPORT, 1) == -1)
		err(1, "enable recvdstport");

	if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
		serrno = errno;
		close(s);
		*cause = "bind";
		return (serrno);
	}

	pl = malloc(sizeof(*pl));
	if (pl == NULL)
		err(1, NULL);

	pl->pl_proxy = p;
	event_set(&pl->pl_ev, s, 0, NULL, NULL);

	TAILQ_INSERT_TAIL(&p->p_listeners, pl, pl_entry);

	return (0);
}

static void
proxy_listen(struct proxy *p)
{
	struct addrinfo *res, *res0;
	int error;
	int serrno = EADDRNOTAVAIL;
	const char *cause = "resolution";

	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_PASSIVE,
	};

	error = getaddrinfo(p->p_laddr, p->p_lport, &hints, &res0);
	if (error != 0) {
		errx(1, "listen address %s port %s: %s",
		    p->p_laddr, p->p_lport, gai_strerror(error));
	}

	for (res = res0; res != NULL; res = res->ai_next) {
		error = proxy_bind(p, res, &cause);
		if (error != 0)
			serrno = error;
	}

	if (TAILQ_EMPTY(&p->p_listeners)) {
		errc(1, serrno, "listen address %s port %s %s",
		    p->p_laddr, p->p_lport, cause);
	}

	freeaddrinfo(res0);
}

static void
proxy_listener_events(struct proxy *p)
{
	struct proxy_listener *pl;

	TAILQ_FOREACH(pl, &p->p_listeners, pl_entry) {
		event_set(&pl->pl_ev, EVENT_FD(&pl->pl_ev), EV_READ|EV_PERSIST,
		    proxy_recv, pl);
		event_add(&pl->pl_ev, NULL);
	}
}
RBT_GENERATE(proxy_msgs, proxy_msg, pm_entry, proxy_msg_compare);
RBT_GENERATE(proxy_msgs_rem, proxy_msg, pm_entry, proxy_msg_rem_compare);

static void
proxy_pkt(int fd, short revents, void *arg)
{
	struct proxy_msg *pm = arg;
	char buf[65536];
	size_t buflen;
	ssize_t rv;

	rv = recv(fd, buf, sizeof(buf), 0);
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			return;
		}

		lwarn("%s recv", __func__);
		goto bump;
	}
	buflen = rv;

	if (sendto(pm->pm_remote_fd, buf, buflen, 0,
	    sin2sa(&pm->pm_internal), sizeof(pm->pm_internal)) == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			return;
		}

		lwarn("%s send", __func__);
		goto bump;
	}

bump:
	evtimer_add(&pm->pm_tmo, &proxy_tmo_tv);
}

static void
proxy_tmo(int nil, short revents, void *arg)
{
	struct proxy_msg *pm = arg;
	struct proxy *p = pm->pm_proxy;

	event_del(&pm->pm_ev);
	close(EVENT_FD(&pm->pm_ev));
	close(pm->pm_remote_fd);
	RBT_REMOVE(proxy_msgs, &p->p_msgs, pm);

	prepare_commit(pm->pm_id);
	do_commit();

	free(pm);
}

static void
proxy_recv(int fd, short revents, void *arg)
{
	struct proxy_listener *pl = arg;
	struct proxy *p = pl->pl_proxy;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(struct sockaddr_storage)) +
		    CMSG_SPACE(sizeof(in_port_t))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t rv;
	char buf[65536];
	size_t buflen;
	socklen_t sinlen;
	int sext, sint;
	struct sockname sn_int, sn_ext, sn_rem;

	struct proxy_msg *pm, *opm;

	pm = calloc(1, sizeof(*pm));
	if (pm == NULL) {
		int serrno = errno;

		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv == -1) {
			switch (errno) {
			case EAGAIN:
			case EINTR:
				/* oh well */
				break;
			default:
				lwarn("discarding message recv");
				break;
			}
			return;
		}

		lwarnc(serrno, "discarding %zd byte message", rv);
	}

	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);
	msg.msg_name = &pm->pm_internal;
	msg.msg_namelen = sizeof(pm->pm_internal);
	msg.msg_iov = iov;
	msg.msg_iovlen = nitems(iov);
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	rv = recvmsg(fd, &msg, 0);
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			goto free;
		default:
			lerr(1, "recvmsg");
			/* NOTREACHED */
		}
	}
	buflen = rv;

	pm->pm_remote.sin_family = pm->pm_internal.sin_family;
	pm->pm_remote.sin_len = pm->pm_internal.sin_len;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IP)
			continue;

		switch (cmsg->cmsg_type) {
		case IP_RECVDSTADDR:
			memcpy(&pm->pm_remote.sin_addr, CMSG_DATA(cmsg),
			    sizeof(pm->pm_remote.sin_addr));
			break;
		case IP_RECVDSTPORT:
			memcpy(&pm->pm_remote.sin_port, CMSG_DATA(cmsg),
			    sizeof(pm->pm_remote.sin_port));
			break;
		}
	}

	proxy_sockname(&sn_int, &pm->pm_internal);
	proxy_sockname(&sn_rem, &pm->pm_remote);

#if 0
	linfo("%s:%s -> %s:%s",
	    sn_int.sn_host, sn_int.sn_port,
	    sn_rem.sn_host, sn_rem.sn_port);
#endif

	pm->pm_id = p->p_id++;
	pm->pm_proxy = p;
	pm->pm_remote_fd = -1;
	opm = RBT_INSERT(proxy_msgs, &p->p_msgs, pm);
	if (opm) {
		free(pm);
		pm = opm;

		rv = send(EVENT_FD(&pm->pm_ev), buf, buflen, 0);
		if (rv == -1) {
			switch (errno) {
			case EAGAIN:
			case EINTR:
				return;
			}
			lerr(1, "%s reuse send", __func__);
		}

		evtimer_add(&pm->pm_tmo, &proxy_tmo_tv);
		return;
	}

	linfo("%s:%s -> %s:%s",
	    sn_int.sn_host, sn_int.sn_port,
	    sn_rem.sn_host, sn_rem.sn_port);

	sext = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
	if (sext == -1) {
		lwarn("external socket");
		goto remove;
	}

	if (setsockbool(sext, SOL_SOCKET, SO_REUSEADDR, 1) == -1) {
		lwarn("external reuseaddr");
		goto close_ext;
	}
	if (setsockbool(sext, SOL_SOCKET, SO_REUSEPORT, 1) == -1) {
		lwarn("external reuseport");
		goto close_ext;
	}

	{
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_len = sizeof(sin),
			.sin_port = pm->pm_internal.sin_port,
		};

		if (bind(sext, sin2sa(&sin), sizeof(sin)) == -1) {
			lwarn("external bind");
			goto close_ext;
		}
	}

	/* this does an implicit bind */
	if (connect(sext,
	    sin2sa(&pm->pm_remote), sizeof(pm->pm_remote)) == -1) {
		lwarn("external connect");
		goto close_ext;
	}

	sinlen = sizeof(pm->pm_external);
	if (getsockname(sext, sin2sa(&pm->pm_external), &sinlen) == -1) {
		lwarn("external getsockname");
		goto close_ext;
	}

	sint = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
	if (sint == -1) {
		lwarn("internal socket");
		goto close_ext;
	}

	if (setsockbool(sint, SOL_SOCKET, SO_REUSEADDR, 1) == -1) {
		lwarn("internal reuseaddr");
		goto close_int;
	}
	if (setsockbool(sint, SOL_SOCKET, SO_REUSEPORT, 1) == -1) {
		lwarn("internal reuseport");
		goto close_int;
	}
	if (setsockbool(sint, SOL_SOCKET, SO_BINDANY, 1) == -1) {
		lwarn("internal set bindany");
		goto close_int;
	}

	if (bind(sint, sin2sa(&pm->pm_remote), sizeof(pm->pm_remote)) == -1) {
		lwarn("internal bind");
		goto close_int;
	}

	proxy_sockname(&sn_ext, &pm->pm_external);

	linfo("%s:%s (%s:%s) -> %s:%s %zu, fd %d",
	    sn_int.sn_host, sn_int.sn_port,
	    sn_ext.sn_host, sn_ext.sn_port,
	    sn_rem.sn_host, sn_rem.sn_port,
	    buflen, sint);

	if (prepare_commit(pm->pm_id) == -1)
		lerr(1, "%s: prepare commit", __func__);

	if (add_rdr(pm->pm_id, sin2sa(&pm->pm_remote),
	    sin2sa(&pm->pm_external), ntohs(pm->pm_external.sin_port),
	    sin2sa(&pm->pm_internal), ntohs(pm->pm_internal.sin_port),
	    IPPROTO_UDP) == -1)
		lerr(1, "%s: add rdr", __func__);

	if (do_commit() == -1)
		lerr(1, "%s: do commit", __func__);

	rv = send(sext, buf, buflen, 0);
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			break;
		default:
			lerr(1, "%s reuse send", __func__);
		}
	}

	pm->pm_remote_fd = sint;
	evtimer_set(&pm->pm_tmo, proxy_tmo, pm);
	event_set(&pm->pm_ev, sext, EV_READ|EV_PERSIST,
	    proxy_pkt, pm);

	event_add(&pm->pm_ev, NULL);
	evtimer_add(&pm->pm_tmo, &proxy_tmo_tv);

	return;
close_int:
	close(sint);
close_ext:
	close(sext);
remove:
	RBT_REMOVE(proxy_msgs, &p->p_msgs, pm);
free:
	free(pm);
}
