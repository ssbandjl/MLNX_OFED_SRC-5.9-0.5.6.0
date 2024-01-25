#ifndef OPENIB_OSD_H
#define OPENIB_OSD_H

#ifndef FD_SETSIZE
#define FD_SETSIZE 1024 /* Set before including winsock2 - see select help */
#define DAPL_FD_SETSIZE FD_SETSIZE
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <comp_channel.h>

#define ntohll _byteswap_uint64
#define htonll _byteswap_uint64

#define DAPL_SOCKET SOCKET
#define DAPL_INVALID_SOCKET INVALID_SOCKET

/* allow casting to WSABUF */
struct iovec
{
       u_long iov_len;
       char FAR* iov_base;
};

static int writev(DAPL_SOCKET s, struct iovec *vector, int count)
{
       int len, ret;

       ret = WSASend(s, (WSABUF *) vector, count, &len, 0, NULL, NULL);
       return ret ? ret : len;
}

struct dapl_thread_signal
{
	COMP_SET set;
};

static void dapls_thread_signal(struct dapl_thread_signal *signal)
{
	CompSetCancel(&signal->set);
}

#endif // OPENIB_OSD_H
