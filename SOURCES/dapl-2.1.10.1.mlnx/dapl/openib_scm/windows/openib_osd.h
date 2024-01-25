#ifndef OPENIB_OSD_H
#define OPENIB_OSD_H

#if defined(FD_SETSIZE) && FD_SETSIZE != 1024
#undef FD_SETSIZE
#undef DAPL_FD_SETSIZE
#endif

#define FD_SETSIZE 1024 /* Set before including winsock2 - see select help */
#define DAPL_FD_SETSIZE FD_SETSIZE

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>

#define ntohll _byteswap_uint64
#define htonll _byteswap_uint64

#define DAPL_SOCKET SOCKET
#define DAPL_INVALID_SOCKET INVALID_SOCKET
#define SHUT_RDWR SD_BOTH

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

#endif // OPENIB_OSD_H
