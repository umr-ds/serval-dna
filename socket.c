/*
Serval DNA named sockets
Copyright 2013 Serval Project Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <limits.h>
#include <stdlib.h>
#include <assert.h>
#include <libgen.h>

#include "instance.h"
#include "str.h"
#include "conf.h"
#include "log.h"
#include "debug.h"
#include "strbuf_helpers.h"
#include "socket.h"

/* Form the name of an AF_UNIX (local) socket in the /var/run/serval (or instance) directory as an
 * absolute path.  Under Linux, this will create a socket name in the abstract namespace.  This
 * permits us to use local sockets on Android despite its lack of a shared writeable directory on a
 * UFS partition.
 *
 * The absolute file name is resolved to its real path using realpath(3), to ensure that name
 * comparisons of addresses returned by recvmsg(2) can reliably be used on systems where the
 * instance path may have a symbolic link in it.
 *
 * Returns -1 if the path name overruns the size of a sockaddr_un structure, or if realpath(3) fails
 * with an error.  The contents of *addr and *addrlen are undefined in this case.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 * @author Daniel O'Connor <daniel@servalproject.com>
 */
int _make_local_sockaddr(struct __sourceloc __whence, struct socket_address *addr, const char *fmt, ...)
{
  bzero(addr, sizeof(*addr));
  addr->local.sun_family = AF_UNIX;
  va_list ap;
  va_start(ap, fmt);
  int r = vformf_serval_run_path(addr->local.sun_path, (sizeof addr->local.sun_path)+100, fmt, ap);
  va_end(ap);
  if (!r)
    return WHY("socket name overflow");
  addr->addrlen=sizeof addr->local.sun_family + strlen(addr->local.sun_path) + 1;
// TODO perform real path transformation in making the serval instance path
//  if (real_sockaddr(addr, addr) == -1)
//    return -1;

#ifdef USE_ABSTRACT_NAMESPACE
  // For the abstract name we use the absolute path name with the initial '/' replaced by the
  // leading nul.  This ensures that different instances of the Serval daemon have different socket
  // names.
  addr->local.sun_path[0] = '\0'; // mark as Linux abstract socket
  --addr->addrlen; // do not count trailing nul in abstract socket name
#endif // USE_ABSTRACT_NAMESPACE
  return 0;
}

/* Converts an AF_UNIX local socket file name to contain a real path name using realpath(3), leaves
 * all other socket types intact, including abstract local socket names.  Returns -1 in case of an
 * error from realpath(3) or a buffer overflow, without modifying *dst_addr or *dst_addrlen.
 * Returns 1 if the path is changed and puts the modified path in *dst_addr and *dst_addrlen.
 * Returns 0 if not the path is not changed and copies from *src_addr to *dst_addr, src_addrlen to
 * *dst_addrlen.
 *
 * Can safely be used to perform an in-place conversion by using src_addr == dst_addr and
 * dst_addrlen == &src_addrlen.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int real_sockaddr(const struct socket_address *src_addr, struct socket_address *dst_addr)
{
  assert(src_addr->addrlen > sizeof src_addr->local.sun_family);
  size_t src_path_len = src_addr->addrlen - sizeof src_addr->local.sun_family;
  if (	 src_addr->addrlen >= sizeof src_addr->local.sun_family + 1
      && src_addr->local.sun_family == AF_UNIX
      && src_addr->local.sun_path[0] != '\0'
      && src_addr->local.sun_path[src_path_len - 1] == '\0'
  ) {
    char real_path[PATH_MAX];
    size_t real_path_len;
    if (realpath(src_addr->local.sun_path, real_path) == NULL)
      return WHYF_perror("realpath(%s)", alloca_str_toprint(src_addr->local.sun_path));
    else if ((real_path_len = strlen(real_path) + 1) > sizeof dst_addr->local.sun_path)
      return WHYF("sockaddr overrun: realpath(%s) returned %s", 
	  alloca_str_toprint(src_addr->local.sun_path), alloca_str_toprint(real_path));
    else if (   real_path_len != src_path_len
	     || memcmp(real_path, src_addr->local.sun_path, src_path_len) != 0
    ) {
      memcpy(dst_addr->local.sun_path, real_path, real_path_len);
      dst_addr->addrlen = real_path_len + sizeof dst_addr->local.sun_family;
      return 1;
    }
  }
  if (dst_addr != src_addr){
    memcpy(&dst_addr->addr, &src_addr->addr, src_addr->addrlen);
    dst_addr->addrlen = src_addr->addrlen;
  }
  return 0;
}

/* Compare any two struct sockaddr.  Return -1, 0 or 1.  Copes with invalid and truncated sockaddr
 * structures.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int cmp_sockaddr(const struct socket_address *addrA, const struct socket_address *addrB)
{
  // Two zero-length sockaddrs are equal.
  if (addrA->addrlen == 0 && addrB->addrlen == 0)
    return 0;
  // If either sockaddr is truncated, then we compare the bytes we have.
  if (addrA->addrlen < sizeof addrA->addr.sa_family || addrB->addrlen < sizeof addrB->addr.sa_family) {
    int c = memcmp(addrA, addrB, addrA->addrlen < addrB->addrlen ? addrA->addrlen : addrB->addrlen);
    if (c == 0)
      c = addrA->addrlen < addrB->addrlen ? -1 : addrA->addrlen > addrB->addrlen ? 1 : 0;
    return c;
  }
  // Order first by address family.
  if (addrA->addr.sa_family < addrB->addr.sa_family)
    return -1;
  if (addrA->addr.sa_family > addrB->addr.sa_family)
    return 1;
  // Both addresses are in the same family...
  switch (addrA->addr.sa_family) {
  case AF_INET: {
      if (addrA->inet.sin_addr.s_addr < addrB->inet.sin_addr.s_addr)
	return -1;
      if (addrA->inet.sin_addr.s_addr > addrB->inet.sin_addr.s_addr)
	return 1;
      if (addrA->inet.sin_port < addrB->inet.sin_port)
	return -1;
      if (addrA->inet.sin_port > addrB->inet.sin_port)
	return 1;
      return 0;
    }break;
  case AF_UNIX: {
      unsigned pathlenA = addrA->addrlen - sizeof (addrA->local.sun_family);
      unsigned pathlenB = addrB->addrlen - sizeof (addrB->local.sun_family);
      int c;
      if (   pathlenA > 1 && pathlenB > 1
	  && addrA->local.sun_path[0] == '\0'
	  && addrB->local.sun_path[0] == '\0'
      ) {
	// Both abstract sockets - just compare names, nul bytes are not terminators.
	c = memcmp(&addrA->local.sun_path[1],
		   &addrB->local.sun_path[1],
		   (pathlenA < pathlenB ? pathlenA : pathlenB) - 1);
      } else {
	// Either or both are named local file sockets.  If the file names are identical up to the
	// first nul, then the addresses are equal.  This collates abstract socket names, whose first
	// character is a nul, ahead of all non-empty file socket names.
	c = strncmp(addrA->local.sun_path,
		    addrB->local.sun_path,
		    (pathlenA < pathlenB ? pathlenA : pathlenB));
      }
      if (c == 0)
	c = pathlenA < pathlenB ? -1 : pathlenA > pathlenB ? 1 : 0;
      return c;
    }
    break;
  }
  // Fall back to comparing raw data bytes.
  int c = memcmp(addrA->addr.sa_data, addrB->addr.sa_data, 
      (addrA->addrlen < addrB->addrlen ? addrA->addrlen : addrB->addrlen) - sizeof addrA->addr.sa_family);
  if (c == 0)
    c = addrA->addrlen < addrB->addrlen ? -1 : addrA->addrlen > addrB->addrlen ? 1 : 0;
  
  return c;
}

int _esocket(struct __sourceloc __whence, int domain, int type, int protocol)
{
  int fd;
  if ((fd = socket(domain, type, protocol)) == -1)
    return WHYF_perror("socket(%s, %s, 0)", alloca_socket_domain(domain), alloca_socket_type(type));
  DEBUGF2(io, verbose_io, "socket(%s, %s, 0) -> %d", alloca_socket_domain(domain), alloca_socket_type(type), fd);
  return fd;
}

int _socket_connect(struct __sourceloc __whence, int sock, const struct socket_address *addr)
{
  if (connect(sock, &addr->addr, addr->addrlen) == -1)
    return WHYF_perror("connect(%d,%s,%lu)", sock, alloca_socket_address(addr), (unsigned long)addr->addrlen);
  DEBUGF2(io, verbose_io, "connect(%d, %s, %lu)", sock, alloca_socket_address(addr), (unsigned long)addr->addrlen);
  return 0;
}

int _socket_bind(struct __sourceloc __whence, int sock, const struct socket_address *addr)
{
  assert(addr->addrlen > sizeof addr->addr.sa_family);
  if (addr->addr.sa_family == AF_UNIX && addr->local.sun_path[0] != '\0') {
    assert(addr->local.sun_path[addr->addrlen - sizeof addr->local.sun_family - 1] == '\0');
    // make sure the path exists, create it if we can
    size_t dirsiz = strlen(addr->local.sun_path) + 1;
    char dir_buf[dirsiz];
    strcpy(dir_buf, addr->local.sun_path);
    const char *dir = dirname(dir_buf); // modifies dir_buf[]
    if (mkdirs_info(dir, 0700) == -1)
      return WHY_perror("mkdirs()");
    // remove a previous socket
    if (unlink(addr->local.sun_path) == -1 && errno != ENOENT)
      WARNF_perror("unlink(%s)", alloca_str_toprint(addr->local.sun_path));
    DEBUGF2(io, verbose_io, "unlink(%s)", alloca_str_toprint(addr->local.sun_path));
  }
  if (bind(sock, &addr->addr, addr->addrlen) == -1)
    return WHYF_perror("bind(%d,%s,%lu)", sock, alloca_socket_address(addr), (unsigned long)addr->addrlen);
  DEBUGF2(io, verbose_io, "bind(%d, %s, %lu)", sock, alloca_socket_address(addr), (unsigned long)addr->addrlen);
  return 0;
}

int _socket_listen(struct __sourceloc __whence, int sock, int backlog)
{
  if (listen(sock, backlog) == -1)
    return WHYF_perror("listen(%d,%d)", sock, backlog);
  DEBUGF2(io, verbose_io, "listen(%d, %d)", sock, backlog);
  return 0;
}

int _socket_set_reuseaddr(struct __sourceloc __whence, int sock, int reuseP)
{
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof reuseP) == -1) {
    WARNF_perror("setsockopt(%d,SOL_SOCKET,SO_REUSEADDR,&%d,%u)", sock, reuseP, (unsigned)sizeof reuseP);
    return -1;
  }
  DEBUGF2(io, verbose_io, "setsockopt(%d, SOL_SOCKET, SO_REUSEADDR, &%d, %u)", sock, reuseP, (unsigned)sizeof reuseP);
  return 0;
}

int _socket_set_rcvbufsize(struct __sourceloc __whence, int sock, unsigned buffer_size)
{
  if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof buffer_size) == -1) {
    WARNF_perror("setsockopt(%d,SOL_SOCKET,SO_RCVBUF,&%u,%u)", sock, buffer_size, (unsigned)sizeof buffer_size);
    return -1;
  }
  DEBUGF2(io, verbose_io, "setsockopt(%d, SOL_SOCKET, SO_RCVBUF, &%u, %u)", sock, buffer_size, (unsigned)sizeof buffer_size);
  return 0;
}

int socket_unlink_close(int sock)
{
  // get the socket name and unlink it from the filesystem if not abstract
  struct socket_address addr;
  addr.addrlen = sizeof addr.store;
  if (getsockname(sock, &addr.addr, &addr.addrlen))
    WHYF_perror("getsockname(%d)", sock);
  else if (addr.addr.sa_family==AF_UNIX 
    && addr.addrlen > sizeof addr.local.sun_family 
    && addr.addrlen <= sizeof addr.local 
    && addr.local.sun_path[0] != '\0') {
    if (unlink(addr.local.sun_path) == -1)
      WARNF_perror("unlink(%s)", alloca_str_toprint(addr.local.sun_path));
  }
  close(sock);
  return 0;
}

ssize_t _send_message(struct __sourceloc __whence, int fd, const struct socket_address *address, const struct fragmented_data *data)
{
  struct msghdr hdr={
    .msg_name=(void *)&address->addr,
    .msg_namelen=address->addrlen,
    .msg_iov=(struct iovec*)data->iov,
    .msg_iovlen=data->fragment_count,
  };
  ssize_t ret = sendmsg(fd, &hdr, 0);
  if (ret == -1 && errno != EAGAIN)
    WHYF_perror("sendmsg(%d,%s,%lu)", fd, alloca_socket_address(address), (unsigned long)address->addrlen);
  return ret;
}

ssize_t _recv_message(struct __sourceloc __whence, int fd, struct socket_address *address, struct fragmented_data *data)
{
  struct msghdr hdr={
    .msg_name=(void *)&address->addr,
    .msg_namelen=address->addrlen,
    .msg_iov=data->iov,
    .msg_iovlen=data->fragment_count,
  };
  ssize_t ret = recvmsg(fd, &hdr, 0);
  if (ret==-1)
    WHYF_perror("recvmsg(%d,%s,%lu)", fd, alloca_socket_address(address), (unsigned long)address->addrlen);
  address->addrlen = hdr.msg_namelen;
  return ret;
}
