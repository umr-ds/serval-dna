/*
 Mesh Stream Protocol (MSP)
 Copyright (C) 2013-2014 Serval Project Inc.
 
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

#include <signal.h>
#include "cli.h"
#include "serval_types.h"
#include "mdp_client.h"
#include "msp_client.h"
#include "fdqueue.h"
#include "log.h"
#include "debug.h"
#include "mem.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "dataformats.h"
#include "socket.h"
#include "conf.h"
#include "commandline.h"

struct buffer{
  size_t position;
  size_t limit;
  size_t capacity;
  uint8_t bytes[];
};

struct connection{
  struct connection *_next;
  struct connection *_prev;
  struct sched_ent alarm_in;
  struct sched_ent alarm_out;
  MSP_SOCKET sock;
  struct buffer *in;
  struct buffer *out;
  char eof;
  int last_state;
};

struct proxy_state{
  struct connection *connections;
  int saw_error;
  int once;
  MSP_SOCKET listener;
  struct mdp_sockaddr remote_addr;
  struct socket_address ip_addr;
  char quit;
};
static struct proxy_state *proxy_state;

static int try_send(struct connection *conn);
static void msp_poll(struct sched_ent *alarm);
static void service_poll(struct sched_ent *alarm);
static void listen_poll(struct sched_ent *alarm);
static void io_poll(struct sched_ent *alarm);
static MSP_HANDLER msp_handler;

struct profile_total mdp_sock_stats={
  .name="msp_poll"
};

struct sched_ent mdp_sock={
  .poll = {
    .revents = 0,
    .events = POLLIN,
    .fd = -1
  },
  .function = msp_poll,
  .stats = &mdp_sock_stats,
};

struct profile_total service_sock_stats={
  .name="service_poll"
};

struct sched_ent service_sock={
  .poll = {
    .revents = 0,
    .events = POLLIN,
    .fd = -1
  },
  .function = service_poll,
  .stats = &service_sock_stats,
};

struct profile_total io_stats={
  .name="io_stats"
};

struct profile_total listen_stats={
  .name="listen_poll"
};

struct sched_ent listen_alarm={
  .poll = {
    .revents = 0,
    .events = POLLIN,
    .fd = -1
  },
  .function = listen_poll,
  .stats = &listen_stats,
};

const char *service_name=NULL;
mdp_port_t service_port;

static struct connection *alloc_connection(
  MSP_SOCKET sock,
  int fd_in,
  void (*func_in)(struct sched_ent *alarm),
  int fd_out,
  void (*func_out)(struct sched_ent *alarm))
{
  struct connection *conn = emalloc_zero(sizeof(struct connection));
  if (!conn)
    return NULL;
  
  conn->sock = sock;
  conn->alarm_in.poll.fd = fd_in;
  conn->alarm_in.poll.events = POLLIN;
  conn->alarm_in.function = func_in;
  conn->alarm_in.stats = &io_stats;
  conn->alarm_in.context = conn;
  conn->alarm_out.poll.fd = fd_out;
  conn->alarm_out.poll.events = POLLOUT;
  conn->alarm_out.function = func_out;
  conn->alarm_out.stats = &io_stats;
  conn->alarm_out.context = conn;
  watch(&conn->alarm_in);
  conn->in = emalloc(1024 + sizeof(struct buffer));
  if (!conn->in){
    free(conn);
    return NULL;
  }
  conn->out = emalloc(1024 + sizeof(struct buffer));
  if (!conn->out){
    free(conn->in);
    free(conn);
    return NULL;
  }
  conn->in->position = conn->out->position = 0;
  conn->in->limit = conn->out->limit = 0;
  conn->in->capacity = conn->out->capacity = 1024;
  if (proxy_state->connections)
    proxy_state->connections->_prev = conn;
  conn->_next = proxy_state->connections;
  proxy_state->connections = conn;
  return conn;
}

static void free_connection(struct connection *conn)
{
  if (!conn)
    return;
  if (!msp_socket_is_closed(conn->sock)){
    msp_set_handler(conn->sock, msp_handler, NULL);
    msp_stop(conn->sock);
  }
  
  if (conn->in)
    free(conn->in);
  if (conn->out)
    free(conn->out);
  conn->in=NULL;
  conn->out=NULL;
  
  if (is_watching(&conn->alarm_in))
    unwatch(&conn->alarm_in);
  if (is_watching(&conn->alarm_out))
    unwatch(&conn->alarm_out);
    
  if (conn->alarm_in.poll.fd!=-1)
    close(conn->alarm_in.poll.fd);
  if (conn->alarm_out.poll.fd!=-1 && conn->alarm_out.poll.fd != conn->alarm_in.poll.fd)
    close(conn->alarm_out.poll.fd);
  conn->alarm_in.poll.fd=-1;
  conn->alarm_out.poll.fd=-1;
  
  if (conn->_next)
    conn->_next->_prev = conn->_prev;
  if (conn->_prev)
    conn->_prev->_next = conn->_next;
  if (conn==proxy_state->connections)
    proxy_state->connections = conn->_next;
  free(conn);

  if (!proxy_state->connections && !msp_socket_is_listening(proxy_state->listener))
    unwatch(&mdp_sock);
}

static void process_msp_asap()
{
  mdp_sock.alarm = gettime_ms();
  mdp_sock.deadline = mdp_sock.alarm+10;
  unschedule(&mdp_sock);
  schedule(&mdp_sock);
}

static void remote_shutdown(struct connection *conn)
{
  struct mdp_sockaddr remote;
  if (conn->alarm_out.poll.fd != STDOUT_FILENO){
    if (shutdown(conn->alarm_out.poll.fd, SHUT_WR))
      WARNF_perror("shutdown(%d)", conn->alarm_out.poll.fd);
  }
  msp_get_remote(conn->sock, &remote);
  DEBUGF(msp, " - Connection with %s:%d remote shutdown", alloca_tohex_sid_t(remote.sid), remote.port);
}

static void local_shutdown(struct connection *conn)
{
  struct mdp_sockaddr remote;
  msp_get_remote(conn->sock, &remote);
  msp_shutdown(conn->sock);
  DEBUGF(msp, " - Connection with %s:%d local shutdown", alloca_tohex_sid_t(remote.sid), remote.port);
}

static size_t msp_handler(MSP_SOCKET sock, msp_state_t state, const uint8_t *payload, size_t len, void *context)
{
  struct connection *conn = context;
  if (!conn)
    return 0;
  
  if (state & MSP_STATE_ERROR)
    proxy_state->saw_error=1;
    
  if (payload && len){
    if (conn->out->limit){
      // attempt to write immediately
      conn->alarm_out.poll.revents=POLLOUT;
      conn->alarm_out.function(&conn->alarm_out);
    }
    if (len > conn->out->capacity - conn->out->limit)
      len = conn->out->capacity - conn->out->limit;
    
    if (len){
      bcopy(payload, &conn->out->bytes[conn->out->limit], len);
      conn->out->limit+=len;
    }
    conn->alarm_out.poll.events|=POLLOUT;
    watch(&conn->alarm_out);
    
    // attempt to write immediately
    conn->alarm_out.poll.revents=POLLOUT;
    conn->alarm_out.function(&conn->alarm_out);
  }
  
  if ((state & MSP_STATE_SHUTDOWN_REMOTE) && !(conn->last_state & MSP_STATE_SHUTDOWN_REMOTE) && conn->out->limit==0)
    remote_shutdown(conn);
  
  conn->last_state=state;
  
  if (state & MSP_STATE_DATAOUT)
    try_send(conn);
  
  if (state & MSP_STATE_CLOSED){
    struct mdp_sockaddr remote;
    msp_get_remote(sock, &remote);
    DEBUGF(msp, " - Connection with %s:%d closed %s", 
	alloca_tohex_sid_t(remote.sid), remote.port,
	(state & MSP_STATE_STOPPED) ? "suddenly":"gracefully");
    
    conn->sock = MSP_SOCKET_NULL;
    if (is_watching(&conn->alarm_in))
      unwatch(&conn->alarm_in);
    if (!is_watching(&conn->alarm_out)){
      // gracefully close now if we have no pending data
      free_connection(conn);
    }
  }
  
  return len;
}

static size_t msp_listener(MSP_SOCKET sock, msp_state_t state, const uint8_t *payload, size_t len, void *UNUSED(context))
{
  if (state & MSP_STATE_ERROR){
    WHY("Error listening for incoming connections");
  }
  if (state & MSP_STATE_CLOSED){
    if (msp_socket_count()==0){
      unschedule(&mdp_sock);
      
      if (is_watching(&mdp_sock))
	unwatch(&mdp_sock);
    }
    return len;
  }
  
  if (proxy_state->once){
    // stop listening after the first incoming connection
    msp_stop(proxy_state->listener);
    proxy_state->listener=MSP_SOCKET_NULL;
    if (service_sock.poll.fd!=-1){
      if (is_watching(&service_sock))
	unwatch(&service_sock);
      mdp_close(service_sock.poll.fd);
      service_sock.poll.fd=-1;
    }
  }
  
  struct mdp_sockaddr remote;
  msp_get_remote(sock, &remote);
  DEBUGF(msp, " - New connection from %s:%d", alloca_tohex_sid_t(remote.sid), remote.port);
  int fd_in = STDIN_FILENO;
  int fd_out = STDOUT_FILENO;
  
  if (proxy_state->ip_addr.addrlen){
    int fd = esocket(PF_INET, SOCK_STREAM, 0);
    if (fd==-1){
      msp_stop(sock);
      return 0;
    }
    if (socket_connect(fd, &proxy_state->ip_addr)==-1){
      msp_stop(sock);
      close(fd);
      return 0;
    }
    fd_in = fd_out = fd;
  }
  struct connection *conn = alloc_connection(sock, fd_in, io_poll, fd_out, io_poll);
  if (!conn)
    return 0;
    
  conn->sock = sock;
  msp_set_handler(sock, msp_handler, conn);
  if (payload)
    return msp_handler(sock, state, payload, len, conn);
  
  assert(len == 0);
  return 0;
}

static void msp_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN)
    // process incoming data packet
    msp_recv(alarm->poll.fd);
  
  // do any timed actions that need to be done, either in response to receiving or due to a timed alarm.
  time_ms_t next;
  msp_processing(&next);
  unschedule(alarm);
  if (next != TIME_MS_NEVER_WILL){
    time_ms_t now = gettime_ms();
    alarm->alarm=next;
    if (alarm->alarm < now)
      alarm->alarm = now;
    alarm->deadline = alarm->alarm +10;
    schedule(alarm);
  }
}

static void service_poll(struct sched_ent *alarm){
  if (alarm->poll.revents & POLLIN){
    struct mdp_header header;
    uint8_t payload[256];
    
    ssize_t len = mdp_recv(alarm->poll.fd, &header, payload, sizeof payload);
    if (len==-1)
      return;
    if (header.flags & (MDP_FLAG_ERROR|MDP_FLAG_BIND))
      return;
    if (is_sid_t_broadcast(header.local.sid))
      header.local.sid = SID_ANY;
    len = snprintf((char*)payload, sizeof payload, "%s.msp.port=%d", service_name, service_port);
    mdp_send(alarm->poll.fd, &header, payload, len);
  }
}

static int try_send(struct connection *conn)
{
  if (!conn->in->limit)
    return 0;
  if (msp_send(conn->sock, conn->in->bytes, conn->in->limit)==-1)
    return 0;
  
  // if this packet was acceptted, clear the read buffer
  conn->in->limit = conn->in->position = 0;
  // hit end of data?
  if (conn->eof){
    local_shutdown(conn);
  }else{
    conn->alarm_in.poll.events|=POLLIN;
    watch(&conn->alarm_in);
  }
  return 1;
}

static void io_poll(struct sched_ent *alarm)
{
  struct connection *conn = alarm->context;
  
  if (alarm->poll.revents & POLLIN) {
    size_t remaining = conn->in->capacity - conn->in->limit;
    if (remaining>0){
      ssize_t r = read(alarm->poll.fd, 
	conn->in->bytes + conn->in->limit,
	remaining);
      if (r<0){
	WARNF_perror("read(%d)", alarm->poll.fd);
	alarm->poll.revents |= POLLERR;
      }
      if (r==0){
	// EOF
	r=-1;
	alarm->poll.revents |= POLLHUP;
      }
      if (r>0){
	conn->in->limit+=r;
	if (try_send(conn))
	  process_msp_asap();
      }
    }

    // stop reading input when the buffer is full
    if (conn->in->limit==conn->in->capacity){
      alarm->poll.events &= ~POLLIN;
      if (alarm->poll.events)
	watch(alarm);
      else if (is_watching(alarm))
	unwatch(alarm);
    }
  }
  
  if (alarm->poll.revents & POLLOUT) {
    // try to write some data
    size_t data = conn->out->limit-conn->out->position;
    if (data>0){
      ssize_t r = write(alarm->poll.fd, 
	conn->out->bytes+conn->out->position,
	data);
      if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK){
	WARNF_perror("write(%d)", alarm->poll.fd);
	alarm->poll.revents |= POLLERR;
      }
      if (r > 0)
	conn->out->position+=r;
    }
    
    // if the buffer is empty now, reset it and unwatch the handle
    if (conn->out->position==conn->out->limit){
      conn->out->limit = conn->out->position = 0;
      alarm->poll.events &= ~POLLOUT;
      if (alarm->poll.events)
	watch(alarm);
      else if (is_watching(alarm))
	unwatch(alarm);
      if (conn->last_state & MSP_STATE_SHUTDOWN_REMOTE)
	remote_shutdown(conn);
    }

    if (conn->out->limit < conn->out->capacity){
      if (!msp_socket_is_null(conn->sock)){
	process_msp_asap();
      }else{
	// gracefully close after flushing the last of the data
	free_connection(conn);
      }
    }
  }
  
  if (alarm->poll.revents & POLLHUP) {
    // EOF? trigger a graceful shutdown
    conn->eof=1;
    alarm->poll.events &= ~POLLIN;
    if (alarm->poll.events)
      watch(alarm);
    else if (is_watching(alarm))
      unwatch(alarm);
    if (!conn->in->limit){
      local_shutdown(conn);
      process_msp_asap();
    }
  }
  
  if (alarm->poll.revents & POLLERR) {
    if (is_watching(&conn->alarm_in))
      unwatch(&conn->alarm_in);
    if (is_watching(&conn->alarm_out))
      unwatch(&conn->alarm_out);
    if (conn->alarm_in.poll.fd!=-1)
      close(conn->alarm_in.poll.fd);
    if (conn->alarm_out.poll.fd!=-1 && conn->alarm_out.poll.fd != conn->alarm_in.poll.fd)
      close(conn->alarm_out.poll.fd);
    conn->alarm_in.poll.fd=-1;
    conn->alarm_in.poll.events=0;
    conn->alarm_out.poll.fd=-1;
    conn->alarm_out.poll.events=0;
    msp_stop(conn->sock);
    process_msp_asap();
  }
}

static void listen_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN) {
    struct socket_address addr;
    addr.addrlen = sizeof addr.store;
    int fd = accept(alarm->poll.fd, &addr.addr, &addr.addrlen);
    if (fd==-1){
      WHYF_perror("accept(%d)", alarm->poll.fd);
      return;
    }
    DEBUGF(msp, "- Incoming TCP connection from %s", alloca_socket_address(&addr));
    watch(&mdp_sock);
    MSP_SOCKET sock = msp_socket(mdp_sock.poll.fd, 0);
    if (msp_socket_is_null(sock))
      return;
    
    struct connection *connection = alloc_connection(sock, fd, io_poll, fd, io_poll);
    if (!connection){
      msp_stop(sock);
      return;
    }

    msp_set_handler(sock, msp_handler, connection);
    msp_connect(sock, &proxy_state->remote_addr);
    process_msp_asap();
    
    if (proxy_state->once){
      unwatch(alarm);
      close(alarm->poll.fd);
      alarm->poll.fd=-1;
    }
  }
}

void sigQuit(int UNUSED(signal))
{
  struct connection *c = proxy_state->connections;
  while(c){
    if (!msp_socket_is_closed(c->sock))
      msp_stop(c->sock);
    c->out->limit = c->out->position = 0;
    c->in->limit = c->in->position = 0;
    c->alarm_in.poll.events = 0;
    c->alarm_out.poll.events = 0;
    if (is_watching(&c->alarm_in))
      unwatch(&c->alarm_in);
    if (is_watching(&c->alarm_out))
      unwatch(&c->alarm_out);
    c=c->_next;
  }
  proxy_state->quit=1;
}

DEFINE_CMD(app_msp_connection, 0,
  "Listen for incoming connections",
  "msp", "listen", "[--once]", "[--forward=<local_port>]", "[--service=<service_name>]", "<port>");
DEFINE_CMD(app_msp_connection, 0,
  "Connect to a remote party",
  "msp", "connect", "[--once]", "[--forward=<local_port>]", "<sid>", "<port>");
static int app_msp_connection(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *sidhex, *port_string, *local_port_string;

  struct proxy_state state;
  bzero(&state, sizeof state);
  state.listener = MSP_SOCKET_NULL;
  proxy_state = &state;

  proxy_state->once = cli_arg(parsed, "--once", NULL, NULL, NULL) == 0;

  if ( cli_arg(parsed, "--forward", &local_port_string, cli_uint, NULL) == -1
    || cli_arg(parsed, "--service", &service_name, NULL, NULL) == -1
    || cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, NULL) == -1
    || cli_arg(parsed, "port", &port_string, cli_uint, NULL) == -1)
    return -1;
  
  struct mdp_sockaddr addr;
  bzero(&addr, sizeof addr);
  
  service_port = addr.port = atoi(port_string);
  proxy_state->saw_error=0;
  
  if (sidhex && *sidhex){
    if (str_to_sid_t(&addr.sid, sidhex) == -1)
      return WHY("str_to_sid_t() failed");
  }
  
  int ret=-1;
  MSP_SOCKET sock = MSP_SOCKET_NULL;
  
  if (service_name){
    // listen for service discovery messages
    service_sock.poll.fd = mdp_socket();
    if (service_sock.poll.fd==-1)
      goto end;
    set_nonblock(service_sock.poll.fd);
    watch(&service_sock);
    // bind
    struct mdp_header header;
    bzero(&header, sizeof(header));

    header.local.sid = BIND_PRIMARY;
    header.local.port = MDP_PORT_SERVICE_DISCOVERY;
    header.remote.sid = SID_ANY;
    header.remote.port = MDP_LISTEN;
    header.ttl = PAYLOAD_TTL_DEFAULT;
    header.flags = MDP_FLAG_BIND|MDP_FLAG_REUSE;
    if (mdp_send(service_sock.poll.fd, &header, NULL, 0)==-1)
      goto end;
    
  }else
    service_sock.poll.fd=-1;
  
  mdp_sock.poll.fd = mdp_socket();
  if (mdp_sock.poll.fd==-1)
    goto end;
  
  set_nonblock(STDIN_FILENO);
  set_nonblock(STDOUT_FILENO);
  bzero(&proxy_state->ip_addr, sizeof proxy_state->ip_addr);
  
  if (local_port_string){
    proxy_state->ip_addr.addrlen = sizeof(proxy_state->ip_addr.inet);
    proxy_state->ip_addr.inet.sin_family = AF_INET;
    proxy_state->ip_addr.inet.sin_port = htons(atoi(local_port_string));
    proxy_state->ip_addr.inet.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  }
  
  if (sidhex && *sidhex){
    if (local_port_string){
      proxy_state->remote_addr = addr;
      listen_alarm.poll.fd = esocket(PF_INET, SOCK_STREAM, 0);
      if (listen_alarm.poll.fd==-1)
	goto end;
      if (socket_bind(listen_alarm.poll.fd, &proxy_state->ip_addr)==-1)
	goto end;
      if (socket_listen(listen_alarm.poll.fd, 0)==-1)
	goto end;
      watch(&listen_alarm);
      DEBUGF(msp, "- Forwarding from %s to %s:%d", alloca_socket_address(&proxy_state->ip_addr), alloca_tohex_sid_t(addr.sid), addr.port);
    }else{
      watch(&mdp_sock);
      sock = msp_socket(mdp_sock.poll.fd, 0);
      proxy_state->once = 1;
      struct connection *conn=alloc_connection(sock, STDIN_FILENO, io_poll, STDOUT_FILENO, io_poll);
      if (!conn)
	goto end;
      msp_set_handler(sock, msp_handler, conn);
      msp_connect(sock, &addr);
      DEBUGF(msp, "- Connecting to %s:%d", alloca_tohex_sid_t(addr.sid), addr.port);
    }
  }else{
    watch(&mdp_sock);
    sock = msp_socket(mdp_sock.poll.fd, 0);
    msp_set_handler(sock, msp_listener, NULL);
    msp_set_local(sock, &addr);
    
    // sock will be closed if listen fails
    if (msp_listen(sock)==-1)
      goto end;
    
    proxy_state->listener=sock;
    if (local_port_string){
      DEBUGF(msp, "- Forwarding from port %d to %s", addr.port, alloca_socket_address(&proxy_state->ip_addr));
    }else{
      proxy_state->once = 1;
      DEBUGF(msp, " - Listening on port %d", addr.port);
    }
  }
  
  process_msp_asap();
  signal(SIGINT, sigQuit);
  signal(SIGTERM, sigQuit);
  proxy_state->quit=0;
  while(!proxy_state->quit && fd_poll()){
    ;
  }
  time_ms_t dummy;
  msp_processing(&dummy);
  ret = proxy_state->saw_error;
  signal(SIGINT, SIG_DFL);
  
end:
  proxy_state->listener = MSP_SOCKET_NULL;
  if (mdp_sock.poll.fd!=-1){
    msp_close_all(mdp_sock.poll.fd);
    mdp_close(mdp_sock.poll.fd);
    mdp_sock.poll.fd=-1;
  }
  if (is_watching(&mdp_sock))
    unwatch(&mdp_sock);
  if (service_sock.poll.fd!=-1){
    if (is_watching(&service_sock))
      unwatch(&service_sock);
    mdp_close(service_sock.poll.fd);
    service_sock.poll.fd=-1;
  }
  if (listen_alarm.poll.fd !=-1 && is_watching(&listen_alarm))
    unwatch(&listen_alarm);
  if (listen_alarm.poll.fd!=-1)
    close(listen_alarm.poll.fd);
  unschedule(&mdp_sock);
  return ret;
}
