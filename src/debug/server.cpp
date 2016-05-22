/*
       IDA remote debugger server
*/

#include "server.h"
#include "dosbox_debmod.h"

#if defined(_MSC_VER) || defined(__NT__)
typedef int socklen_t;
#endif

// DOSBox headers
#include "dosbox.h"
#include "mem.h"
rpc_server_t *g_idados_server = NULL;
static  bool g_server_running = false;

//--------------------------------------------------------------------------
// SERVER GLOBAL VARIABLES
static const char *server_password = NULL;
static bool verbose = false;
static bool keep_broken_connections = false;

#ifdef __SINGLE_THREADED_SERVER__

static bool init_lock(void) { return true; }
bool lock_begin(void) { return true; }
bool lock_end(void) { return true; }

static inline bool srv_lock_init(void) { return true; }
bool srv_lock_begin(void) { return true; }
bool srv_lock_end(void) { return true; }
static inline bool srv_lock_free(void) { return true; }

#else

static qmutex_t g_mutex = NULL;

//--------------------------------------------------------------------------
static bool init_lock(void)
{
  g_mutex = qmutex_create();
  return g_mutex != NULL;
}

//--------------------------------------------------------------------------
bool lock_begin(void)
{
  return qmutex_lock(g_mutex);
}

//--------------------------------------------------------------------------
bool lock_end(void)
{
  return qmutex_unlock(g_mutex);
}

//--------------------------------------------------------------------------
qmutex_t g_lock = NULL;

//--------------------------------------------------------------------------
static inline bool srv_lock_init(void)
{
  g_lock = qmutex_create();
  return g_lock != NULL;
}

//--------------------------------------------------------------------------
bool srv_lock_begin(void)
{
  return qmutex_lock(g_lock);
}

//--------------------------------------------------------------------------
bool srv_lock_end(void)
{
  return qmutex_unlock(g_lock);
}

//--------------------------------------------------------------------------
static inline bool srv_lock_free(void)
{
  return qmutex_free(g_lock);
}

#endif

//--------------------------------------------------------------------------
rpc_server_list_t clients_list;
rpc_server_t *g_global_server = NULL;

//--------------------------------------------------------------------------
// perform an action (func) on all debuggers
int for_all_debuggers(debmod_visitor_t &v)
{
  int code = 0;
  srv_lock_begin();
  {
    rpc_server_list_t::iterator it;
    for ( it=clients_list.begin(); it != clients_list.end(); ++it )
    {
      code = v.visit(it->first->get_debugger_instance());
      if ( code != 0 )
        break;
    }
  } srv_lock_end();
  return code;
}


//--------------------------------------------------------------------------
void neterr(idarpc_stream_t *irs, const char *module)
{
  int code = irs_error(irs);
  qeprintf("%s: %s\n", module, winerr(code));
  exit(1);
}

static SOCKET listen_socket = INVALID_SOCKET;


// Set this variable before generating SIGINT for internal purposes
bool ignore_sigint = false;

//--------------------------------------------------------------------------
static void NT_CDECL shutdown_gracefully(int signum)
{
  if ( signum == SIGINT && ignore_sigint )
  {
    ignore_sigint = false;
    return;
  }

#if 0
#if defined(__NT__) || defined(__ARM__) // strsignal() is not available
  qeprintf("got signal #%d, terminating\n", signum);
#else
  qeprintf("%s: terminating the server\n", strsignal(signum));
#endif
#endif

  srv_lock_begin();

  for (rpc_server_list_t::iterator it = clients_list.begin(); it != clients_list.end();++it)
  {
    rpc_server_t *server = it->first;
#ifndef __SINGLE_THREADED_SERVER__
    qthread_t thr = it->second;

    // free thread
    if ( thr != NULL )
      qthread_free(thr);
#endif
    if ( server == NULL || server->irs == NULL )
      continue;

    debmod_t *d = server->get_debugger_instance();
    if ( d != NULL )
      d->dbg_exit_process(); // kill the process instead of letting it run in wild

    server->term_irs();
  }

  clients_list.clear();
  srv_lock_end();
  srv_lock_free();

  if ( listen_socket != INVALID_SOCKET )
    closesocket(listen_socket);

  term_subsystem();
  //_exit(1);
}

//--------------------------------------------------------------------------
static int handle_single_session(rpc_server_t *server)
{
  static int s_sess_id = 1;
  int sid = s_sess_id++;

  char peername[MAXSTR];
  if ( !irs_peername(server->irs, peername, sizeof(peername), false) )
    qstrncpy(peername, "(unknown)", sizeof(peername));
  lprintf("=========================================================\n"
          "[%d] Accepting connection from %s...\n", sid, peername);

  bytevec_t req = prepare_rpc_packet(RPC_OPEN);
  append_dd(req, IDD_INTERFACE_VERSION);
  append_dd(req, DEBUGGER_ID);
  append_dd(req, sizeof(ea_t));

  rpc_packet_t *rp = server->process_request(req, true);

  bool handle_request = true;
  bool send_response  = true;
  bool ok;
  if ( rp == NULL )
  {
    lprintf("[%d] Could not establish the connection\n", sid);
    handle_request = false;
    send_response  = false;
  }

  if ( handle_request )
  {
    // Answer is beyond the rpc_packet_t buffer
    const uchar *answer = (uchar *)(rp+1);
    const uchar *end = answer + rp->length;

    ok = extract_long(&answer, end);
    if ( !ok )
    {
      lprintf("[%d] Incompatible IDA version\n", sid);
      send_response = false;
    }
    else if ( server_password != NULL )
    {
      char *pass = extract_str(&answer, end);
      if ( strcmp(pass, server_password) != '\0' )
      {
        lprintf("[%d] Bad password\n", sid);
        ok = false;
      }
    }

    qfree(rp);
  }

  if ( send_response )
  {
    req = prepare_rpc_packet(RPC_OK);
    append_dd(req, ok);
    server->send_request(req);

    if ( ok )
    {
      return 1;
#if 0
      // the main loop: handle client requests until it drops the connection
      // or sends us RPC_OK (see rpc_debmod_t::close_remote)
      bytevec_t empty;
      rpc_packet_t *packet = server->process_request(empty);
      if ( packet != NULL )
        qfree(packet);
#endif
    }
  }

  return 0;
}

//--------------------------------------------------------------------------
int idaapi thread_handle_session(void *ctx)
{
  rpc_server_t *server = (rpc_server_t *)ctx;
  handle_single_session(server);
  return 0;
}

//--------------------------------------------------------------------------
int handle_session(rpc_server_t *server)
{
#ifndef __SINGLE_THREADED_SERVER__
  qthread_t t = qthread_create(thread_handle_session, (void *)server);
  bool run_handler = false;
#else
  bool t = true;
  bool run_handler = true;
#endif

  // Add the session to the list
  srv_lock_begin();
  clients_list[server] = t;
  g_global_server = server;
  srv_lock_end();

  if ( run_handler )
    return handle_single_session(server);

  return 0;
}

//--------------------------------------------------------------------------
bool are_broken_connections_supported(void)
{
  return dosbox_debmod_t::reuse_broken_connections;
}



int idados_init()
{
#ifdef ENABLE_LOWCNDS
  init_idc();
#endif

  // call the debugger module to initialize its subsystem once
  if ( !init_lock()
    || !init_subsystem()
#ifndef __SINGLE_THREADED_SERVER__
    || !srv_lock_init()
#endif
    )
  {
    lprintf("Could not initialize subsystem!");
    return -1;
  }

  bool reuse_conns = are_broken_connections_supported();
  int port_number = DEBUGGER_PORT_NUMBER;

#if 0
  // TODO: Should we replace this by atexit or similar?
  signal(SIGINT, shutdown_gracefully);
  signal(SIGTERM, shutdown_gracefully);
  signal(SIGSEGV, shutdown_gracefully);
  //  signal(SIGPIPE, SIG_IGN);
#endif

  if ( !init_irs_layer() )
  {
    neterr(NULL, "init_sockets");
  }

  listen_socket = socket(AF_INET, SOCK_STREAM, 0);
  if ( listen_socket == INVALID_SOCKET )
    neterr(NULL, "socket");

  idarpc_stream_t *irs = (idarpc_stream_t *)listen_socket;
  setup_irs(irs);

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = qhtons(short(port_number));

  if ( bind(listen_socket, (sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR )
    neterr(irs, "bind");

  if ( listen(listen_socket, SOMAXCONN) == SOCKET_ERROR )
    neterr(irs, "listen");

  hostent *local_host = gethostbyname("");
  if ( local_host != NULL )
  {
    const char *local_ip = inet_ntoa(*(struct in_addr *)*local_host->h_addr_list);
    if ( local_host->h_name != NULL && local_ip != NULL )
      lprintf("Host %s (%s): ", local_host->h_name, local_ip);
    else if ( local_ip != NULL )
      lprintf("Host %s: ", local_ip);
  }
  lprintf("Listening on port #%u...\n", port_number);

  return 1;
}

void idados_term()
{
  shutdown_gracefully(0);
}

bool DEBUG_RemoteDataReady(void) //FIXME need to rework this.
{
 if(g_idados_server)
   return irs_ready(g_idados_server->irs, 1); //wait 1 millisecond.
/*
 fd_set fds;
 int nfds;
 struct timeval tv;

 if(r_debug.connected == false)
   return false;
 
 memset(&tv, 0, sizeof(tv));

 nfds = r_debug.socket + 1;
 FD_ZERO(&fds);
 FD_SET(r_debug.socket, &fds);
 
 select(nfds, &fds, NULL, NULL, &tv);
 if(FD_ISSET(r_debug.socket, &fds))
   return true;
*/
  return false;
}

idaman callui_t idaapi dummy_callui(ui_notification_t what, ...)
{
  // TODO: Maybe implement at least ui_msg?
  callui_t i;
  i.cnd = true;
  return i;
}


class dosbox_rpc_server_t : public rpc_server_t
{
  public:
    dosbox_rpc_server_t(idarpc_stream_t *irs) : rpc_server_t(irs) { }
    virtual int poll_events(int timeout_ms);
};

int dosbox_rpc_server_t::poll_events(int timeout_ms)
{
  int code = rpc_server_t::poll_events(timeout_ms);

  // poll_events sets poll_debug_events to true if there were no
  // packets. We return a non-zero error code to let control return to dosbox.
  if (!has_pending_event && poll_debug_events)
    return -1;
  return code;
}




int idados_start_session()
{
    callui = &dummy_callui;
    sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    SOCKET rpc_socket = accept(listen_socket, (sockaddr *)&sa, &salen);
    if ( rpc_socket == INVALID_SOCKET )
    {
      if ( errno != EINTR )
        neterr((idarpc_stream_t *)listen_socket, "accept");
      return 0;
    }
#if defined(__LINUX__) && defined(LIBWRAP)
    const char *p = check_connection(rpc_socket);
    if ( p != NULL )
    {
      fprintf(stderr,
        "ida-server CONNECTION REFUSED from %s (tcp_wrappers)\n", p);
      shutdown(rpc_socket, 2);
      close(rpc_socket);
      return 0;
    }
#endif // defined(__LINUX__) && defined(LIBWRAP)

    g_idados_server = new dosbox_rpc_server_t((idarpc_stream_t *)rpc_socket);
    g_idados_server->verbose = true;
    g_idados_server->set_debugger_instance(create_debug_session());
    dosbox_debmod_t *dm = (dosbox_debmod_t *)g_idados_server->get_debugger_instance();
    dm->debug_debugger = true;

    return handle_session(g_idados_server);
}

int idados_handle_command()
{
  bool ret = 1;
  if(g_idados_server == NULL)
    ret = idados_start_session();

  rpc_server_t *server = g_idados_server;

  if(ret)
  {
    dosbox_debmod_t *dm = (dosbox_debmod_t *)server->get_debugger_instance();

    dm->dosbox_step_ret = 0;
    bytevec_t empty;
    rpc_packet_t *packet = server->process_request(empty); // FIXME: "must_login" argument?
    if (packet != NULL)
      qfree(packet);

    return dm->dosbox_step_ret;
  }
#if 0
  server->network_error_code = 0;
  lprintf("[%d] Closing connection from %s...\n", sid, peername);

  bool preserve_server = keep_broken_connections && server->get_broken_connection();
  if ( !preserve_server )
  { // Terminate dedicated debugger instance.
    server->get_debugger_instance()->dbg_term();
    server->term_irs();
  }
  else
  {
    server->term_irs();
    lprintf("[%d] Debugged session entered into sleeping mode\n", sid);
    server->prepare_broken_connection();
  }

  if ( !preserve_server )
  {
    // Remove the session from the list
    srv_lock_begin();
    for (rpc_server_list_t::iterator it = clients_list.begin(); it != clients_list.end();++it)
    {
      if ( it->first != server )
        continue;

#ifndef __SINGLE_THREADED_SERVER__
      // free the thread resources
      qthread_free(it->second);
#endif

      // remove client from the list
      clients_list.erase(it);
      break;
    }
    srv_lock_end();

    // Free the debug session
    delete server;
#endif
  return 0;
}

void idados_stopped()
{
 g_server_running = false;
}

void idados_running()
{
 g_server_running = true;
}

bool idados_is_running()
{
 return g_server_running;
}

void idados_hit_breakpoint(PhysPt addr)
{
  if(!g_idados_server)
    return;

  dosbox_debmod_t *dm = (dosbox_debmod_t *)g_idados_server->get_debugger_instance();
  
  dm->hit_breakpoint(addr);

  idados_stopped();

}


