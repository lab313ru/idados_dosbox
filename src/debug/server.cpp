/*
       IDA Pro remote debugger server
*/

#include "dosbox.h"
#include "mem.h"

#include <pro.h>
#include <fpro.h>
#ifndef UNDER_CE
#  include <signal.h>
#endif

#include <area.hpp>
#include <idd.hpp>
#include <map>
#include <algorithm>

#ifdef __NT__
//#  ifndef SIGHUP
//#    define SIGHUP 1
//#  endif
#  if defined(__AMD64__)
#    define SYSTEM "Windows64"
#  else
#    define SYSTEM "Windows32"
#  endif
#  ifndef USE_ASYNC
#    define socklen_t int
#  endif
#else   // not NT, i.e. UNIX
#  if defined(__LINUX__)
#    define SYSTEM "Linux"
#  elif defined(__MAC__)
#    define SYSTEM "Mac OS X"
#  else
#    error "Unknown platform"
#  endif

#  include <sys/socket.h>
#  include <netinet/in.h>
#  define SOCKET intptr_t
#  define INVALID_SOCKET (-1)
#  define SOCKET_ERROR   (-1)
#  define closesocket(s)           close(s)
#  ifdef LIBWRAP
extern "C" const char *check_connection(int);
#  endif // LIBWRAP
#endif // !__NT__

#  define __SINGLE_THREADED_SERVER__
#  define DEBUGGER_ID    DEBUGGER_ID_X86_DOSBOX_EMULATOR

#ifdef UNDER_CE
#  include "async.h"
#  ifndef __SINGLE_THREADED_SERVER__
#    define __SINGLE_THREADED_SERVER__
#  endif
#else
#  include "tcpip.h"
#endif

#ifdef __SINGLE_THREADED_SERVER__
#  define __SERVER_TYPE__ "ST"
#else
#  define __SERVER_TYPE__ "MT"
#endif

#include "debmod.h"
#include "rpc_hlp.h"
#include "rpc_server.h"
#include "dosbox_debmod.h"

//--------------------------------------------------------------------------
// SERVER GLOBAL VARIABLES
static const char *server_password = NULL;
static  bool verbose = false;
static  bool g_server_running = false;
//--------------------------------------------------------------------------
#ifdef __SINGLE_THREADED_SERVER__

rpc_server_t *g_global_server = NULL;

int for_all_debuggers(debmod_visitor_t &v)
{
  return g_global_server == NULL ? 0: v.visit(g_global_server->get_debugger_instance());
}
#else

typedef std::map<rpc_server_t *, qthread_t> rpc_server_list_t;
static rpc_server_list_t clients_list;

qmutex_t g_lock = NULL;

// perform an action (func) on all debuggers
int for_all_debuggers(debmod_visitor_t &v)
{
  int code = 0;
  qmutex_lock(g_lock);
  {
    rpc_server_list_t::iterator it;
    for ( it=clients_list.begin(); it != clients_list.end(); ++it )
    {
      code = v.visit(it->first->get_debugger_instance());
      if ( code != 0 )
        break;
    }
  } qmutex_unlock(g_lock);
  return code;
}

#endif

#ifndef USE_ASYNC


static SOCKET listen_socket = INVALID_SOCKET;
static rpc_server_t *g_idados_server = NULL;

//--------------------------------------------------------------------------
void neterr(idarpc_stream_t *irs, const char *module)
{
  int code = irs_error(irs);
  qeprintf("%s: %s\n", module, winerr(code));
  exit(1);
}

//--------------------------------------------------------------------------
static void NT_CDECL shutdown_gracefully()
{

#ifdef __SINGLE_THREADED_SERVER__

  if ( g_global_server != NULL )
  {
    debmod_t *d = g_global_server->get_debugger_instance();
    if ( d != NULL )
      d->dbg_exit_process();
    g_global_server->term_irs();
  }
#else
  qmutex_lock(g_lock);

  for (rpc_server_list_t::iterator it = clients_list.begin(); it != clients_list.end();++it)
  {
    rpc_server_t *server = it->first;
    qthread_t thr = it->second;

    // free thread
    if (thr != NULL)
      qthread_free(thr);

    if (server == NULL || server->irs == NULL)
      continue;

    debmod_t *d = server->get_debugger_instance();
    if ( d != NULL )
      d->dbg_exit_process(); // kill the process instead of letting it run in wild

    server->term_irs();
  }

  clients_list.clear();

  qmutex_unlock(g_lock);

  qmutex_free(g_lock);

#endif

  if ( listen_socket != INVALID_SOCKET )
    closesocket(listen_socket);

  term_subsystem();
}
#endif

//--------------------------------------------------------------------------
static int handle_single_session(rpc_server_t *server)
{
  lprintf("=========================================================\n"
    "Accepting incoming connection...\n");

  bytevec_t open = prepare_rpc_packet(RPC_OPEN);
  append_dd(open, IDD_INTERFACE_VERSION);
  append_dd(open, DEBUGGER_ID);
  append_dd(open, sizeof(ea_t));

  rpc_packet_t *rp = server->process_request(open, true);

  if (rp == NULL)
  {
    lprintf("Could not establish the connection\n");

    delete server;
    return 0;
  }

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;
  bool send_response = true;

  bool ok = extract_long(&answer, end);
  if ( !ok )
  {
    lprintf("Incompatible IDA Pro version\n");
    send_response = false;
  }
  else if ( server_password != NULL )
  {
    char *pass = extract_str(&answer, end);
    if ( strcmp(pass, server_password) != '\0' )
    {
      lprintf("Bad password\n");
      ok = false;
    }
  }

  qfree(rp);

  if ( send_response )
  {
    server->poll_debug_events = false;
    server->has_pending_event = false;

    open = prepare_rpc_packet(RPC_OK);
    append_dd(open, ok);
    server->send_request(open);

    if (ok)
    {
      return 1;

//      qstring cmd;
//      rpc_packet_t *packet = server->process_request(cmd, PRF_POLL);
//      if (packet != NULL)
//        qfree(packet);
    }
  }
/*
  server->network_error_code = 0;

  lprintf("Closing incoming connection...\n");

  server->term_irs();
*/
 return 0;
}

int thread_handle_session(void *ctx)
{
  rpc_server_t *server = (rpc_server_t *)ctx;
  static int s_sess_id = 1;
  int sess_id = s_sess_id++;

  lprintf("session %d entered\n", sess_id);
  handle_single_session(server);
  lprintf("session %d exiting\n", sess_id);

  return 0;
}

int handle_session(rpc_server_t *server)
{
  bool ret;
  g_global_server = server;
  ret = handle_single_session(server);
  g_global_server = NULL;

  return ret;
}

/*
//--------------------------------------------------------------------------
// debugger remote server - TCP/IP mode
int NT_CDECL main(int argc, char *argv[])
{
  int port_number = DEBUGGER_PORT_NUMBER;
  lprintf("IDA " SYSTEM " remote debug server(" __SERVER_TYPE__ "). Version 1.%d. Copyright HexRays 2004-2009\n", IDD_INTERFACE_VERSION);
  while ( argc > 1 && (argv[1][0] == '-' || argv[1][0] == '/'))
  {
    switch ( argv[1][1] )
    {
    case 'p':
      port_number = atoi(&argv[1][2]);
      break;
    case 'P':
      server_password = argv[1] + 2;
      break;
    case 'v':
      verbose = true;
      break;
    default:
      error("usage: ida_remote [switches]\n"
        "  -p...  port number\n"
        "  -P...  password\n"
        "  -v     verbose\n");
    }
    argv++;
    argc--;
  }

  // call the debugger module to initialize its subsystem once
  if (
    !init_subsystem()
#ifndef __SINGLE_THREADED_SERVER__
    || ((g_lock = qmutex_create())== NULL)
#endif
    )
  {
    lprintf("Could not initialize subsystem!");
    return -1;
  }

#ifndef __NT__
  signal(SIGHUP, shutdown_gracefully);
#endif
  signal(SIGINT, shutdown_gracefully);
  signal(SIGTERM, shutdown_gracefully);
  signal(SIGSEGV, shutdown_gracefully);
  //  signal(SIGPIPE, SIG_IGN);

  if ( !init_irs_layer() )
  {
    neterr(NULL, "init_sockets");
  }

  listen_socket = socket(AF_INET, SOCK_STREAM, 0);

  if ( listen_socket == -1 )
    neterr(NULL, "socket");

  setup_irs((idarpc_stream_t*)listen_socket);

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = qhtons(short(port_number));

  if ( bind(listen_socket, (sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR )
    neterr((idarpc_stream_t *)listen_socket, "bind");

  if ( listen(listen_socket, SOMAXCONN) == SOCKET_ERROR )
    neterr((idarpc_stream_t *)listen_socket, "listen");

  lprintf("Listening on port #%u...\n", port_number);

  while ( true )
  {
    sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    SOCKET rpc_socket = accept(listen_socket, (sockaddr *)&sa, &salen);
    if ( rpc_socket == -1 )
      neterr((idarpc_stream_t *)listen_socket, "accept");
#if defined(__LINUX__) && defined(LIBWRAP)
    const char *p;
    if((p = check_connection(rpc_socket)) != NULL) {
      fprintf(stderr,
        "ida-server CONNECTION REFUSED from %s (tcp_wrappers)\n", p);
      shutdown(rpc_socket, 2);
      close(rpc_socket);
      continue;
    }
#endif // defined(__LINUX__) && defined(LIBWRAP)

    rpc_server_t *server = new rpc_server_t(rpc_socket);
    server->verbose = verbose;
    server->set_debugger_instance(create_debug_session());
    handle_session(server);
  }
/ * NOTREACHED
  term_subsystem();
#ifndef __SINGLE_THREADED_SERVER__
  qmutex_free(g_lock);
#endif
* /
}

main */


int idados_init()
{
  int port_number = DEBUGGER_PORT_NUMBER;

  // call the debugger module to initialize its subsystem once
  if (!init_subsystem())
  {
    lprintf("Could not initialize subsystem!");
    return -1;
  }

  if ( !init_irs_layer() )
  {
    neterr(NULL, "init_sockets");
  }

  listen_socket = socket(AF_INET, SOCK_STREAM, 0);

  if ( listen_socket == -1 )
    neterr(NULL, "socket");

  setup_irs((idarpc_stream_t*)listen_socket);

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = qhtons(short(port_number));

  if ( bind(listen_socket, (sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR )
    neterr((idarpc_stream_t *)listen_socket, "bind");

  if ( listen(listen_socket, SOMAXCONN) == SOCKET_ERROR )
    neterr((idarpc_stream_t *)listen_socket, "listen");

  lprintf("Listening on port #%u...\n", port_number);

 return 1;
}

void idados_term()
{
  shutdown_gracefully();
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

idaman callui_t dummy_callui(ui_notification_t what,...);


int idados_start_session()
{
    callui = &dummy_callui;
    sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    SOCKET rpc_socket = accept(listen_socket, (sockaddr *)&sa, &salen);
    if ( rpc_socket == -1 )
      neterr((idarpc_stream_t *)listen_socket, "accept");
#if defined(__LINUX__) && defined(LIBWRAP)
    const char *p;
    if((p = check_connection(rpc_socket)) != NULL) {
      fprintf(stderr,
        "ida-server CONNECTION REFUSED from %s (tcp_wrappers)\n", p);
      shutdown(rpc_socket, 2);
      close(rpc_socket);
      continue;
    }
#endif // defined(__LINUX__) && defined(LIBWRAP)

    g_idados_server = new rpc_server_t(rpc_socket);
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

  if(ret)
  {
   bytevec_t cmd;
   dosbox_debmod_t *dm = (dosbox_debmod_t *)g_idados_server->get_debugger_instance();
   
   //g_idados_server->poll_required = dm->events.empty() == true ? false : true;
   //g_idados_server->poll_required = false;
//printf("OK!\n");
   dm->dosbox_step_ret = 0;
   rpc_packet_t *packet = g_idados_server->process_request(cmd); // FIXME: "must_login" argument?
   if (packet != NULL)
     qfree(packet);

   return dm->dosbox_step_ret;
  }
/*
  server->network_error_code = 0;

  lprintf("Closing incoming connection...\n");

  server->term_irs();
*/
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
  
  // FIXME: poll_required is gone. Replace it by anything?
  //g_idados_server->poll_required = true;
  dm->hit_breakpoint(addr);

  idados_stopped();

}


