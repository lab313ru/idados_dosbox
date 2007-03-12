#include <vector>
#include <string>

#ifndef WIN32
  #include <errno.h>
  #include <fcntl.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #define INVALID_SOCKET -1
#else
  #include <winsock.h>
  #define sleep(x) Sleep(x)
  #define errno WSAGetLastError()
#endif

#ifndef ushort
typedef unsigned short ushort;
#endif

#include "debug_remote.h"

#include "pack.cpp"

using std::string;
using std::vector;

#define TIMEOUT         (1000/25)       // in milliseconds, timeout for polling
#define verb(x) printf x
//ERIC
struct  RemoteDebug {
#ifdef WIN32
	 SOCKET listen_socket;
	 SOCKET socket;
#else
    int listen_socket;
    int socket;
#endif
	 sockaddr sa;
    char *password;
    bool connected;
    
    PhysPt base; 
     
    //ida pro stuff
    bool has_pending_event;
    bool poll_debug_events;
    vector<debug_event_t> events;
    bool sent_event;
    Bits ret; //FIXME !!! ERIC this is evil
    memory_info_t *miv;
} r_debug;


static string perform_request(const rpc_packet_t *rp);


//IDA Pro helper functions.
//--------------------------------------------------------------------------
inline string prepare_rpc_packet(uchar code)
{
  rpc_packet_t rp;
  rp.length = 0;
  rp.code   = code;
  
 //DEBUG  printf("code = %d, sizeof(rp) = %d sizeof(ulong) = %d sizeof(uchar) = %d\n", code, sizeof(rpc_packet_t), sizeof(ulong), sizeof(uchar));
  
  return string((char *)&rp, 5); //sizeof(rp));
}

//--------------------------------------------------------------------------
static void append_long(string &s, ulong x)
{
  uchar buf[sizeof(ulong)+1];
  uchar *ptr = buf;
  ptr = pack_dd(ptr, buf + sizeof(buf), x);
  s.append((char *)buf, ptr-buf);
}

//--------------------------------------------------------------------------
inline ulong extract_long(const uchar **ptr, const uchar *end)
{
  return unpack_dd(ptr, end);
}

//--------------------------------------------------------------------------
inline void append_str(string &s, const char *str)
{
  if ( str == NULL ) str = "";
  size_t len = strlen(str) + 1;
  s.append(str, len);
}

//--------------------------------------------------------------------------
static char *extract_str(const uchar **ptr, const uchar *end)
{
  char *str = (char *)*ptr;
  *ptr = (const uchar *)strchr(str, '\0') + 1;
  if ( *ptr > end )
    *ptr = end;
  return str;
}

//--------------------------------------------------------------------------
inline void extract_memory(const uchar **ptr, const uchar *end, void *buf, size_t size)
{
  if ( buf != NULL )
    memcpy(buf, *ptr, size);
  *ptr += size;
  if ( *ptr > end )
    *ptr = end;
}

//--------------------------------------------------------------------------
static void append_ea(string &s, ea_t x)
{
  uchar buf[sizeof(ea_t)+1];
  uchar *ptr = buf;
  ptr = pack_dd(ptr, buf+sizeof(buf), x+1);
  s.append((char *)buf, ptr-buf);
}

//--------------------------------------------------------------------------
inline ea_t extract_ea(const uchar **ptr, const uchar *end)
{
  return unpack_dd(ptr, end) - 1;
}

//--------------------------------------------------------------------------
inline void append_breakpoint(string &s, const e_breakpoint_t *info)
{
  append_ea(s, info->hea);
  append_ea(s, info->kea);
}

//--------------------------------------------------------------------------
static void append_exception(string &s, const e_exception_t *e)
{
  append_long(s, e->code);
  append_long(s, e->can_cont);
  append_ea(s, e->ea);
  append_str(s, e->info);
}

//--------------------------------------------------------------------------
static void append_module_info(string &s, const module_info_t *info)
{
  append_str(s, info->name);
  append_ea(s, info->base);
  append_ea(s, info->size);
  append_ea(s, info->rebase_to);
}

//--------------------------------------------------------------------------
static void append_debug_event(string &s, const debug_event_t *ev)
{
  append_long(s, ev->eid);
  append_long(s, ev->pid);
  append_long(s, ev->tid);
  append_ea  (s, ev->ea);
  append_long(s, ev->handled);
  switch ( ev->eid )
  {
    case NO_EVENT:       // Not an interesting event
    case THREAD_START:   // New thread started
    case STEP:           // One instruction executed
    case SYSCALL:        // Syscall (not used yet)
    case WINMESSAGE:     // Window message (not used yet)
    case PROCESS_DETACH: // Detached from process
    default:
      break;
    case PROCESS_START:  // New process started
    case PROCESS_ATTACH: // Attached to running process
    case LIBRARY_LOAD:   // New library loaded
      append_module_info(s, &ev->modinfo);
      break;
    case PROCESS_EXIT:   // Process stopped
    case THREAD_EXIT:    // Thread stopped
      append_long(s, ev->exit_code);
      break;
    case BREAKPOINT:     // Breakpoint reached
      append_breakpoint(s, &ev->bpt);
      break;
    case EXCEPTION:      // Exception
      append_exception(s, &ev->exc);
      break;
    case LIBRARY_UNLOAD: // Library unloaded
    case INFORMATION:    // User-defined information
      append_str(s, ev->info);
      break;
  }
}

//--------------------------------------------------------------------------
static void extract_module_info(const uchar **ptr, const uchar *end, module_info_t *info)
{
  char *name = extract_str(ptr, end);
  info->base = extract_ea(ptr, end);
  info->size = extract_ea(ptr, end);
  info->rebase_to = extract_ea(ptr, end);
  strncpy(info->name, name, sizeof(info->name));
}

//--------------------------------------------------------------------------
inline void extract_breakpoint(const uchar **ptr, const uchar *end, e_breakpoint_t *info)
{
  info->hea = extract_ea(ptr, end);
  info->kea = extract_ea(ptr, end);
}

//--------------------------------------------------------------------------
static void extract_exception(const uchar **ptr, const uchar *end, e_exception_t *exc)
{
  exc->code     = extract_long(ptr, end);
  exc->can_cont = extract_long(ptr, end);
  exc->ea       = extract_ea(ptr, end);
  char *info    = extract_str(ptr, end);
  strncpy(exc->info, info, sizeof(exc->info));
}

//--------------------------------------------------------------------------
static void extract_debug_event(const uchar **ptr, const uchar *end, debug_event_t *ev)
{
  ev->eid     = event_id_t(extract_long(ptr, end));
  ev->pid     = extract_long(ptr, end);
  ev->tid     = extract_long(ptr, end);
  ev->ea      = extract_ea(ptr, end);
  ev->handled = extract_long(ptr, end);
  switch ( ev->eid )
  {
    case NO_EVENT:       // Not an interesting event
    case THREAD_START:   // New thread started
    case STEP:           // One instruction executed
    case SYSCALL:        // Syscall (not used yet)
    case WINMESSAGE:     // Window message (not used yet)
    case PROCESS_DETACH: // Detached from process
    default:
      break;
    case PROCESS_START:  // New process started
    case PROCESS_ATTACH: // Attached to running process
    case LIBRARY_LOAD:   // New library loaded
      extract_module_info(ptr, end, &ev->modinfo);
      break;
    case PROCESS_EXIT:   // Process stopped
    case THREAD_EXIT:    // Thread stopped
      ev->exit_code = extract_long(ptr, end);
      break;
    case BREAKPOINT:     // Breakpoint reached
      extract_breakpoint(ptr, end, &ev->bpt);
      break;
    case EXCEPTION:      // Exception
      extract_exception(ptr, end, &ev->exc);
      break;
    case LIBRARY_UNLOAD: // Library unloaded
    case INFORMATION:    // User-defined information
      strncpy(ev->info, extract_str(ptr, end), sizeof(ev->info));
      break;
  }
}

//--------------------------------------------------------------------------
static void extract_exception_info(const uchar **ptr,
                                                const uchar *end,
                                                int qty)
{
  //exception_info_t *extable = NULL;
  long code, flags;
  string name, desc;
  
  if ( qty > 0 )
  {
   // extable = new exception_info_t[qty];
   // if ( extable != NULL )
   // {
      for ( int i=0; i < qty; i++ )
      {
        code  = extract_long(ptr, end);
        flags = extract_long(ptr, end);
        name  = extract_str(ptr, end);
        desc  = extract_str(ptr, end);
        
        printf("Exception[%d] (%08x, %08x, '%s', '%s'\n",i, code, flags, name.c_str(), desc.c_str());
/*
        extable[i].code  = extract_long(ptr, end);
        extable[i].flags = extract_long(ptr, end);
        extable[i].name  = extract_str(ptr, end);
        extable[i].desc  = extract_str(ptr, end);
*/
      }
  //  }
  }
  return ; //extable;
}

//--------------------------------------------------------------------------
static void extract_regvals(const uchar **ptr, const uchar *end, regval_t *values, int n)
{
  size_t size = sizeof(regval_t) * n;
  memcpy(values, *ptr, size);
  *ptr += size;
  if ( *ptr > end )
    *ptr = end;
}


//--------------------------------------------------------------------------
static void append_memory_info(string &s, const memory_info_t *info)
{
  append_ea(s, info->startEA);
  append_ea(s, info->size());
  append_long(s, info->perm);
  append_str(s, info->name);
  append_str(s, info->sclass);
}

//--------------------------------------------------------------------------
inline void append_memory(string &s, const void *buf, size_t size)
{
  if ( size != 0 )
    s.append((char *)buf, size);
}

inline void append_longlong(string &s, ulonglong x)
{
  uchar buf[sizeof(ulonglong)+1];
  uchar *ptr = buf;
  ptr = pack_dq(ptr, buf + sizeof(buf), x);
  s.append((char *)buf, ptr-buf);
}

inline void append_short(string &s, ushort x)
{
  uchar buf[sizeof(ushort)+1];
  uchar *ptr = buf;
  ptr = pack_dw(ptr, buf + sizeof(buf), x);
  s.append((char *)buf, ptr-buf);
}

//--------------------------------------------------------------------------
inline void append_regvals(string &s, const regval_t *values, int n)
{

//FIXME possibly not endian safe!!!
//  s.append((char *)values, sizeof(regval_t)*n);

 const regval_t *reg_ptr = values;
 
 for(int i=0; i < n; i++)
 {
   append_longlong(s, reg_ptr->ival);
   //append_long(s, 10);
   //append_long(s, 0);
   
   for(int j=0; j < 6; j++)
     append_short(s, reg_ptr->fval[j]);
   reg_ptr++;
 }
 
}

static void finalize_packet(string &cmd)
{
  rpc_packet_t *rp = (rpc_packet_t *)&cmd[0];
  rp->length = htonl((ulong)(cmd.length() - 5)); //sizeof(rpc_packet_t)));
}

int send_request(string &s)     // returns error code
{
   // if nothing is initialized yet or error occurred, silently fail
  if ( r_debug.connected == false)
      return -1;

  finalize_packet(s);
  const char *ptr = s.c_str();
  int left = int(s.length());
#ifdef DEBUG_NETWORK
  rpc_packet_t *rp = (rpc_packet_t *)ptr;
  int len = ntohl(rp->length);
  //show_hex(rp+1, len, "SEND %s %d bytes:\n", get_rpc_name(rp->code), len);
//  msg("SEND %s\n", get_rpc_name(rp->code));



#endif

/*

printf("send data = ");
for(int i = 0;i<left;i++)
  printf("%d,",ptr[i]);
printf("\n");

*/
  while ( left > 0 )
  {
    //ssize_t code = irs_send(irs, ptr, left);
    ssize_t code = send(r_debug.socket, ptr, (size_t)left, 0);
    if ( code == -1 )
    {
      //code = irs_error(irs);
      //network_error_code = code;
      //warning("irs_send: %s", winerr(code));
      printf("Argh! in send_request!\n");
      return code;
    }
    left -= code;
    ptr += code;
  }
  return 0;
}

int irs_ready()
{
  int milliseconds = TIMEOUT;
  int seconds = milliseconds / 1000;
  milliseconds %= 1000;
  struct timeval tv = { seconds, milliseconds * 1000 };
  fd_set rd;
  FD_ZERO(&rd);
  FD_SET(r_debug.socket, &rd);
  return select(int(r_debug.socket+1),
         &rd, NULL,
         NULL,
         seconds != -1 ? &tv : NULL);
}

/*
//--------------------------------------------------------------------------
int remote_get_debug_event(debug_event_t *event, bool ida_is_idle)
{

  if ( has_pending_event )
  {
    verbev(("get_debug_event => has pending event, returning it\n"));
    *event = pending_event;
    has_pending_event = false;
    poll_debug_events = false;
    return 1;
  }

  int result = false;
  if ( poll_debug_events )
  {
    // do we have something waiting?
    // we must use TIMEOUT here to avoid competition between
    // IDA analyzer and the debugger program.
    // The analysis will be slow during the application run.
    // As soon as the program is suspended, the analysis will be fast
    // because get_debug_event() will not be called.
    if ( irs_ready(irs) != 0 )
    {
      verbev(("get_debug_event => remote has an event for us\n"));
      // get the packet - it should be RPC_EVENT (nothing else can be)
      string empty;
      rpc_packet_t *rp = process_request(empty, ida_is_idle);
      verbev(("get_debug_event => processed remote event, has=%d\n", has_pending_event));
      if ( rp != NULL || !has_pending_event )
        error("rpc: event protocol error");
    }
  }
  else
  {
    verbev(("get_debug_event => first time, send GET_DEBUG_EVENT\n"));
    string cmd = prepare_rpc_packet(RPC_GET_DEBUG_EVENT);
    append_long(cmd, ida_is_idle);

    rpc_packet_t *rp = process_request(cmd);
    if ( rp == NULL ) return -1;
    const uchar *answer = (uchar *)(rp+1);
    const uchar *end = answer + rp->length;

    result = extract_long(&answer, end);
    if ( result == 1 )
      extract_debug_event(&answer, end, event);
    else
      poll_debug_events = true;
    verbev(("get_debug_event => remote said %d, poll=%d now\n", result, poll_debug_events));
    qfree(rp);
  }  
  return result;
}
*/

//--------------------------------------------------------------------------
static int poll_events(bool idling)
{
  int code = 0;
  debug_event_t ev;

    if ( !r_debug.events.empty() && r_debug.sent_event == false )
    {
      
      for(int i=0;i < r_debug.events.size();i++)
      {
        ev = r_debug.events[i];
        if(ev.handled == false)
        {
          r_debug.sent_event = true;
          ev.handled = true;
          r_debug.events[i] = ev;
          
          printf("OUT <- %s\n",get_event_id_name(ev.eid));
          string cmd = prepare_rpc_packet(RPC_EVENT);
          append_debug_event(cmd, &ev);
          code = send_request(cmd);
        }
      }
    }

  return code;
}

static int recv_all(void *ptr, int left, bool idling, bool poll)
{
  int code;
  int i;
  
  while ( true )
  {
    code = 0;
    if ( left <= 0 )
      break;
    // since we have to poll the debugged program from the same thread as ours,
    // we poll it here when waiting for the client to send commands
/*
    if ( poll && irs_ready() == 0 )
    {
      code = poll_events(idling);
      if ( code != 0 )
        break;
      continue;
    }
*/
    
    poll_events(false); //ERIC
    
    code = recv(r_debug.socket, (char *)ptr, left, 0);
    if(code == 0)
    {
      printf("\nRemote client closed connection.\n\n");
      r_debug.connected = false;
      DEBUG_ContinueWithoutDebug();
      return -1;
    }

 /*
       for(i = 0; code == -1 && i < 5;i++)
    {
      sleep(1);
      code = recv(r_debug.socket, ptr, left, 0);
    }
    
    if ( code == -1 )
    {
      //code = irs_error(irs);
      //network_error_code = code;
      //warning("irs_recv: %s", winerr(code));
      printf("Error: recv_all() code = %d\n", code);
      break;
    }
*/
    left -= code;
    // visual studio 64 does not like simple
    // (char*)ptr += code;
    char *p2 = (char *)ptr;
    p2 += code;
    ptr = p2;
  }
  return code;
}

rpc_packet_t *recv_request(bool idling)
{
   // if nothing is initialized yet or error occurred, silently fail
  if ( !r_debug.connected )
    return NULL;

  if(!idling && DEBUG_RemoteDataReady() == false)
    return NULL;

  for(;!DEBUG_RemoteDataReady();) //loop until we have data. evil I know. :(
   sleep(1);

  rpc_packet_t p;
  int code = recv_all(&p, sizeof(rpc_packet_t), idling, r_debug.poll_debug_events);
  if ( code != 0 )
    return NULL;

  int size = p.length = ntohl(p.length);
  if ( size < 0 )
    printf("rpc: bad packet length");
  size += sizeof(rpc_packet_t);
  uchar *urp = (uchar *)malloc(size);
  if ( urp == NULL )
    printf("rpc: no local memory");

  memcpy(urp, &p, sizeof(rpc_packet_t));
  int left = size - sizeof(rpc_packet_t);
  uchar *ptr = urp + sizeof(rpc_packet_t);
  code = recv_all(ptr, left, idling, false);
  if ( code != 0 )
    return NULL;

  rpc_packet_t *rp = (rpc_packet_t *)urp;
#ifdef DEBUG_NETWORK
  int len = rp->length;
  show_hex(rp+1, len, "RECV %s %d bytes:\n", get_rpc_name(rp->code), len);
//  msg("RECV %s\n", get_rpc_name(rp->code));
#endif
  return rp;
}

static rpc_packet_t *process_request(string &cmd, bool ida_is_idle=false)
{
  bool only_events = cmd.empty();
//  while ( true )
//  {
    if ( !cmd.empty() )
    {
      int code = send_request(cmd);
      if ( code != 0 )
        return NULL;
      rpc_packet_t *rp = (rpc_packet_t *)cmd.c_str();
      if ( only_events && rp->code == RPC_EVOK )
        return NULL;
      if ( rp->code == RPC_ERROR )
        printf("Major Error!!!\n");
    }
    rpc_packet_t *rp = recv_request(ida_is_idle);
    if ( rp == NULL )
      return NULL;
    switch ( rp->code )
    {
      case RPC_UNK:
        printf("rpc: remote did not understand our request");
      case RPC_MEM:
        printf("rpc: no remote memory");
      case RPC_OK:
        printf("rpc: ok");
        return rp;
    }
    cmd = perform_request(rp);
    free(rp);
    
    if ( !cmd.empty() )
    {
      int code = send_request(cmd);
      if ( code != 0 )
        return NULL;
      rpc_packet_t *rp = (rpc_packet_t *)cmd.c_str();
      if ( only_events && rp->code == RPC_EVOK )
        return NULL;
      if ( rp->code == RPC_ERROR )
        printf("Major Error!!!\n");
    }

//  }
}

static string perform_request(const rpc_packet_t *rp)
{
  const uchar *ptr = (const uchar *)(rp + 1);
  const uchar *end = ptr + rp->length;
  string cmd = prepare_rpc_packet(RPC_OK);
  debug_event_t ev;
  
  //DEBUG printf("IN -> %s\n", get_rpc_name(rp->code));
  
  switch ( rp->code )
  {
  
    case RPC_INIT:
      {
        bool debug_debugger = extract_long(&ptr, end);
       // if ( debug_debugger )
       //   verbose = true;
        int result = remote_init(debug_debugger);
        verb(("init(debug_debugger=%d) => %d\n", debug_debugger, result));
        append_long(cmd, result);
      }
      break;

    case RPC_TERM:
      //remote_term();
      DEBUG_RemoteCloseConnection();
      verb(("term()\n"));
      exitLoop = true;
      break;
/*
    case RPC_GET_PROCESS_INFO:
      {
        process_info_t info;
        int n = extract_long(&ptr, end);
        char *input = NULL;
        if ( n == 0 )
          input = extract_str(&ptr, end);
        bool result = remote_process_get_info(n, input, &info);
        append_long(cmd, result);
        if ( result )
          append_process_info(cmd, &info);
        verb(("get_process_info(n=%d) => %d\n", n, result));
      }
      break;

    case RPC_DETACH_PROCESS:
      {
        bool result = remote_detach_process();
        append_long(cmd, result);
        verb(("detach_process() => %d\n", result));
      }
      break;
*/
    case RPC_START_PROCESS:
      {
        char *path = extract_str(&ptr, end);
        char *args = extract_str(&ptr, end);
        char *sdir = extract_str(&ptr, end);
        int flags  = extract_long(&ptr, end);
        char *input= extract_str(&ptr, end);
        ulong crc32= extract_long(&ptr, end);
        int result = remote_start_process(); //remote_start_process(path, args, sdir, flags, input, crc32);
        verb(("start_process(path=%s args=%s flags=%d\n"
              "              sdir=%s\n"
              "              input=%s crc32=%x) => %d\n",
              path, args,
              flags,
              sdir,
              input, crc32,
              result));
        append_long(cmd, 1); //RPC_EVENT); //result);
        //append_debug_event(cmd, &r_debug.event);
      }
      break;

    case RPC_GET_DEBUG_EVENT:
      {
        bool ida_is_idle = extract_long(&ptr, end);
        static debug_event_t ev;
        int result = 1;
/*        
        if(r_debug.has_pending_event)
        {
          r_debug.has_pending_event = false;
          result = RPC_EVENT;
        }
        else
          r_debug.event.eid = NO_EVENT;
*/
        //? 0 : 1; // remote_get_debug_event(&ev, ida_is_idle);
        extract_debug_event(&ptr, end, &ev);
        
        //DEBUG printf("ida event eid = %s\n", get_event_id_name(ev.eid));

        if(r_debug.sent_event == true)
          result = 0;

        append_long(cmd, result);
/*        
        if ( result == RPC_EVENT )
        {
          append_debug_event(cmd, &r_debug.event);
//          verb(("got event: %s\n", debug_event_str(&ev)));
        }
*/
  //      else if ( !has_pending_event )
  //        poll_debug_events = true;

//        verb(("get_debug_event(ida_is_idle=%d) => %d (has_pending=%d, poll=%d)\n", ida_is_idle, result, has_pending_event, poll_debug_events));
//        verbev(("get_debug_event(ida_is_idle=%d) => %d (has_pending=%d, poll=%d)\n", ida_is_idle, result, has_pending_event, poll_debug_events));
      }
      break;
/*
    case RPC_ATTACH_PROCESS:
      {
        process_id_t pid = extract_long(&ptr, end);
        int event_id = extract_long(&ptr, end);
        bool result = remote_attach_process(pid, event_id);
        verb(("attach_process(pid=%u, evid=%d) => %d\n", pid, event_id, result));
        append_long(cmd, result);
      }
      break;
*/
    case RPC_PREPARE_TO_PAUSE_PROCESS:
      {
        bool result = 1; //remote_prepare_to_pause_process();
        verb(("prepare_to_pause_process() => %d\n", result));
        append_long(cmd, result);
      }
      break;

    case RPC_EXIT_PROCESS:
      {
        bool result = 1;//remote_exit_process();
        verb(("exit_process() => %d\n", result));

        ev.eid = PROCESS_EXIT;
        ev.exit_code = 0;
        remote_queue_event(ev);
        r_debug.has_pending_event = true;
        
        append_long(cmd, result);
      }
      break;

    case RPC_CONTINUE_AFTER_EVENT:
      {
        bool result = 1;
        debug_event_t ev;
        debug_event_t sent_ev;
        extract_debug_event(&ptr, end, &ev);

        if(r_debug.events.empty() == false)
        {
          
          sent_ev = r_debug.events.front();
          
          //skip breakpoints
          while(sent_ev.eid == BREAKPOINT && sent_ev.handled)
          {
            if(r_debug.events.size() == 1)
            {
              r_debug.events.pop_back();
              break;
            }
            else
            {
              for(int i = 1;i < r_debug.events.size();i++)
                r_debug.events[i-1] = r_debug.events[i];
              
              r_debug.events.pop_back();
              
              sent_ev = r_debug.events.front();
            }

          }
          
          if(sent_ev.handled && r_debug.events.empty() == false)
          {
            if(r_debug.events.size() == 1)
              r_debug.events.pop_back();
            else
            {
              for(int i = 1;i < r_debug.events.size();i++)
                r_debug.events[i-1] = r_debug.events[i];

              r_debug.events.pop_back();
            }
          
            switch(sent_ev.eid)
            {
              case PROCESS_START : result = DEBUG_Continue(); break;
              case STEP : result = 1; r_debug.ret = DEBUG_RemoteStep(); break;
              case BREAKPOINT : result = 1; break;
                //case NO_EVENT : result = 1; DEBUG_Continue(); break;
              case PROCESS_EXIT : result = 1; break; //DEBUG_ContinueWithoutDebug(); break;
              default : result = 1; break;
            }
          }
          else
            DEBUG_Continue();
        }
        else
          DEBUG_Continue();
        
        //DEBUG verb(("continue_after_event(...) => %d eid = %s handled = %d\n", result, get_event_id_name(ev.eid), ev.handled));
        append_long(cmd, result);
      }
      break;
/*
    case RPC_STOPPED_AT_DEBUG_EVENT:
      remote_stopped_at_debug_event();
      verb(("stopped_at_debug_event\n"));
      break;
*/
    case RPC_TH_SUSPEND:
      {
        thread_id_t tid = extract_long(&ptr, end);
        bool result = 1; //remote_thread_suspend(tid);
        verb(("thread_suspend(tid=%d) => %d\n", tid, result));
        append_long(cmd, result);
      }
      break;

    case RPC_TH_CONTINUE:
      {
        thread_id_t tid = extract_long(&ptr, end);
        bool result = DEBUG_Continue(); //remote_thread_continue(tid);
        verb(("thread_continue(tid=%08X) => %d\n", tid, result));
        append_long(cmd, result);
      }
      break;

    case RPC_TH_SET_STEP:
      {
        thread_id_t tid = extract_long(&ptr, end);
       // r_debug.ret = DEBUG_RemoteStep();
        bool result = 1; //remote_thread_set_step(tid);
        
        ev.eid = STEP;
        remote_queue_event(ev);
        r_debug.has_pending_event = true;
        
        verb(("thread_set_step(tid=%08X) => %d\n", tid, result));
        append_long(cmd, result);
      }
      break;

    case RPC_READ_REGS:
      {
        thread_id_t tid = extract_long(&ptr, end);
        int nregs = extract_long(&ptr, end);
        regval_t *values = new regval_t[nregs];
        if ( values == NULL ) goto nomem;
        bool result = remote_thread_read_registers(tid, values, nregs);
        verb(("thread_read_regs(tid=%08X) => %d\n", tid, result));
        append_long(cmd, result);
        append_regvals(cmd, values, nregs);
        delete values;
      }
      break;

    case RPC_WRITE_REG:
      {
        thread_id_t tid = extract_long(&ptr, end);
        int reg_idx = extract_long(&ptr, end);
        regval_t value;
        extract_regvals(&ptr, end, &value, 1);
        bool result = 1; //FIXME!!! remote_thread_write_register(tid, reg_idx, &value);
        verb(("thread_write_reg(tid=%08X) => %d\n", tid, result));
        append_long(cmd, result);
      }
      break;
/*
    case RPC_GET_SREG_BASE:
      {
        thread_id_t tid = extract_long(&ptr, end);
        int sreg_value = extract_long(&ptr, end);
        ea_t ea;
        bool result = remote_thread_get_sreg_base(tid, sreg_value, &ea);
        verb(("get_thread_sreg_base(tid=%u, %d) => %a\n", tid, sreg_value, result ? ea : BADADDR));
        append_long(cmd, result);
        if ( result )
          append_ea(cmd, ea);
      }
      break;
*/
    case RPC_SET_EXCEPTION_INFO:
      {
        int qty = extract_long(&ptr, end);
        //exception_info_t *extable = extract_exception_info(&ptr, end, qty);
        extract_exception_info(&ptr, end, qty);
        //remote_set_exception_info(extable, qty);
        verb(("set_exception_info(qty=%u)\n", qty));
      }
      break;

    case RPC_GET_MEMORY_INFO:
      {
        memory_info_t *areas = NULL;
        int qty;
        int result = remote_get_memory_info(&areas, &qty);
        verb(("get_memory_info() => %d (qty=%d)\n", result, qty));
        append_long(cmd, result);
        if ( result > 0 )
        {
          append_long(cmd, qty);
          for ( int i=0; i < qty; i++ )
            append_memory_info(cmd, &areas[i]);
          //if(areas)
          //  free(areas);
        }
      }
      break;

    case RPC_READ_MEMORY:
      {
        ea_t ea = extract_ea(&ptr, end);
        size_t size = extract_long(&ptr, end);
        uchar *buf = new uchar[size];
        //if ( buf == NULL ) goto nomem;
        ssize_t result = remote_read_memory(ea, buf, size);
        verb(("read_memory(ea=0x%08x size=%d) => %d", ea, size, result));
        if ( result && size == 1 )
          verb((" (0x%02X)\n", *buf));
        else
          verb(("\n"));
        append_long(cmd, (ulong)(result));
        append_memory(cmd, buf, size);
        delete buf;
      }
      break;
/*
    case RPC_WRITE_MEMORY:
      {
        ea_t ea = extract_ea(&ptr, end);
        size_t size = extract_long(&ptr, end);
        uchar *buf = new uchar[size];
        if ( buf == NULL ) goto nomem;
        extract_memory(&ptr, end, buf, size);
        ssize_t result = remote_write_memory(ea, buf, size);
        verb(("write_memory(ea=%a size=%d) => %d", ea, size, result));
        if ( result && size == 1 )
          verb((" (0x%02X)\n", *buf));
        else
          verb(("\n"));
        append_long(cmd, ulong(result));
        delete buf;
      }
      break;

    case RPC_ISOK_BPT:
      {
        bpttype_t type = extract_long(&ptr, end);
        ea_t ea        = extract_ea(&ptr, end);
        int len        = extract_long(&ptr, end);
        int result  = remote_is_ok_bpt(type, ea, len);
        verb(("isok_bpt(type=%d ea=%a len=%d) => %d\n", type, ea, len, result));
        append_long(cmd, result);
      }
      break;
*/
    case RPC_ADD_BPT:
      {
        bpttype_t type = extract_long(&ptr, end);
        ea_t ea        = extract_ea(&ptr, end);
        int len        = extract_long(&ptr, end);
        bool result = remote_add_bpt(type, ea, len);
        verb(("add_bpt(type=%d ea=%x len=%d) => %d\n", type, ea, len, result));
        append_long(cmd, result);
      }
      break;

    case RPC_DEL_BPT:
      {
        ea_t ea  = extract_ea(&ptr, end);
        int size = extract_long(&ptr, end);
        uchar *buf = NULL;
        if ( size != 0 )
        {
          buf = new uchar[size];
          if ( buf == NULL ) goto nomem;
          extract_memory(&ptr, end, buf, size);
        }
        bool result = 1; //remote_del_bpt(ea, buf, size);
        DEBUG_DelBreakPoint((PhysPt)ea);
        verb(("del_bpt(ea=%x) => %d\n", ea, result));
        append_long(cmd, result);
        delete buf;
      }
      break;
/*
    case RPC_OPEN_FILE:
      {
        char *file = extract_str(&ptr, end);
        bool readonly = extract_long(&ptr, end);
        ulong fsize = 0;
        int fn = find_free_channel();
        if ( fn != -1 )
        {
          channels[fn] = (readonly ? fopenRB : fopenWB)(file);
          if ( channels[fn] == NULL )
            fn = -1;
          else if ( readonly )
            fsize = efilelength(channels[fn]);
        }
        verb(("open_file('%s', %d) => %d %d\n", file, readonly, fn, fsize));
        append_long(cmd, fn);
        if ( fn != -1 )
          append_long(cmd, fsize);
        else
          append_long(cmd, qerrcode());
      }
      break;

    case RPC_CLOSE_FILE:
      {
        int fn = extract_long(&ptr, end);
        if ( fn >= 0 && fn < qnumber(channels) )
        {
          qfclose(channels[fn]);
          channels[fn] = NULL;
        }
        verb(("close_file(%d)\n", fn));
      }
      break;

    case RPC_READ_FILE:
      {
        char *buf = NULL;
        int fn    = extract_long(&ptr, end);
        long off  = extract_long(&ptr, end);
        long size = extract_long(&ptr, end);
        long s2 = size - 1;
        if ( size > 0 )
        {
          buf = new char[size];
          if ( buf == NULL )
            goto nomem;
          qfseek(channels[fn], off, SEEK_SET);
          s2 = qfread(channels[fn], buf, size);
        }
        append_long(cmd, size);
        if ( size != s2 )
          append_long(cmd, qerrcode());
        append_memory(cmd, buf, size);
        delete buf;
        verb(("read_file(%d, 0x%lX, %d) => %d\n", fn, off, size, s2));
      }
      break;

    case RPC_WRITE_FILE:
      {
        char *buf = NULL;
        int fn     = extract_long(&ptr, end);
        ulong off  = extract_long(&ptr, end);
        ulong size = extract_long(&ptr, end);
        if ( size > 0 )
        {
          buf = new char[size];
          if ( buf == NULL )
            goto nomem;
          extract_memory(&ptr, end, buf, size);
        }
        qfseek(channels[fn], off, SEEK_SET);
        ulong s2 = qfwrite(channels[fn], buf, size);
        append_long(cmd, size);
        if ( size != s2 )
          append_long(cmd, qerrcode());
        delete buf;
        verb(("write_file(%d, 0x%lX, %d) => %d\n", fn, off, size, s2));
      }
      break;

    case RPC_IOCTL:
      {
        char *buf = NULL;
        int fn = extract_long(&ptr, end);
        size_t size = extract_long(&ptr, end);
        if ( size > 0 )
        {
          buf = new char[size];
          if ( buf == NULL )
            goto nomem;
        }
        extract_memory(&ptr, end, buf, size);
        void *outbuf = NULL;
        ssize_t outsize = 0;
        int code = remote_ioctl(fn, buf, size, &outbuf, &outsize);
        append_long(cmd, code);
        append_long(cmd, outsize);
        if ( outsize > 0 )
          append_memory(cmd, outbuf, outsize);
        qfree(outbuf);
        verb(("ioctl(%d) => %d\n", fn, code));
      }
      break;
*/
    case RPC_EVOK:
      //has_pending_event = false;
      cmd = "";
      //verbev(("got evok, clearing has_pending_event\n"));
      printf("Got response to event! Yay!\n");
      r_debug.sent_event = false;
      break;

    default:
      printf("UNHANDLED COMMAND!!!!!!!!!!!!!!!!!!!!!!\n\n\n\n\n\n\n");
      return prepare_rpc_packet(RPC_UNK);
    nomem:
      return prepare_rpc_packet(RPC_MEM);
  }
  return cmd;
}

///////////////////////////////////////////////////////////////////////////

//ERIC REMOTE DEBUG
static void DEBUG_RemoteInit(void)
{
    int flags;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(2139);

#ifdef WIN32
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD( 2, 0 );

  err = WSAStartup( wVersionRequested, &wsaData );
  if ( err != 0 ) return;
#endif

    r_debug.listen_socket = socket(AF_INET, SOCK_STREAM, 0);

	 if(r_debug.listen_socket == INVALID_SOCKET)
	 {
		printf("ERROR (%d) creating socket!\n", errno);
		return;
	 }
	 
#ifdef WIN32
    flags = 1;
    ioctlsocket(r_debug.listen_socket, FIONBIO, (u_long *)&flags);
#else
    flags = fcntl(r_debug.listen_socket, F_GETFL, 0);
    fcntl(r_debug.listen_socket, F_SETFL, flags|O_NONBLOCK);
#endif

    bind(r_debug.listen_socket, (sockaddr *)&sa, sizeof(sa));
    listen(r_debug.listen_socket, 1);
    
    r_debug.connected = false;
    
    r_debug.password = (char *)malloc(5); /* 'test\0' */
    strcpy(r_debug.password, "test");
    DEBUG_ShowMsg("DEBUGGER: Binding socket to port 2139\n");

    r_debug.has_pending_event = false;
    r_debug.poll_debug_events = false;
    r_debug.sent_event = false;
    r_debug.miv = NULL;
}

static void  DEBUG_RemoteCloseConnection(void)
{
 if(r_debug.connected)
 {
#ifdef WIN32
   closesocket(r_debug.socket);
#else
   close(r_debug.socket);
#endif
   r_debug.connected = false;
 }
 
}

static void DEBUG_RemoteClose()
{
    DEBUG_RemoteCloseConnection();

    close(r_debug.listen_socket);
    DEBUG_ShowMsg("DEBUGGER: Closing port 2139\n");

    if(r_debug.miv)
    {
      free(r_debug.miv);
      r_debug.miv = NULL;
    }

#ifdef WIN32
	 WSACleanup();
#endif

    return;
}

Bits DEBUG_RemoteHandleCMD()
{ 
    if(!r_debug.connected)
    {
        if(DEBUG_RemoteNewConnection() == false)
            return 0;
    }
    
    string cmd;

    r_debug.ret = 0;
    process_request(cmd, false);
    
    return r_debug.ret;
}

bool DEBUG_RemoteNewConnection()
{
    struct hostent *host;
    sockaddr_in sa;
    int s;
#ifdef WIN32
	 int salen = sizeof(sa);
#else
    socklen_t salen = sizeof(sa);
#endif
	 s = accept(r_debug.listen_socket, (sockaddr *)&sa, &salen);
    
    if(s == -1)
	 {
      return false;
	 }

    r_debug.connected = true;
    r_debug.socket = s;
    
    DEBUG_ShowMsg("DEBUGGER: Accepted remote connection\n");

//    irs = (idarpc_stream_t *)r_debug.socket;

  string open = prepare_rpc_packet(RPC_OPEN);

  printf("open data = ");
  const char *ptr = open.c_str();
for(int i = 0;i<open.length();i++)
  printf("%d,",ptr[i]);
printf("\n");

  append_long(open, 9); //IDD_INTERFACE_VERSION);
  append_long(open, 0); //DEBUGGER_ID); DEBUGGER_ID_X86_IA32_WIN32_USER
  append_long(open, 4); //32bit //sizeof(ea_t));
  rpc_packet_t *rp = process_request(open, true);
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;
  printf("pass length=%d\n",rp->length);
  bool send_response = true;
  bool ok = extract_long(&answer, end);
  if ( !ok )
  {
    printf("Incompatible IDA Pro version\n");
    send_response = false;
  }
  else if ( r_debug.password != NULL )
  {
    char *pass = extract_str(&answer, end);
    printf("remote password = '%s'\n", pass);
    printf("local password = '%s'\n", r_debug.password);
    
    printf("password cmp = %d\n", strcmp(pass, r_debug.password));
    
    if ( strcmp(pass, r_debug.password) != 0 )
    {
      printf("Bad password\n");
      ok = false;
    }
  }
  free(rp);

  open = prepare_rpc_packet(RPC_OK);
  append_long(open, true); //ok);
  send_request(open);
      
    return true;
}

bool DEBUG_RemoteDataReady(void)
{
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

 return false;
}

void DEBUG_RemoteBreakpoint(PhysPt addr)
{
  debug_event_t ev;
  
 if(r_debug.connected)
 {
   ev.eid = BREAKPOINT;
   ev.bpt.hea = addr; //BADADDR; //r_debug.base - addr; //BADADDR; //addr;//r_debug.base - addr;
   ev.bpt.kea = BADADDR;
   ev.ea = addr;
   printf("Hit Breakpoint address: %x\n", addr);
   remote_queue_event(ev);
   r_debug.has_pending_event = true;
  }
}
 
const char *get_rpc_name(int code)
{
  switch ( code )
  {
    case RPC_OK                      : return "RPC_OK";
    case RPC_UNK                     : return "RPC_UNK";
    case RPC_MEM                     : return "RPC_MEM";
    case RPC_OPEN                    : return "RPC_OPEN";
    case RPC_EVENT                   : return "RPC_EVENT";
    case RPC_EVOK                    : return "RPC_EVOK";
    case RPC_INIT                    : return "RPC_INIT";
    case RPC_TERM                    : return "RPC_TERM";
    case RPC_GET_PROCESS_INFO        : return "RPC_GET_PROCESS_INFO";
    case RPC_DETACH_PROCESS          : return "RPC_DETACH_PROCESS";
    case RPC_START_PROCESS           : return "RPC_START_PROCESS";
    case RPC_GET_DEBUG_EVENT         : return "RPC_GET_DEBUG_EVENT";
    case RPC_ATTACH_PROCESS          : return "RPC_ATTACH_PROCESS";
    case RPC_PREPARE_TO_PAUSE_PROCESS: return "RPC_PREPARE_TO_PAUSE_PROCESS";
    case RPC_EXIT_PROCESS            : return "RPC_EXIT_PROCESS";
    case RPC_CONTINUE_AFTER_EVENT    : return "RPC_CONTINUE_AFTER_EVENT";
    case RPC_STOPPED_AT_DEBUG_EVENT  : return "RPC_STOPPED_AT_DEBUG_EVENT";
    case RPC_TH_SUSPEND              : return "RPC_TH_SUSPEND";
    case RPC_TH_CONTINUE             : return "RPC_TH_CONTINUE";
    case RPC_TH_SET_STEP             : return "RPC_TH_SET_STEP";
    case RPC_READ_REGS               : return "RPC_READ_REGS";
    case RPC_WRITE_REG               : return "RPC_WRITE_REG";
    case RPC_GET_MEMORY_INFO         : return "RPC_GET_MEMORY_INFO";
    case RPC_READ_MEMORY             : return "RPC_READ_MEMORY";
    case RPC_WRITE_MEMORY            : return "RPC_WRITE_MEMORY";
    case RPC_ISOK_BPT                : return "RPC_ISOK_BPT";
    case RPC_ADD_BPT                 : return "RPC_ADD_BPT";
    case RPC_DEL_BPT                 : return "RPC_DEL_BPT";
    case RPC_GET_SREG_BASE           : return "RPC_GET_SREG_BASE";
    case RPC_SET_EXCEPTION_INFO      : return "RPC_SET_EXCEPTION_INFO";
    case RPC_OPEN_FILE               : return "RPC_OPEN_FILE";
    case RPC_CLOSE_FILE              : return "RPC_CLOSE_FILE";
    case RPC_READ_FILE               : return "RPC_READ_FILE";
    case RPC_WRITE_FILE              : return "RPC_WRITE_FILE";
    case RPC_IOCTL                   : return "RPC_IOCTL";
    case RPC_SET_DEBUG_NAMES         : return "RPC_SET_DEBUG_NAMES";
    case RPC_SYNC_STUB               : return "RPC_SYNC_STUB";
    case RPC_ERROR                   : return "RPC_ERROR";
    case RPC_MSG                     : return "RPC_MSG";
    case RPC_WARNING                 : return "RPC_WARNING";
  }
  return "?";
}

const char *get_event_id_name(event_id_t code)
{
  switch ( code )
  {
    case NO_EVENT       : return "NO_EVENT";
    case PROCESS_START  : return "PROCESS_START";
    case PROCESS_EXIT   : return "PROCESS_EXIT";
    case THREAD_START   : return "THREAD_START";
    case THREAD_EXIT    : return "THREAD_EXIT";
    case BREAKPOINT     : return "BREAKPOINT";
    case STEP           : return "STEP";
    case EXCEPTION      : return "EXCEPTION";
    case LIBRARY_LOAD   : return "LIBRARY_LOAD";
    case LIBRARY_UNLOAD : return "LIBRARY_UNLOAD";
    case INFORMATION    : return "INFORMATION";

    case SYSCALL        : return "SYSCALL";
    case WINMESSAGE     : return "WINMESSAGE";
    case PROCESS_ATTACH : return "PROCESS_ATTACH";
    case PROCESS_DETACH : return "PROCESS_DETACH";
  }
  
 return "?";
}

int remote_init(bool debug_debugger)
{
  r_debug.base = GetAddress(SegValue(cs),0); // reg_eip);
  printf("CS:IP = %x\n", GetAddress(SegValue(cs), (ulong)reg_eip));
  return RPC_OK;
}

//queue an event to send to the client.
void remote_queue_event(debug_event_t ev)
{
  ev.pid = 1;
  ev.tid = 1;
  ev.handled = false;
  //r_debug.event.ea = GetAddress(SegValue(cs), (ulong)reg_eip);
  //r_debug.event.ea--;

  r_debug.events.push_back(ev);
  
  return;
}

int remote_start_process(void)
{
  debug_event_t ev;
  string filename = "";
  

  filename = DEBUG_GetFileName();
  
  ev.eid = PROCESS_START;
  ev.ea = BADADDR; // r_debug.base; //GetAddress(0xf7,0); NOTE this gets overwritten at the moment.

  if(filename != "")
    strcpy(ev.modinfo.name, filename.c_str());
  else
    strcpy(ev.modinfo.name,"BINEXE.EXE");

  ev.modinfo.base = BADADDR; //r_debug.base;//GetAddress(0xf7,0);
  ev.modinfo.size = 0;//GetAddress(SegValue(ss),reg_esp) - r_debug.base; //0; //0xa000*0x10 - r_debug.base;
    ev.modinfo.rebase_to = BADADDR; //GetAddress(SegValue(cs),reg_eip); //r_debug.base;//r_debug.event.modinfo.base; //r_debug.event.ea;
  
  printf("remote name = %s, base = %08x, size = %08x, rebase_to = %08x BADADDR = %08x\n", ev.modinfo.name, ev.modinfo.base, ev.modinfo.size, ev.modinfo.rebase_to, BADADDR);
  remote_queue_event(ev);
  r_debug.has_pending_event = true;

  return RPC_OK;
}

int remote_get_memory_info(memory_info_t **areas, int *qty)
{
 memory_info_t *miv;
 
 *qty = 4;
 
 //return 1;
 if(r_debug.miv == NULL)
 {
   r_debug.miv = (memory_info_t *)malloc(sizeof(memory_info_t) * *qty);
   miv = r_debug.miv;
 
   miv->startEA = 0x0; //0;//r_debug.base; //(ea_t)GetAddress(0,0);
   miv->endEA = (ea_t)GetAddress(SegValue(ds),0); // 0x1970;
   miv->endEA--;
   strcpy(miv->name, "ROM");
   miv->sclass[0] = '\0'; 
   miv->perm = 0 | SEGPERM_READ;
   miv++;
 
   miv->startEA = (ea_t)GetAddress(SegValue(ds),0); // 0x1970;
   miv->endEA = (ea_t)GetAddress(SegValue(cs),0); // 0x1a70; //(ea_t)GetAddress(SegValue(ds),0);
   miv->endEA--;
   strcpy(miv->name, "PSP");
   miv->sclass[0] = '\0'; 
   miv->perm = 0 | SEGPERM_READ;
   miv++;

   miv->startEA = (ea_t)GetAddress(SegValue(cs),0); //0x1a70; //(ea_t)GetAddress(SegValue(ds), 0); //GetAddress(0xa000,0);
   miv->endEA = (ea_t)GetAddress(SegValue(ss), 0); // 0x1c20; //GetAddress(0xf000,0) - 1;
   miv->endEA--;
   strcpy(miv->name, ".text");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
   miv++;

   miv->startEA = (ea_t)GetAddress(SegValue(ss),0); //0x1a70; //(ea_t)GetAddress(SegValue(ds), 0); //GetAddress(0xa000,0);
   miv->endEA = (ea_t)GetAddress(SegValue(ss), 0xffff); //reg_sp); // 0x1c20; //GetAddress(0xf000,0) - 1;
   miv->endEA--;
   strcpy(miv->name, ".stack");
   miv->sclass[0] = '\0';
   miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
   miv++;
 }
 
/* 
 miv->startEA = (ea_t)GetAddress(SegValue(ss), 0); //GetAddress(0xf000,0);
 miv->endEA = (ea_t)GetAddress(SegValue(ss), reg_esp);//GetAddress(0x10000,0) - 1;
 strcpy(miv->name, ".stack");
 miv->sclass[0] = '\0';
 miv->perm = 0 | SEGPERM_READ | SEGPERM_WRITE;
 miv++;
*/

 *areas = r_debug.miv;

 return 1;
}

ssize_t remote_read_memory(ea_t ea, uchar *buf, size_t size)
{
 int i;
 PhysPt addr = (PhysPt)ea;
 uchar tmp;
 
 //addr = addr + r_debug.base;
 
 for(i=0;i<size;i++)
  {
   buf[i] = mem_readb(addr);
   // printf("%02x,",buf[i]);
   addr++;
  }

 return size;
}

//FIXME there might be problems with reg struct packing!
bool remote_thread_read_registers(thread_id_t tid, regval_t *values, int nregs)
{
  memset(values, 0, nregs * sizeof(regval_t)); // force null bytes at the end of floating point registers.
                                               // we need this to properly detect register modifications,
                                               // as we compare the whole regval_t structure !

  values[R_EAX   ].ival = (ulong)reg_eax;
  values[R_EBX   ].ival = (ulong)reg_ebx;
  values[R_ECX   ].ival = (ulong)reg_ecx;
  values[R_EDX   ].ival = GetAddress(SegValue(ds), (ulong)reg_edx);//(ulong)reg_edx;
  values[R_ESI   ].ival = (ulong)reg_esi;
  values[R_EDI   ].ival = (ulong)reg_edi;
  values[R_EBP   ].ival = (ulong)reg_ebp;
  values[R_ESP   ].ival = GetAddress(SegValue(ss), (ulong)reg_esp);//(ulong)reg_esp;
  values[R_EIP   ].ival = GetAddress(SegValue(cs), (ulong)reg_eip);//(ulong)reg_eip;
  values[R_EFLAGS].ival = (ulong)reg_flags;
  values[R_CS    ].ival = (ulong)SegValue(cs);
  values[R_DS    ].ival = (ulong)SegValue(ds);
  values[R_ES    ].ival = (ulong)SegValue(es);
  values[R_FS    ].ival = (ulong)SegValue(fs);
  values[R_GS    ].ival = (ulong)SegValue(gs);
  values[R_SS    ].ival = (ulong)SegValue(ss);
  
  printf("AX = %08x",(ulong)values[R_EAX   ].ival);
  printf(" BX = %08x",(ulong)values[R_EBX   ].ival);
  printf(" CX = %08x",(ulong)values[R_ECX   ].ival);
  printf(" DX = %08x\n",(ulong)values[R_EDX   ].ival);
  printf("SI = %08x",(ulong)values[R_ESI   ].ival);
  printf(" DI = %08x",(ulong)values[R_EDI   ].ival);
  printf(" BP = %08x",(ulong)values[R_EBP   ].ival);
  printf(" SP = %08x\n",(ulong)values[R_ESP   ].ival);
  printf("IP = %08x",(ulong)values[R_EIP   ].ival);
  printf(" Flags = %08x\n",(ulong)values[R_EFLAGS].ival);
  printf("CS = %08x",(ulong)values[R_CS    ].ival);
  printf(" SS = %08x",(ulong)values[R_SS    ].ival);
  printf(" DS = %08x",(ulong)values[R_DS    ].ival);
  printf(" ES = %08x\n",(ulong)values[R_ES    ].ival);
  printf("FS = %08x",(ulong)values[R_FS    ].ival);
  printf(" GS = %08x\n",(ulong)values[R_GS    ].ival);


/*
  struct user_fpregs_struct i387;
  if ( qptrace(PTRACE_GETFPREGS, process_handle, 0, &i387) != 0 )
    return false;

  for (int i = 0; i < FPU_REGS_COUNT; i++)
  {
    uchar *fpu_float = (uchar *)i387.st_space;
    fpu_float += i * 10;
    *(long double *)values[R_ST0+i].fval = *(long double *)fpu_float;
  }
  values[R_CTRL].ival = ulong(i387.cwd);
  values[R_STAT].ival = ulong(i387.swd);
  values[R_TAGS].ival = ulong(i387.twd);
*/
 return true;
}


bool remote_add_bpt(bpttype_t type, ea_t ea, int len)
{
 printf("new breakpoint at base, offset %x, %x.\n", r_debug.base, ea);
 
 //ea += r_debug.base;
 switch(type)
 {
   case BPT_EXEC :
   case BPT_SOFT : DEBUG_AddBreakPoint((Bit32u)ea, false); break;
   case BPT_WRITE : DEBUG_AddMemBreakPoint((Bit32u)ea); break;
 }
 
 return 1;
}

