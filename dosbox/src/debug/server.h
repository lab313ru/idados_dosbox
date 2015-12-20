/*
       IDA Pro remote debugger server
*/

#include <fpro.h>
#include <expr.hpp>
#include <signal.h>

#include <map>
#include <algorithm>

#define __SINGLE_THREADED_SERVER__
#define DEBUGGER_ID DEBUGGER_ID_X86_DOSBOX_EMULATOR


#ifdef __X64__
#define SYSBITS " 64-bit"
#else
#define SYSBITS " 32-bit"
#endif

#include "tcpip.h"

#ifdef __SINGLE_THREADED_SERVER__
#  define __SERVER_TYPE__ "ST"
#else
#  define __SERVER_TYPE__ "MT"
#endif

#include "debmod.h"
#include "rpc_hlp.h"
#include "rpc_server.h"

// sizeof(ea_t)==8 and sizeof(size_t)==4 servers can not be used to debug 64-bit
// applications. but to debug 32-bit applications, simple 32-bit servers
// are enough and can work with both 32-bit and 64-bit versions of ida.
// so, there is no need to build sizeof(ea_t)==8 and sizeof(size_t)==4 servers
#if defined(__EA64__) != defined(__X64__)
#error "Mixed mode servers do not make sense, they should not be compiled"
#endif

extern rpc_server_list_t clients_list;
