// bidirectional codes (client <-> server)
#define RPC_OK    0      // response: function call succeeded
#define RPC_UNK   1      // response: unknown function code
#define RPC_MEM   2      // response: no memory

#define RPC_OPEN  3      // server->client: i'm ready, the very first packet

#define RPC_EVENT 4      // server->client: debug event ready, followed by debug_event
#define RPC_EVOK  5      // client->server: event processed (in response to RPC_EVENT)
                         // we need EVOK to handle the situation when the debug
                         // event was detected by the server during polling and
                         // was sent to the client using RPC_EVENT but client has not received it yet
                         // and requested GET_DEBUG_EVENT. In this case we should not
                         // call remote_get_debug_event() but instead force the client
                         // to use the event sent by RPC_EVENT.
                         // In other words, if the server has sent RPC_EVENT but has not
                         // received RPC_EVOK, it should fail all GET_DEBUG_EVENTS.

// codes client->server
#define RPC_INIT                      10
#define RPC_TERM                      11
#define RPC_GET_PROCESS_INFO          12
#define RPC_DETACH_PROCESS            13
#define RPC_START_PROCESS             14
#define RPC_GET_DEBUG_EVENT           15
#define RPC_ATTACH_PROCESS            16
#define RPC_PREPARE_TO_PAUSE_PROCESS  17
#define RPC_EXIT_PROCESS              18
#define RPC_CONTINUE_AFTER_EVENT      19
#define RPC_STOPPED_AT_DEBUG_EVENT    20
#define RPC_TH_SUSPEND                21
#define RPC_TH_CONTINUE               22
#define RPC_TH_SET_STEP               23
#define RPC_READ_REGS                 24
#define RPC_GET_MEMORY_INFO           25
#define RPC_READ_MEMORY               26
#define RPC_WRITE_MEMORY              27
#define RPC_ISOK_BPT                  28
#define RPC_ADD_BPT                   29
#define RPC_DEL_BPT                   30
#define RPC_WRITE_REG                 31
#define RPC_GET_SREG_BASE             32
#define RPC_SET_EXCEPTION_INFO        33

#define RPC_OPEN_FILE                 34
#define RPC_CLOSE_FILE                35
#define RPC_READ_FILE                 36
#define RPC_WRITE_FILE                38

#define RPC_IOCTL                     39

// codes server->client
#define RPC_SET_DEBUG_NAMES           50
#define RPC_SYNC_STUB                 51
#define RPC_ERROR                     52
#define RPC_MSG                       53
#define RPC_WARNING                   54

#if C_IDA_64BIT
#define ulong Uint64
#else
#define ulong Uint32
#endif

#define uchar unsigned char
#define ulonglong unsigned long long

#pragma pack(push, 1) //we need to pack the struct

#define MAXSTR 1024

#define SEGPERM_EXEC  1
#define SEGPERM_WRITE 2
#define SEGPERM_READ  4

enum event_id_t
{
  NO_EVENT       = 0x00000000, // Not an interesting event
  PROCESS_START  = 0x00000001, // New process started
  PROCESS_EXIT   = 0x00000002, // Process stopped
  THREAD_START   = 0x00000004, // New thread started
  THREAD_EXIT    = 0x00000008, // Thread stopped
  BREAKPOINT     = 0x00000010, // Breakpoint reached
  STEP           = 0x00000020, // One instruction executed
  EXCEPTION      = 0x00000040, // Exception
  LIBRARY_LOAD   = 0x00000080, // New library loaded
  LIBRARY_UNLOAD = 0x00000100, // Library unloaded
  INFORMATION    = 0x00000200, // User-defined information
                               // This event can be used to return empty information
                               // This will cause IDA to call get_debug_event()
                               // immediately once more
  SYSCALL        = 0x00000400, // Syscall (not used yet)
  WINMESSAGE     = 0x00000800, // Window message (not used yet)
  PROCESS_ATTACH = 0x00001000, // Attached to running process
  PROCESS_DETACH = 0x00002000, // Detached from process
/*
  SIGNAL,
  DEBUG_STRING
  ...
*/
};
/*
enum register_x86_t
{
  // FPU registers
  R_ST0,
  R_ST1,
  R_ST2,
  R_ST3,
  R_ST4,
  R_ST5,
  R_ST6,
  R_ST7,
  R_CTRL,
  R_STAT,
  R_TAGS,
  // segment registers
  R_CS,
  R_DS,
  R_ES,
  R_FS,
  R_GS,
  R_SS,
  // general registers
  R_EAX,
  R_EBX,
  R_ECX,
  R_EDX,
  R_ESI,
  R_EDI,
  R_EBP,
  R_ESP,
  R_EIP,
#ifdef __EA64__
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_R13,
  R_R14,
  R_R15,
#endif
  R_EFLAGS,
};
*/

  // FPU registers
#define   R_ST0 0
#define  R_ST1  1
#define  R_ST2  2
#define  R_ST3  3
#define  R_ST4  4
#define  R_ST5  5
#define  R_ST6  6
#define  R_ST7  7
#define  R_CTRL 8
#define  R_STAT 9
#define  R_TAGS 10
  // segment registers
#define  R_CS 11
#define  R_DS 12
#define  R_ES 13
#define  R_FS 14
#define  R_GS 15
#define  R_SS 16
  // general registers
#define  R_EAX 17
#define  R_EBX 18
#define  R_ECX 19
#define  R_EDX 20
#define  R_ESI 21
#define  R_EDI 22
#define  R_EBP 23
#define  R_ESP 24
#define  R_EIP 25
#define  R_EFLAGS 26
  
typedef int process_id_t;
typedef int thread_id_t;
typedef ulong ea_t;       // effective address
typedef ulong asize_t;    // memory chunk size

#define BADADDR ea_t(-1)

struct module_info_t
{
  char name[MAXSTR];    // full name of the module.
  ea_t base;            // module base address. if unknown pass BADADDR
  asize_t size;         // module size. if unknown pass 0
  ea_t rebase_to;       // if not BADADDR, then rebase the program to the specified address
};

struct e_breakpoint_t
{
  ea_t hea;             // Possible address referenced by hardware breakpoints
  ea_t kea;             // Address of the triggered bpt from the kernel's point
                        // of view (for some systems with special memory mappings,
                        // the triggered ea might be different from event ea).
                        // Use to BADADDR for flat memory model.
};

struct e_exception_t
{
  int code;          // Exception code
  bool can_cont;     // Execution of the process can continue after this exception?
  ea_t ea;           // Possible address referenced by the exception
  char info[MAXSTR]; // Exception message
};

// This structure is used only when detailed information
//   on a debug event is needed.
struct debug_event_t
{
  debug_event_t(void) : eid(NO_EVENT) {}
  event_id_t   eid;        // Event code (used to decipher 'info' union)
  process_id_t pid;        // Process where the event occured
  thread_id_t  tid;        // Thread where the event occured
  ea_t ea;                 // Address where the event occured
  bool handled;            // Is event handled by the debugger?
                           // (from the system's point of view)
  union
  {
    module_info_t modinfo;         // PROCESS_START, PROCESS_ATTACH, LIBRARY_LOAD
    int exit_code;                 // PROCESS_EXIT, THREAD_EXIT
    char info[MAXSTR];             // LIBRARY_UNLOAD (unloaded library name)
                                   // INFORMATION (will be displayed in the
                                   //              messages window if not empty)
    e_breakpoint_t bpt;            // BREAKPOINT
    e_exception_t exc;             // EXCEPTION
  };
};

struct area_t
{
  ea_t startEA;
  ea_t endEA;                  // endEA excluded
  area_t(void) {}
  area_t(ea_t ea1, ea_t ea2)  { startEA = ea1; endEA = ea2; }
  int compare(const area_t &r) const { return startEA > r.startEA ? 1 : startEA < r.startEA ? -1 : 0; }
  bool operator ==(const area_t &r) const { return compare(r) == 0; }
  bool operator !=(const area_t &r) const { return compare(r) != 0; }
  bool operator > (const area_t &r) const { return compare(r) >  0; }
  bool operator < (const area_t &r) const { return compare(r) <  0; }
  bool contains(ea_t ea) const { return startEA <= ea && endEA > ea; }
  bool contains(const area_t &r) const { return r.startEA >= startEA && r.endEA <= endEA; }
  bool empty(void) const { return startEA >= endEA; }
  asize_t size(void) const { return endEA - startEA; }
  void intersect(const area_t &r)
  {
    if ( startEA < r.startEA ) startEA = r.startEA;
    if ( endEA   > r.endEA   ) endEA   = r.endEA;
    if ( endEA   < startEA   ) endEA   = startEA;
  }
};

struct memory_info_t : public area_t
{
  memory_info_t(void) : perm(0) { name[0] = '\0'; sclass[0] = '\0'; }
  uchar perm;                  // Memory area permissions (0-no information): see segment.hpp
  char name[64];               // Memory area name (null string => kernel will give an appropriate name)
  char sclass[64];             // Memory area class name (null string => kernel will give an appropriate name)
};

#pragma pack(push, 4)

// register value
struct regval_t
{
  ulonglong ival;     // 8:  integer value
  ushort    fval[6];  // 12: floating point value in the internal representation (see ieee.h)
  regval_t(void) : ival(~(ulonglong)(0)) {}
};

#pragma pack(push, 1)

// Hardware breakpoint types
typedef int bpttype_t;
const bpttype_t
  BPT_EXEC  =  0,             // Execute instruction
  BPT_WRITE =  1,             // Write access
  BPT_RDWR  =  3,             // Read/write access
  BPT_SOFT  =  4;             // Software breakpoint

struct rpc_packet_t      // fields are always sent in the network order
{
  ulong length;          // length of the packet (do not count length & code)
  uchar code;            // function code
};

static void DEBUG_RemoteInit(void);
static void DEBUG_RemoteCloseConnection(void);
static void DEBUG_RemoteClose(void);
Bits DEBUG_RemoteHandleCMD(void);
bool DEBUG_RemoteNewConnection(void);
bool DEBUG_RemoteDataReady(void);
void DEBUG_RemoteBreakpoint(PhysPt addr);

const char *get_rpc_name(int code);
const char *get_event_id_name(event_id_t code);

void remote_queue_event(debug_event_t ev);

int remote_init(bool debug_debugger);
int remote_start_process(void);
int remote_get_memory_info(memory_info_t **areas, int *qty);
ssize_t remote_read_memory(ea_t ea, uchar *buf, size_t size);
bool remote_thread_read_registers(thread_id_t tid, regval_t *values, int nregs);
bool remote_add_bpt(bpttype_t type, ea_t ea, int len);
