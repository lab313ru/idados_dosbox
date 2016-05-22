//
// This file is included from other files, do not directly compile it.
// It contains the debugger_t structure definition and a few other helper functions
//

#include <loader.hpp>
#include <srarea.hpp>
#include "consts.h"

bool plugin_inited;
bool debugger_inited;

#if TARGET_PROCESSOR == PLFM_386
  #define REGISTERS                x86_registers
  #define REGISTERS_SIZE           qnumber(x86_registers)
  #define REGISTER_CLASSES         x86_register_classes
  #define REGISTER_CLASSES_DEFAULT X86_RC_GENERAL
  #define READ_REGISTERS           x86_read_registers
  #define WRITE_REGISTER           x86_write_register
  #if DEBUGGER_ID != DEBUGGER_ID_GDB_USER
    #define is_valid_bpt           is_x86_valid_bpt
  #endif
  #define BPT_CODE                 X86_BPT_CODE
  #define BPT_CODE_SIZE            X86_BPT_SIZE
#elif TARGET_PROCESSOR == PLFM_ARM
  #define REGISTERS                arm_registers
  #define REGISTERS_SIZE           qnumber(arm_registers)
  #define REGISTER_CLASSES         arm_register_classes
  #define REGISTER_CLASSES_DEFAULT ARM_RC_GENERAL
  #define READ_REGISTERS           arm_read_registers
  #define WRITE_REGISTER           arm_write_register
  #if DEBUGGER_ID != DEBUGGER_ID_GDB_USER
    #define is_valid_bpt           is_arm_valid_bpt
  #endif
  #define BPT_CODE                 ARM_BPT_CODE
  #define BPT_CODE_SIZE            ARM_BPT_SIZE
#elif TARGET_PROCESSOR == PLFM_DALVIK
  #define BPT_CODE                 { 0 }
  #define BPT_CODE_SIZE            0
  #define READ_REGISTERS           s_read_registers
  #define WRITE_REGISTER           s_write_register
  #define is_valid_bpt             is_dalvik_valid_bpt
#else
  #error This processor is not supported yet
#endif

static const uchar bpt_code[] = BPT_CODE;

//--------------------------------------------------------------------------
int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  int ret = is_valid_bpt(type, ea, len);
  if ( ret != BPT_OK )
    return ret;
  else
    return s_is_ok_bpt(type, ea, len);
}

//--------------------------------------------------------------------------
// For ARM, we have to set the low bit of the address to 1 for thumb mode
#if DEBUGGER_ID == DEBUGGER_ID_ARM_LINUX_USER
static int idaapi arm_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
  // This function is called from debthread, but to use get_segreg() we must
  // switch to the mainthread
  struct ida_local arm_bptea_fixer_t : public exec_request_t
  {
    update_bpt_info_t *bpts;
    update_bpt_info_t *e;
    qvector<ea_t *> thumb_mode;
    virtual int idaapi execute(void)
    {
      for ( update_bpt_info_t *b=bpts; b != e; b++ )
      {
        if ( b->type == BPT_SOFT && get_segreg(b->ea, ARM_T) == 1 )
        {
          b->ea++; // odd address means that thumb bpt must be set
          thumb_mode.push_back(&b->ea);
        }
      }
      return 0;
    }
    arm_bptea_fixer_t(update_bpt_info_t *p1, update_bpt_info_t *p2)
      : bpts(p1), e(p2) {}
  };
  arm_bptea_fixer_t abf(bpts, bpts+nadd);
  execute_sync(abf, MFF_READ);

  int ret = s_update_bpts(bpts, nadd, ndel);

  // reset the odd bit because the addresses are required by the caller
  for ( int i=0; i < abf.thumb_mode.size(); i++ )
    (*abf.thumb_mode[i])--;

  return ret;
}
#define s_update_bpts arm_update_bpts
#endif

//--------------------------------------------------------------------------
static int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
  bool valid_bpt_exists = false;
  update_bpt_info_t *e = bpts + nadd;
  for ( update_bpt_info_t *b=bpts; b != e; b++ )
  {
    if ( b->code == BPT_SKIP )
      continue;

    b->code = is_valid_bpt(b->type, b->ea, b->size);
    if ( b->code == BPT_OK )
      valid_bpt_exists = true;
  }

  if ( !valid_bpt_exists && ndel == 0 )
    return 0; // none of bpts is writable

  int ret = s_update_bpts(bpts, nadd, ndel);
  return ret;
}

//--------------------------------------------------------------------------
static void idaapi stopped_at_debug_event(bool dlls_added)
{
  if ( dlls_added )
    s_stopped_at_debug_event();
}

//--------------------------------------------------------------------------
#ifndef REMOTE_DEBUGGER
// another copy of this function (for remote debugging) is defined in rpc_server.cpp
int send_ioctl(
  void *,
  int fn,
  const void *buf,
  size_t size,
  void **poutbuf,
  ssize_t *poutsize)
{
  return g_dbgmod.handle_ioctl(fn, buf, size, poutbuf, poutsize);
}
#endif

//--------------------------------------------------------------------------
THREAD_SAFE int debmod_t::send_debug_names_to_ida(
      ea_t *addrs,
      const char *const *names,
      int qty)
{
  return ::send_debug_names_to_ida(addrs, names, qty);
}

//---------------------------------------------------------------------------
THREAD_SAFE int send_debug_names_to_ida(
      ea_t *addrs,
      const char *const *names,
      int qty)
{
  struct debug_name_handler_t : public exec_request_t
  {
    ea_t *addrs;
    const char *const *names;
    int qty;
    debug_name_handler_t(ea_t *_addrs, const char *const *_names, int _qty)
      : addrs(_addrs), names(_names), qty(_qty) {}
    int idaapi execute(void)
    {
      set_arm_thumb_modes(addrs, qty);
      return set_debug_names(addrs, names, qty);
    }
  };
  debug_name_handler_t dnh(addrs, names, qty);
  return execute_sync(dnh, MFF_WRITE);
}

//--------------------------------------------------------------------------
THREAD_SAFE int debmod_t::send_debug_event_to_ida(
      const debug_event_t *ev,
      int rqflags)
{
  return ::send_debug_event_to_ida(ev, rqflags);
}

//---------------------------------------------------------------------------
THREAD_SAFE int send_debug_event_to_ida(
      const debug_event_t *ev,
      int rqflags)
{
  return handle_debug_event(ev, rqflags);
}

//--------------------------------------------------------------------------
#if TARGET_PROCESSOR != PLFM_ARM
void set_arm_thumb_modes(ea_t * /*addrs*/, int /*qty*/)
{
}
#endif

//--------------------------------------------------------------------------
static int idaapi process_get_info(int n, process_info_t *info)
{
  char input[QMAXFILE];
  input[0] = '\0';
  if ( n == 0 && !is_temp_database() )
    dbg_get_input_path(input, sizeof(input));

  return s_process_get_info(n, input, info);
}

//--------------------------------------------------------------------------
static bool idaapi init_debugger(
      const char *hostname,
      int port_num,
      const char *password)
{
  if ( !s_open_remote(hostname, port_num, password) )
    return false;

  int code = s_init((debug & IDA_DEBUG_DEBUGGER) != 0);
  // network error?
  if ( code <= 0 )
  {
    s_close_remote();
    return false;
  }

  debugger.process_get_info = (code & DBG_HAS_PROCGETINFO) != 0 ? process_get_info : NULL;
  debugger.detach_process   = (code & DBG_HAS_DETACHPROC)  != 0 ? s_detach_process : NULL;
  debugger_inited = true;
#ifdef WINCE_DEBUGGER
  slot = BADADDR;
  wince_load_options();
#endif
  processor_specific_init();
  register_idc_funcs(true);
  init_dbg_idcfuncs(true);
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_WIN32_USER || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
  install_x86seh_menu();
#endif
  return true;
}

//--------------------------------------------------------------------------
static bool idaapi term_debugger(void)
{
  if ( debugger_inited )
  {
    debugger_inited = false;
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_WIN32_USER || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
    remove_x86seh_menu();
#endif
    init_dbg_idcfuncs(false);
    register_idc_funcs(false);
    processor_specific_term();
    g_dbgmod.dbg_term();
    return s_close_remote();
  }
  return false;
}

static const char* const optype_names[] =
{
	"o_void",
	"o_reg",
	"o_mem",
	"o_phrase",
	"o_displ",
	"o_imm",
	"o_far",
	"o_near",
	"o_idpspec0",
	"o_idpspec1",
	"o_idpspec2",
	"o_idpspec3",
	"o_idpspec4",
	"o_idpspec5",
};

static const char* const dtyp_names[] =
{
	"dt_byte",
	"dt_word",
	"dt_dword",
	"dt_float",
	"dt_double",
	"dt_tbyte",
	"dt_packreal",
	"dt_qword",
	"dt_byte16",
	"dt_code",
	"dt_void",
	"dt_fword",
	"dt_bitfild",
	"dt_string",
	"dt_unicode",
	"dt_3byte",
	"dt_ldbl",
	"dt_byte32",
	"dt_byte64",
};

typedef const regval_t &(idaapi *getreg_func_t)(const char *name, const regval_t *regvalues);

static int idaapi hook_idp(void *user_data, int notification_code, va_list va)
{
	switch (notification_code)
	{
	case processor_t::idp_notify::get_operand_info:
	{
		ea_t ea = va_arg(va, ea_t);
		int n = va_arg(va, int);
		int thread_id = va_arg(va, int);
		getreg_func_t getreg = va_arg(va, getreg_func_t);
		const regval_t *regvalues = va_arg(va, const regval_t *);
		idd_opinfo_t * opinf = va_arg(va, idd_opinfo_t *);

		opinf->ea = BADADDR;
		opinf->debregidx = 0;
		opinf->modified = false;
		opinf->value.ival = 0;
		opinf->value_size = 1;

		if (decode_insn(ea))
		{
			uFlag = get_flags_novalue(ea);
			flags_t flags = get_optype_flags1(uFlag);
			opinfo_t buf;

			if (get_opinfo(ea, n, flags, &buf) == NULL) break;

			opinf->ea = buf.ri.base + cmd.Operands[n].value;

			return -1;
		}
	} break;
	}
	return 0;
}

//--------------------------------------------------------------------------
// Initialize debugger plugin
static int idaapi init(void)
{
#if !defined(__X64__) && DEBUGGER_ID != DEBUGGER_ID_X86_IA32_BOCHS \
 && DEBUGGER_ID != DEBUGGER_ID_TRACE_REPLAYER
  // Cannot debug 64-bit files locally in 32-bit IDA
  if ( inf.is_64bit() && !debugger.is_remote() )
    return PLUGIN_SKIP;
#endif
  if ( init_plugin() )
  {
    dbg = &debugger;
    plugin_inited = true;

	hook_to_notification_point(HT_IDP, hook_idp, NULL);

    return PLUGIN_KEEP;
  }
  return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
  if ( plugin_inited )
  {
    term_plugin();
    plugin_inited = false;
	unhook_from_notification_point(HT_IDP, hook_idp, NULL);
  }
  // we're being unloaded, clear the 'dbg' pointer if it's ours
  if ( dbg == &debugger )
    dbg = NULL;
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
static void idaapi run(int arg)
{
#ifdef HAVE_PLUGIN_RUN
  plugin_run(arg);
#else
  qnotused(arg);
#endif
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

#ifdef REMOTE_DEBUGGER
#  ifndef S_OPEN_FILE
#    define S_OPEN_FILE  s_open_file
#  endif
#  ifndef S_CLOSE_FILE
#    define S_CLOSE_FILE s_close_file
#  endif
#  ifndef S_READ_FILE
#    define S_READ_FILE  s_read_file
#  endif
#  ifndef S_WRITE_FILE
#    define S_WRITE_FILE s_write_file
#  endif
#else
#  define S_OPEN_FILE  NULL
#  define S_CLOSE_FILE NULL
#  define S_READ_FILE  NULL
#  define S_WRITE_FILE NULL
#endif

#ifndef GET_DEBMOD_EXTS
#  define GET_DEBMOD_EXTS NULL
#endif

#ifndef HAVE_UPDATE_CALL_STACK
#  define UPDATE_CALL_STACK NULL
#else
#  define UPDATE_CALL_STACK s_update_call_stack
#endif

#ifndef HAVE_APPCALL
#  define APPCALL NULL
#  define CLEANUP_APPCALL NULL
#else
#  define APPCALL s_appcall
#  define CLEANUP_APPCALL s_cleanup_appcall
#endif

#ifndef S_MAP_ADDRESS
#  define S_MAP_ADDRESS NULL
#endif

#ifndef SET_DBG_OPTIONS
#  define SET_DBG_OPTIONS NULL
#endif

#ifndef S_FILETYPE
#  define S_FILETYPE 0
#endif

// wince has no single step mechanism (except Symbian TRK, which provides support for it)
#if TARGET_PROCESSOR == PLFM_ARM && DEBUGGER_ID != DEBUGGER_ID_ARM_EPOC_USER
#  define S_SET_RESUME_MODE NULL
#else
#  define S_SET_RESUME_MODE s_set_resume_mode
#endif
#ifndef DEBUGGER_RESMOD
#  define DEBUGGER_RESMOD 0
#endif
debugger_t debugger =
{
  IDD_INTERFACE_VERSION,
  DEBUGGER_NAME,
  DEBUGGER_ID,
  PROCESSOR_NAME,
  DEBUGGER_FLAGS,

  REGISTER_CLASSES,
  REGISTER_CLASSES_DEFAULT,
  REGISTERS,
  REGISTERS_SIZE,

  MEMORY_PAGE_SIZE,

  bpt_code,
  sizeof(bpt_code),
  S_FILETYPE,
  DEBUGGER_RESMOD,

  init_debugger,
  term_debugger,

  NULL, // process_get_info: patched at runtime if ToolHelp functions are available
  s_start_process,
  s_attach_process,
  NULL, // detach_process:   patched at runtime if Windows XP/2K3
  rebase_if_required_to,
  s_prepare_to_pause_process,
  s_exit_process,

  s_get_debug_event,
  s_continue_after_event,
  s_set_exception_info,
  stopped_at_debug_event,

  s_thread_suspend,
  s_thread_continue,
  S_SET_RESUME_MODE,
  READ_REGISTERS,
  WRITE_REGISTER,
  s_thread_get_sreg_base,

  s_get_memory_info,
  s_read_memory,
  s_write_memory,

  is_ok_bpt,
  update_bpts,
  s_update_lowcnds,
  S_OPEN_FILE,
  S_CLOSE_FILE,
  S_READ_FILE,
  S_MAP_ADDRESS,
  SET_DBG_OPTIONS,
  GET_DEBMOD_EXTS,
  UPDATE_CALL_STACK,
  APPCALL,
  CLEANUP_APPCALL,
  s_eval_lowcnd,
  S_WRITE_FILE,
  s_ioctl,
  s_enable_trace,
  s_is_tracing_enabled,
  s_rexec,
  s_get_debapp_attrs,
};

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE|PLUGIN_DBG, // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  comment,              // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
