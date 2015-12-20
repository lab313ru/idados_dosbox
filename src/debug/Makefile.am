AM_CPPFLAGS = -I$(top_srcdir)/include -I@IDA_SDK@/include -I@IDA_SDK@/plugins/debugger -I@IDA_PLUGIN@ -DNO_OBSOLETE_FUNCS
#-D__IDP__ -D__PLUGIN__
#-fvisibility=hidden

if DEBUG_IDA
IDADOS = \
  @IDA_SDK@/plugins/debugger/util.cpp \
  @IDA_SDK@/plugins/debugger/rpc_hlp.cpp \
  @IDA_SDK@/plugins/debugger/rpc_engine.cpp \
  @IDA_SDK@/plugins/debugger/rpc_server.cpp \
  @IDA_SDK@/plugins/debugger/debmod.cpp \
  @IDA_SDK@/plugins/debugger/pc_debmod.cpp \
  @IDA_PLUGIN@/dosbox_debmod.cpp \
  @IDA_SDK@/plugins/debugger/tcpip.cpp \
  server.cpp
else
IDADOS =
endif

noinst_LIBRARIES = libdebug.a
libdebug_a_SOURCES = debug.cpp debug_gui.cpp debug_disasm.cpp debug_inc.h disasm_tables.h debug_win32.cpp $(IDADOS)

