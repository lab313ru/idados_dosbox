AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/../../../include -I$(top_srcdir)/../ -DNO_OBSOLETE_FUNCS 
#-D__IDP__ -D__PLUGIN__
#-fvisibility=hidden

noinst_LIBRARIES = libdebug.a
libdebug_a_SOURCES = debug.cpp debug_gui.cpp debug_disasm.cpp debug_inc.h disasm_tables.h debug_win32.cpp ../../../util.cpp \
../../../rpc_hlp.cpp ../../../rpc_engine.cpp ../../../rpc_server.cpp ../../../debmod.cpp ../../../pc_debmod.cpp \
../../../dosbox_debmod.cpp ../../../tcpip.cpp server.cpp pro_util.cpp

