#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>

#define USE_DANGEROUS_FUNCTIONS
#include "pro.h"

bool under_debugger = false;

idaman THREAD_SAFE NORETURN void ida_export interr(int code)
{
	fprintf(stderr, "Internal error: %d\n", code);
	exit(-1);
}

idaman void *ida_export qalloc( size_t size )
{
  return malloc(size);
}

idaman void *ida_export qalloc_or_throw(size_t size)
{
 return qalloc(size);
}

idaman void *ida_export qrealloc_or_throw(void *ptr, size_t size)
{
  return realloc(ptr, size);
}

idaman THREAD_SAFE void *ida_export qvector_reserve(void *vec, void *old, size_t cnt, size_t elsize)
{
  // HACK: Template type is unknown, but shouldn't matter for accessing v->alloc
  qvector<int>* v = (qvector<int>*)(vec);
  if (cnt > v->alloc) {
    void *ptr = realloc(old, cnt*elsize);
    v->alloc = cnt;
    return ptr;
  } else {
    return old;
  }
}


idaman void  ida_export qfree( void *alloc )
{
  free(alloc);
}

idaman NORETURN void ida_export qexit(int code)
{
 exit(code);
}

idaman int ida_export qerrcode(int new_code=-1)
{
 return errno;
}

idaman const char *ida_export qerrstr(int code=-1)
{
  if(code == -1)
    code = qerrcode();

  return strerror(code);
}

idaman char *ida_export winerr(int code)
{
  return ""; //FIXME: String constant returned as char*
}

idaman int ida_export qvprintf(const char *fmt, va_list va)
{
 return vprintf(fmt, va);
}

idaman NORETURN void ida_export verror(const char *message, va_list va)
{
  printf("verror: ");
  qvprintf(message, va);

  qexit(1);
}

idaman int ida_export qsnprintf(char *buffer, size_t n, const char *format, ...) 
{
  int ret;
  va_list va;

  if (n == 0)
    return 0;
  if (n == 1) {
    buffer[0] = 0;
    return 0;
  }

  std::string f;
  const char *ptr;
  for (ptr = format; *ptr; ++ptr) {
    if (*ptr != '%') {
      f += *ptr;
      continue;
    }

    // Scan forward to see if this is an 'a' format specifier.
    // We support zero padding and field width modifiers, but nothing else.
    const char *ptr2 = ptr+1;
    while (*ptr2 >= '0' && *ptr2 <= '9')
      ++ptr2;

    if (*ptr2 == 'a') {
      // found a '%a'

      bool zero_padding = (ptr[1] == '0');
      int width = -1;
      if (ptr[1] >= '0' && ptr[1] <= '9') {
        width = atoi(ptr+1);
#if C_IDA_64BIT
        width *= 2;
#endif
      }
      f += '%';
      if (zero_padding) f += '0';
      if (width > 0) {
        char buf[32];
        sprintf(buf, "%d", width);
        f += buf;
      }
      f += FMT_EA;
      f += 'x';
      ptr = ptr2;
    } else {

      if (ptr[1] == '%') {
        f += "%";
        ++ptr;
      }
      f += *ptr;
    }
  }

  va_start(va, format);
  ret = vsnprintf(buffer, n, f.c_str(), va);
  va_end(va);

  // "These function return the number of characters _actually written_
  // to the output string excluding the terminating zero."
  if (ret >= n)
    ret = n-1;

  return ret;
}

idaman char *ida_export qstrncpy(char *dst, const char *src, size_t dstsize)
{
  return strncpy(dst, src, dstsize);
}

inline uchar *put_dw(uchar *ptr, uchar *end, ushort x)
{
  //QBUFCHECK(ptr, end-ptr, NULL);
  if ( ptr < end )
    *ptr++ = (uchar)(x>>8);
  if ( ptr < end )
    *ptr++ = (uchar)(x);
  return ptr;
}

inline ushort get_dw(const uchar **pptr, const uchar *end)
{
  ushort x = 0;
  const uchar *ptr = *pptr;
  if ( ptr < end )
    x = (*ptr++) << 8;
  if ( ptr < end )
    x |= *ptr++;
  *pptr = ptr;
  return x;
}

inline uchar *pack_db(uchar *ptr, uchar *end, uchar x)
{
  if ( ptr < end )
    *ptr++ = x;
  return ptr;
}

//-----------------------------------------------------------------------
idaman uchar    *ida_export pack_dd(uchar *ptr, uchar *end, uint32 x)
{
  QBUFCHECK(ptr, end-ptr, NULL);
  if ( x <= 0x7F )
    return pack_db(ptr, end, (uchar)(x));
  if ( x <= 0x3FFF )
    return put_dw(ptr, end, ushort(x|0x8000));
  if ( x <= 0x1FFFFFFFL )
  {
    ptr = put_dw(ptr, end, ushort((x>>16)|0xC000));
    return put_dw(ptr, end, ushort(x));
  }
  *ptr++ = 0xFF;
  ptr = put_dw(ptr, end, ushort((x>>16)));
  return put_dw(ptr, end, ushort(x));
}

//-----------------------------------------------------------------------
idaman uchar    *ida_export pack_dq(uchar *ptr, uchar *end, uint64 x)
{
  QBUFCHECK(ptr, end-ptr, NULL);
  ptr = pack_dd(ptr, end, (uint32)x);
  ptr = pack_dd(ptr, end, x >> 32);
}


//-----------------------------------------------------------------------
idaman uint32    ida_export unpack_dd(const uchar **pptr, const uchar *end)
{
  const uchar *ptr = *pptr;
  uint32 x = 0;
  if ( ptr < end )
    x = *ptr++;
  if ( (x & 0x80) == 0x80 )
  {
    if ( (x & 0xC0) == 0xC0 )
    {
      ushort low, high;
      if ( (x & 0xE0) == 0xE0 )
      {
        high = get_dw(&ptr, end);
        low  = get_dw(&ptr, end);
      }
      else
      {
        if ( ptr < end )
          high = ushort(((x & ~0xC0) << 8) + *ptr++);
        else
          high = 0;
        low = get_dw(&ptr, end);
      }
      x = (long(high)<<16) + low;
    }
    else
    {
      if ( ptr < end )
        x = ((x & ~0x80)<<8) + *ptr++;
    }
  }
  *pptr = ptr;
  return x;
}

//-----------------------------------------------------------------------
idaman uint64    ida_export unpack_dq(const uchar **pptr, const uchar *end)
{
  uint32 l = unpack_dd(pptr, end);
  uint32 h = unpack_dd(pptr, end);
  return (((uint64)h)<<32) + l;
}

idaman FILE *ida_export qfopen(const char *file, const char *mode)
{
  return fopen(file, mode);
}

idaman int ida_export qfread(FILE *fp, void *buf, size_t n)
{
  return fread(buf, 1, n, fp);
}

idaman int ida_export qfwrite(FILE *fp, const void *buf, size_t n)
{
  return fwrite(buf, 1, n, fp);
}

idaman int ida_export qfseek(FILE *fp, int32 offset, int whence)
{
  return fseek(fp, offset, whence);
}

idaman int ida_export qfclose(FILE *fp)
{
  return fclose(fp);
}


idaman int ida_export qveprintf(const char *fmt, va_list va)
{
  return qvprintf(fmt, va);
}

idaman int ida_export qvsnprintf(char *buffer, size_t n, const char *format, va_list va)
{
  return vsnprintf(buffer, n, format, va);
}

idaman char *ida_export qstrdup( const char *string )
{
 return strdup(string);
}

idaman void ida_export reg_hit_counter(hit_counter_t *hc, bool do_reg)
{
  return;
}

idaman hit_counter_t *ida_export create_hit_counter(const char *name)
{
  //I got "Undefined reference to 'vtable for ...'" messages when compiling using new and the hit_counter_t constructor
  //so I'm doing it the old fashioned way.
  struct hit_counter_t *hc = (struct hit_counter_t *)malloc(sizeof(struct hit_counter_t));
  hc->name = name;

  hc->total = 0;
  hc->misses = 0;
  hc->elapsed = 0;
  hc->stamp = 0;
 
  return hc;
}

idaman void ida_export hit_counter_timer(hit_counter_t *hc, bool enable)
{
  return;
}

idaman void *ida_export open_linput(const char *file, bool remote)
{
  return NULL;
}

class linput_t
{
};

idaman void ida_export close_linput(linput_t *li)
{
  return;
}

idaman uint32 ida_export calc_file_crc32(linput_t *fp)
{
  return 0;
}

idaman uint32 ida_export qfsize(FILE *fp)
{
 uint32 cur_pos = ftell(fp);
 uint32 len;

 fseek(fp, 0, SEEK_END);

 len = ftell(fp);

 fseek(fp, cur_pos, SEEK_SET);

 return len;  
}

idaman bool  ida_export qfileexist(const char *file)
{
  // CHECKME
  struct stat buf;
  return (stat(file, &buf) == 0);
}


idaman FILE *ida_export fopenWB(const char *file)
{
  return qfopen(file, "wb");
}

idaman FILE *ida_export fopenRB(const char *file)
{
  return qfopen(file, "rb");
}

//stubs for callui_t and ui_notification_t
union callui_t          // Return codes (size of this type should be 4 bytes at most)
{
 uint32 padding; 
};

enum ui_notification_t
{
 ui_msg = 23,
 ui_temp = 1000
};

idaman callui_t ida_export_data /*idaapi*/ dummy_callui(ui_notification_t what, ...)
{
  // TODO: Maybe implement at least ui_msg?
  callui_t i;
  i.padding = 1;
  return i;
}

idaman void ida_export vshow_hex(const void *dataptr,size_t len,const char *fmt, va_list va)
{
  return;
}

int idados_msg(const char *format, ...)
{
  int ret;
  va_list va;

  va_start(va, format);
  ret = qvprintf(format, va); 
  va_end(va);

  return ret;
}


// TODO: port to different OSs
#include <sys/time.h>
idaman void ida_export get_nsec_stamp(uint64 *nsecs)
{
  if (!nsecs) return;
  timeval t;
  gettimeofday(&t, 0);
  uint64 r = ((uint64)t.tv_sec) * 1000000000UL;
  r += ((uint64)t.tv_usec) * 1000;
  *nsecs = r;
}

idaman bool ida_export relocate_relobj(struct relobj_t *_relobj, ea_t ea, bool mf)
{
  assert(false);
}

idaman void *ida_export launch_process(
        const launch_process_params_t &lpp,
        qstring *errbuf)
{
  assert(false);
}

callui_t (idaapi*callui)(ui_notification_t what,...);

