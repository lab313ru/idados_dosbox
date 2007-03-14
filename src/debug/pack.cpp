#define QBUFCHECK(x,y,z) ;

inline uchar *pack_db(uchar *ptr, uchar *end, uchar x)
{
  if ( ptr < end )
    *ptr++ = x;
  return ptr;
}

inline uchar unpack_db(const uchar **pptr, const uchar *end)
{
  const uchar *ptr = *pptr;
  uchar x = 0;
  if ( ptr < end )
    x = *ptr++;
  *pptr = ptr;
  return x;
}


//-----------------------------------------------------------------------
inline uchar *put_dw(uchar *ptr, uchar *end, ushort x)
{
  //QBUFCHECK(ptr, end-ptr, NULL);
  if ( ptr < end )
    *ptr++ = (uchar)(x>>8);
  if ( ptr < end )
    *ptr++ = (uchar)(x);
  return ptr;
}


//-----------------------------------------------------------------------
uchar *pack_dw(uchar *ptr, uchar *end, ushort x)
{
  QBUFCHECK(ptr, end-ptr, NULL);
  if ( x <= 0x7F )
    return pack_db(ptr, end, (uchar)(x));
  if ( x <= 0x3FFF )
    return put_dw(ptr, end, ushort(x|0x8000));
  ptr = pack_db(ptr, end, 0xFF);
  return put_dw(ptr, end, x);
}

//-----------------------------------------------------------------------
uchar *pack_dd(uchar *ptr, uchar *end, ulong x)
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
uchar *pack_ds(uchar *ptr, uchar *end, const char *x, size_t len)
{
  QBUFCHECK(ptr, end-ptr, NULL);
  if ( x == NULL )
    x = "";
  if ( len == 0 )
    len = strlen(x);
  if ( ptr+len > end )
    len = end - ptr;
  ptr = pack_dd(ptr, end, (ulong)(len));
  memcpy(ptr, x, len);
  return ptr+len;
}

//-----------------------------------------------------------------------
uchar *pack_dq(uchar *ptr, uchar *end, ulonglong x)
{
 ulong low, high;
 
 low = x & 0xffffffff;
 high = x >> 32;
 
  ptr = pack_dd(ptr, end, low); //low
  ptr = pack_dd(ptr, end, high); //high

  return ptr;
}

//-----------------------------------------------------------------------
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

//-----------------------------------------------------------------------
ushort unpack_dw(const uchar **pptr, const uchar *end)
{
  const uchar *ptr = *pptr;
  ushort x = 0;
  if ( ptr < end )
    x = *ptr++;
  if ( (x & 0x80) != 0 )
  {
    if ( (x & 0xC0) == 0xC0 )
    {
      x = get_dw(&ptr, end);
    }
    else
    {
      if ( ptr < end )
        x = ((x << 8) | *ptr++) & ~0x8000;
    }
  }
  *pptr = ptr;
  return x;
}

//-----------------------------------------------------------------------
ulong unpack_dd(const uchar **pptr, const uchar *end)
{
  const uchar *ptr = *pptr;
  ulong x = 0;
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
ulonglong unpack_dq(const uchar **pptr, const uchar *end)
{
  ulonglong x;
  ulong l = unpack_dd(pptr, end);
  ulong h = unpack_dd(pptr, end);
  
  x = (ulonglong)h << 32 + l;
  
  return x;
}

//-----------------------------------------------------------------------
char *unpack_ds(const uchar **pptr, const uchar *end, bool empty_null)
{
  size_t len = unpack_dd(pptr, end);
  if ( len == 0 && empty_null ) return NULL;
  size_t bufsize = len+1;
  if ( bufsize > MAXSTR )
    bufsize = MAXSTR;
  char *buf = (char *)malloc(bufsize);
  if ( buf == NULL )
    return NULL; //nomem("unpack_ds");
  memcpy(buf, *pptr, len);
  buf[len] = '\0';
  *pptr += len;
  return buf;
}

