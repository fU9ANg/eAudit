/* FileName: zconf.h */
/**********************************************************************
 * 
 * Configuration of the zlib compression library
 * 
 * Author:
 *		Lizemin (lizemin@unismmw.com) 
 * 
 * Date: 
 *		Oct, 10, 1999 
 * 
 * Copyright(C) 1999-2000 Beijing Tsinghua Unishunf Info Sec Co., Ltd 
 * All rights reserved. 
 * 
 * 
 * ---------------------------------------------------------------------
 * Modify History 
 * ---------------------------------------------------------------------
 * 
 *         Date             Who                   Description 
 * 
 *      Oct, 10, 1999     Lizemin             The first version 1.0 
 * 
 *
 ************************************************************************/
																											
#ifndef _ZCONF_H
#define _ZCONF_H

/*
 * If you *really* need a unique prefix for all types and library functions,
 * compile with -DZ_PREFIX. The "standard" zlib should be compiled without it.
 */
#ifdef Z_PREFIX
#define deflateInit_            z_deflateInit_
#define deflate                 z_deflate
#define deflateEnd              z_deflateEnd
#define inflateInit_            z_inflateInit_
#define inflate                 z_inflate
#define inflateEnd              z_inflateEnd
#define deflateInit2_           z_deflateInit2_
#define deflateSetDictionary    z_deflateSetDictionary
#define deflateCopy             z_deflateCopy
#define deflateReset            z_deflateReset
#define deflateParams           z_deflateParams
#define inflateInit2_           z_inflateInit2_
#define inflateSetDictionary    z_inflateSetDictionary
#define inflateSync             z_inflateSync
#define inflateReset            z_inflateReset
#define compress                z_compress
#define uncompress              z_uncompress
#define adler32                 z_adler32
#define crc32                   z_crc32
#define get_crc_table           z_get_crc_table
#define Bytes                   z_Byte
#define uInt                    z_uInt
#define uLong                   z_uLong
#define Bytef                   z_Bytef
#define charf                   z_charf
#define intf                    z_intf
#define uIntf                   z_uIntf
#define uLongf                  z_uLongf
#define voidpf                  z_voidpf
#define voidp                   z_voidp
#endif

#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
#  define WIN32
#endif

#if defined(__GNUC__) || defined(WIN32) || defined(__386__) || defined(i386)
#  ifndef __32BIT__
#    define __32BIT__
#  endif
#endif

#if defined(__MSDOS__) && !defined(MSDOS)
#  define MSDOS
#endif

/*
 * Compile with -DMAXSEG_64K if the alloc function cannot allocate more
 * than 64k bytes at a time (needed on systems with 16-bit int).
 */
#if defined(MSDOS) && !defined(__32BIT__)
#  define MAXSEG_64K
#endif

#ifdef MSDOS
#  define UNALIGNED_OK
#endif

#if (defined(MSDOS) || defined(_WINDOWS) || defined(WIN32))  && !defined(STDC)
#  define STDC
#endif

#if (defined(__STDC__) || defined(__cplusplus)) && !defined(STDC)
#  define STDC
#endif

#ifndef STDC
/* cannot use !defined(STDC) && !defined(const) on Mac */
#  ifndef const
#    define const
#  endif
#endif

/* Some Mac compilers merge all .h files incorrectly: */
#if defined(__MWERKS__) || defined(applec) ||defined(THINK_C) ||defined(__SC__)
#  define NO_DUMMY_DECL
#endif

/* Maximum value for memLevel in deflateInit2 */
#ifndef MAX_MEM_LEVEL
#  ifdef MAXSEG_64K
#    define MAX_MEM_LEVEL 8
#  else
#    define MAX_MEM_LEVEL 9
#  endif
#endif

/* Maximum value for windowBits in deflateInit2 and inflateInit2 */
#ifndef MAX_WBITS
/* 32K LZ77 window */
#  define MAX_WBITS   15
#endif

/* The memory requirements for deflate are (in bytes):
            1 << (windowBits+2)   +  1 << (memLevel+9)
 that is: 128K for windowBits=15  +  128K for memLevel = 8  (default values)
 plus a few kilobytes for small objects. For example, if you want to reduce
 the default memory requirements from 256K to 128K, compile with
     make CFLAGS="-O -DMAX_WBITS=14 -DMAX_MEM_LEVEL=7"
 Of course this will generally degrade compression (there's no free lunch).

   The memory requirements for inflate are (in bytes) 1 << windowBits
 that is, 32K for windowBits=15 (default value) plus a few kilobytes
 for small objects.
*/

/* Type declarations */

/* function prototypes */
#ifndef OF
#  ifdef STDC
#    define OF(args)  args
#  else
#    define OF(args)  ()
#  endif
#endif

/* The following definitions for FAR are needed only for MSDOS mixed
 * model programming (small or medium model with some far allocations).
 * This was tested only with MSC; for other MSDOS compilers you may have
 * to define NO_MEMCPY in zutil.h.  If you don't need the mixed model,
 * just define FAR to be empty.
 */
#if (defined(M_I86SM) || defined(M_I86MM)) && !defined(__32BIT__)
/* MSC small or medium model */
#  define SMALL_MEDIUM
#  ifdef _MSC_VER
#    define FAR __far
#  else
#    define FAR far
#  endif
#endif

#if defined(__BORLANDC__) && (defined(__SMALL__) || defined(__MEDIUM__))
#  ifndef __32BIT__
#    define SMALL_MEDIUM
#    define FAR __far
#  endif
#endif

#ifndef FAR
#   define FAR
#endif

#if defined(__BORLANDC__) && defined(SMALL_MEDIUM)
/* Borland C/C++ ignores FAR inside typedef */
    #define Bytef unsigned char FAR
#else
   typedef unsigned char  FAR Bytef;
#endif

#ifdef STDC
   typedef void FAR *voidpf;
   typedef void     *voidp;
#else
   typedef unsigned char FAR *voidpf;
   typedef unsigned char     *voidp;
#endif

/* Compile with -DZLIB_DLL for Windows DLL support */
#if (defined(_WINDOWS) || defined(WINDOWS)) && defined(ZLIB_DLL)
#  include <windows.h>
#  define EXPORT  WINAPI
#else
#  define EXPORT
#endif

#ifdef _cplusplus
extern "C"{
#endif

unsigned long crc32( unsigned long crc, const unsigned char *buf, unsigned int len );

#ifdef _cplusplus
}
#endif

#endif
