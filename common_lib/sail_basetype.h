/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef SAIL_BASETYPE_H
#define SAIL_BASETYPE_H

/* these data types are platform/implementation-dependent. */
#if defined(_WINDOWS)

    #include <stddef.h>
    #include <limits.h>
    /* win32 */
    #if defined(_WIN32)
        #define SAIL_ENTRY      __declspec( dllexport )
        #define SAIL_PTR        *
        #ifndef NULL_PTR
            #define NULL_PTR    0
        #endif
    /* win16 */
    #else
        #define SAIL_ENTRY      _export _far _pascal        
        #define SAIL_PTR        far *
        #ifndef NULL_PTR
            #define NULL_PTR    0
        #endif
    #endif
/* not windows */
#else
    #include <unistd.h>
    
    #define SAIL_ENTRY
    #define SAIL_PTR            *
    #ifndef NULL_PTR
        #define NULL_PTR        0
    #endif
#endif




/*Define BOOL Type, can be TRUE or FALSE */
typedef unsigned int            SAIL_BOOL;

#ifndef TRUE
    #define TRUE                1
#endif

#ifndef FALSE
    #define FALSE               0
#endif



/*SAIL_UINT8, SAIL_INT8*/
typedef unsigned char           SAIL_UINT8;
typedef char                    SAIL_INT8;
typedef SAIL_UINT8  SAIL_PTR    SAIL_PUINT8;
typedef SAIL_INT8   SAIL_PTR    SAIL_PINT8;

/* SAIL_UINT16, SAIL_INT16 */
typedef unsigned short          SAIL_UINT16;
typedef short                   SAIL_INT16;
#define MAX_SAIL_UINT16         USHRT_MAX;
#define MAX_SAIL_INT16          SHRT_MAX;
typedef SAIL_UINT16 SAIL_PTR    SAIL_PUINT16;
typedef SAIL_INT16  SAIL_PTR    SAIL_PINT16;

/* SAIL_UINT32, SAIL_INT32 */
typedef unsigned int            SAIL_UINT32;
typedef int                     SAIL_INT32;
typedef SAIL_UINT32 SAIL_PTR    SAIL_PUINT32;
typedef SAIL_INT32  SAIL_PTR    SAIL_PINT32;


/*____________________________________________________________________________
SAIL_UINT64, SAIL_INT64
	
Find a 64-bit data type, if possible.
The conditions here are more complicated to avoid using numbers that
will choke lesser preprocessors (like 0xffffffffffffffff) unless
we're reasonably certain that they'll be acceptable.
 
Some *preprocessors* choke on constants that long even if the
compiler can accept them, so it doesn't work reliably to test values.
So cross our fingers and hope that it's a 64-bit type.
	
GCC uses ULONG_LONG_MAX.  Solaris uses ULLONG_MAX.
IRIX uses ULONGLONG_MAX.  Are there any other names for this?
____________________________________________________________________________*/
#if ULONG_MAX > 0xfffffffful
    #if ULONG_MAX == 0xfffffffffffffffful
        typedef unsigned long   SAIL_UINT64;
        typedef long            SAIL_INT64;
        #define SAIL_HAVE64	1
    #endif
#endif

#ifndef SAIL_HAVE64
    #if defined(ULONG_LONG_MAX) || defined (ULLONG_MAX) || defined(ULONGLONG_MAX)
        typedef unsigned long long	SAIL_UINT64;
        typedef long long			SAIL_INT64;
        #define SAIL_HAVE64			1
    #endif
#endif

#ifndef SAIL_HAVE64
    #if defined(__MWERKS__)
        #if __option ( longlong )
            typedef unsigned long long  SAIL_UINT64;
            typedef long long           SAIL_INT64;
            #define SAIL_HAVE64         1
        #endif
    #endif
#endif

/*typedef SAIL_UINT64   SAIL_PTR    SAIL_PUINT64;*/
/*typedef SAIL_INT64    SAIL_PTR    SAIL_PINT64;*/

#if SAIL_HAVE64
/* too painful to test all the variants above, so just do it this way */
    #define MAX_SAIL_UINT64 ((SAIL_UINT64)0xfffffffffffffffful)
    #define MAX_SAIL_INT64  ((SAIL_INT64)0x7fffffffffffffff)
#endif

#if INT_MAX == 0x7FFFFFFFL
    #define SAIL_ENUM_TYPEDEF( enumName, typeName )	typedef enum enumName typeName
#else
    #define SAIL_ENUM_TYPEDEF( enumName, typeName )	typedef SAIL_INT32 typeName
#endif

#define kSAIL_EnumMaxValue		INT_MAX
#define SAIL_ENUM_FORCE( enumName )		\
        k ## enumName ## force = kSAIL_EnumMaxValue

typedef SAIL_UINT8                  SAIL_BYTE;
typedef SAIL_BYTE   SAIL_PTR        SAIL_PBYTE;

typedef SAIL_INT32                  SAIL_ERROR;
typedef SAIL_ERROR  SAIL_PTR        SAIL_PERROR;

/* a simple value sufficient to hold any numeric or pointer type */
typedef void                        SAIL_USERVALUE;
typedef SAIL_USERVALUE  SAIL_PTR    SAIL_PUSERVALUE;

/* A SAIL_Size refers to in memory sizes. Use SAIL_FileOffset for file offsets */
typedef size_t                      SAIL_SIZE;
typedef SAIL_SIZE   SAIL_PTR        SAIL_PSIZE;
#define MAX_SAIL_SIZE               ( ~(SAIL_SIZE)0 )


/* An offset or size of a file */
#if SAIL_UNIX
    #ifdef HAVE_64BIT_FILES
        typedef off64_t             SAIL_OFFSET;
    #else /* !HAVE_64BIT_FILES	*/
        typedef off_t               SAIL_OFFSET;
    #endif /* HAVE_64BIT_FILES	*/
#else
    #if SAIL_HAVE64
        typedef SAIL_INT64          SAIL_OFFSET;
    #else
        typedef SAIL_INT32          SAIL_OFFSET;
    #endif
#endif

typedef SAIL_OFFSET SAIL_PTR        SAIL_POFFSET;

typedef SAIL_UINT32                 SAIL_FLAGS;

typedef SAIL_FLAGS  SAIL_PTR        SAIL_PFLAGS;


typedef struct tag_SAIL_VERSION
{
    SAIL_UINT16     majorVersion;
    SAIL_UINT16     minorVersion;
}SAIL_VERSION;

typedef SAIL_VERSION    SAIL_PTR    SAIL_PVERSION;


/* SAIL_STATE enumerates the session states */
typedef SAIL_UINT32                 SAIL_STATE;


typedef struct SAIL_INFO
{
    SAIL_VERSION    SailSafeVersion;        /* SailSafe interface version number */
    SAIL_UINT8      manufacturerID[32];     /* blank padded */
    SAIL_FLAGS      flags;                  /* must be zero */
    SAIL_UINT8      libraryDescription[32]; /* blank padded */
    SAIL_VERSION    libraryVersion;         /* version of library */
} SAIL_INFO;
typedef SAIL_INFO   SAIL_PTR    SAIL_PINFO; /* points to a SAIL_INFO structure */


/* SAIL_NOTIFICATION enumerates the types of notifications 
 * that SailSafe provides to an application.  */
typedef SAIL_UINT32     SAIL_NOTIFICATION;

typedef SAIL_UINT32     SAIL_RV;

/*define HINSTANCE type*/
#if defined(_WIN32)/* win32 */
    typedef SAIL_PUSERVALUE SAIL_HMODULE;
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef IN_OUT
#define IN_OUT
#endif

#ifndef SAIL_SESSION_HANDLE
typedef SAIL_UINT32	SAIL_SESSION_HANDLE;
typedef SAIL_UINT32	SAIL_PTR SAIL_SESSION_HANDLE_PTR;
#endif

#endif
