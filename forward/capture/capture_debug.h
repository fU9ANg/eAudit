#ifndef _CAPTURE_DEBUG_H
#define _CAPTURE_DEBUG_H

#define MAX_PT_BUF_SIZE  2048

/*function declaration*/
extern void info(const char *fmt, ...);
extern void INFO(const char *fmt, ...);
extern void DEBUG(const char *fmt, ...);
extern void warning(const char *fmt, ...);
extern void error(const char *fmt,...);
extern void PRINT_PAR(const char *format,...);

#endif
