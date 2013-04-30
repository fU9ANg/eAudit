
#ifndef _CTL_DEBUG_H
#define _CTL_DEBUG_H

#define MAX_ERR_BUF 1024

/*function declaration*/
extern void info(const char *fmt, ...);
extern void INFO(const char *fmt, ...);
extern void DEBUG(const char *fmt, ...);
extern void warning(const char *fmt, ...);
extern void error(const char *fmt,...);

#endif
