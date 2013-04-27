/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#ifndef ANALYZE_DEBUG_H
#define ANALYZE_DEBUG_H


//#define 			_DEBUG
//#define			_INFO

/*
 * prototypes.
 */
void info   (const char *fmt, ...);
void INFO   (const char *fmt, ...);
void DEBUG  (const char *fmt, ...);
void warning(const char *fmt, ...);
void error  (const char *fmt, ...);


#endif /* ANALYZE_DEBUG_H */
