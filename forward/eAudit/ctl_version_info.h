
#ifndef _CTL_VERSION_INFO_H
#define _CTL_VERSION_INFO_H

#define MAX_VERSION_SIZE 64

/*function declaration*/
extern const char *get_copyright_info(void);
extern const char *get_pcap_version(void);
extern char *get_sys_version(void);
extern void show_version_info(void);

#endif
