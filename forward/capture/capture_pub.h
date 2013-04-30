
#ifndef _CAPTURE_PUB_H
#define _CAPTURE_PUB_H

#include <pcap.h>
#include "sail_errorcode.h"
#include "eAudit_pub.h"
#include "interface_pub.h"
#include "capture_model_ctl.h"

#define LOG_TOOL SYS_LOG

extern pcap_t *pd;
extern int g_capture_cmd;
extern int g_block_flag;

extern int g_can_capture;

#endif
