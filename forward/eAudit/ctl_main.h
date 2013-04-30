
#ifndef _CTL_MAIN_H
#define _CTL_MAIN_H

/*the path of sys lock file*/
#ifndef _WITH_SYS_LOCK_PATH
#define EAUDIT_LOCK_FILE "/eAudit/bin/eAudit.LOCK"
#else
#define EAUDIT_LOCK_FILE "/var/lock/subsys/eAudit.LOCK"
#endif

#define MAX_RULES_GROUP_NUM 15

#define SYS_CFG_SET_PATH "/var/lib/eAudit/data"

#define MAX_PAR_SIZE                1024
#define MAX_ANS_MODEL_NAME 512

#define RES_CALLBACK_RPT_TIMES 2000
#define MAXBUF 700

/*the capture model path*/
#define CAPTURE_MODEL_PATH "/eAudit/bin/capture"
#define PMC_MODEL_PATH  "/eAudit/bin/pmc_server"
/*the filter model path*/
#define FILTER_MODEL_PATH   "/eAudit/bin/filter"

/*the analyze model path*/
#define ANALYZE_MODEL_PATH_SUFFIX  "_analysis"
#define SERVER_MODEL_PAHT_SUFFIX "_server"
#define ANALYZE_MODEL_BASE_PATH      "/eAudit/bin/"

/*the monitor proccess path*/
#define MOT_MODEL_PATH "/eAudit/bin/monitor"

/*pmc server process path*/
#define PMC_SEVER_MODEL_PATH "/eAudit/bin/pmc_sever"

/*the watch model path*/
#define WATCH_MODEL_PATH "/eAudit/bin/watch"

#define OPTSTRING_INIT "vVdDcCiIhH"

#define PIPE_PID_KEY_INFO 'K'

#endif
