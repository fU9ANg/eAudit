/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "common.h"
#include "analyze_db.h"
#include "debug.h"
#include "file.h"
#include "analyze_global.h"

	void
analyze_common(
	EA_ITF_PAR_INFO_ID	itf_par_info_id,
	MMAP_FILE_INFO_ID	mmap_file_info_id,
	CALLBACK_FUNC_SET_ID	callback_func_set_id
	)
{

	int i;

	if  (itf_par_info_id == NULL || \
		mmap_file_info_id == NULL|| \
		callback_func_set_id == NULL || \
		callback_func_set_id->analyze_fptr       == NULL || \
		callback_func_set_id->flush_fptr         == NULL || \
		callback_func_set_id->force_into_db_fptr == NULL)
	return;

	while(TRUE) {
		read_mmap_file(itf_par_info_id, mmap_file_info_id, callback_func_set_id);

		for(i=0; i<mmap_file_info_id->pkt_file_hdr.usr_hdr_id->all_packets_num; i++) {
			mmap_file_info_id->cur_pos = 	mmap_file_info_id->cur_pos_bk;

			get_protect_rule_id(mmap_file_info_id); /* protected resource */
			get_libpcap_pkt_hdr(mmap_file_info_id); /* libpcap packet header */

			mmap_file_info_id->cur_pos_bk += mmap_file_info_id->libpcap_hdr_id->cap_len;

			#ifdef _HEIFENG
			printf("=====================================new\n");
			heifeng_error();

			#endif

		
			(*(callback_func_set_id->analyze_fptr))(itf_par_info_id, mmap_file_info_id);

			mmap_file_info_id->cur_pos = mmap_file_info_id->next_pkt_pos;
#ifdef _HEIFENG
			heifeng_error();
#endif

		}

		unmmap_file(itf_par_info_id, mmap_file_info_id);
	}
}


	void
modify_dynamic_strategy(
	unsigned long	src_ip,
	unsigned short	src_port,
	char		pkt_type,
	char		cmd,
	unsigned long	res_index,
	EA_ITF_PAR_INFO_ID itf_par_info_id
	)
{
	sem_lock(itf_par_info_id->semid);

	itf_par_info_id->redirection_port_info_id->flag				=
		cmd;
	itf_par_info_id->redirection_port_info_id->redirect_info.res_index	=
		res_index;
	itf_par_info_id->redirection_port_info_id->redirect_info.ip		=
		src_ip;
	itf_par_info_id->redirection_port_info_id->redirect_info.filter_pkt_type=
		pkt_type;
	itf_par_info_id->redirection_port_info_id->redirect_info.mode_switch 	=
		itf_par_info_id->protect_res_id[res_index].mode_switch;
	itf_par_info_id->redirection_port_info_id->redirect_info.port		=
		ntohs(src_port);
	itf_par_info_id->redirection_port_info_id->redirect_info.pro_id		=
		itf_par_info_id->protect_res_id[res_index].pro_no;

	strcpy(itf_par_info_id->redirection_port_info_id->redirect_info.pro_name,
	        itf_par_info_id->protect_res_id[res_index].pro_name);

	itf_par_info_id->redirection_port_info_id->redirect_info.rule_id	=
		itf_par_info_id->protect_res_id[res_index].rule_id;

	kill(itf_par_info_id->redirect_pid, SIGUSR1);
	sem_unlock(itf_par_info_id->semid);
}


	void
stop_process(
	int sig_no
	)
{
	if(SIGINT==sig_no||SIGKILL==sig_no || SIGTERM == sig_no) {

		disconn_db();
		INFO("Close Database  Success!");
		INFO("SMTP ANALYSIS PROCESS RES CALLBACK OK!");
		exit(EXIT_SUCCESS);
	}
}


	void
set_stop_handle()
{
	signal(SIGTERM,stop_process);
	signal(SIGKILL,stop_process);
}



	void
get_current_date(
	char*	cur_date,
	int	date_len
	)
{
	struct 	tm break_time;
	time_t	t;
	time(&t);
	break_time = *localtime(&t);
	strftime(cur_date, date_len, "%Y_%m_%d", &break_time);
}


	void
change_current_date(
	unsigned long cur_date,
	int	      date_len
	)
{
	struct tm*    time_tmp = NULL;
	time_tmp	       = localtime(&cur_date);
	strftime(g_session_pos->g_cur_date, date_len, "%Y_%m_%d", time_tmp);
}


	int
is_next_day(
	struct tm*    ptime
	)
{
	time_t	      t;
	struct tm     tmptime;

	if(ptime == NULL) return(FALSE);

	time(&t);
	tmptime            = *localtime(&t);

	if(ptime->tm_mday !=  tmptime.tm_mday) return(TRUE);

	return(FALSE);
}


	off_t
get_file_size(
	char	*filename)
{
	struct	stat sbuf;
	int	ret;

	if(filename == NULL) return(0);

	ret = stat(filename, &sbuf);
	return(ret < 0 ? 0:sbuf.st_size);
}


	int
file_is_exist(
	char*	filename)
{
	if(NULL == filename)
		return(FILE_NOT_EXIST);
	if(0    == access(filename,F_OK))
		return(FILE_EXIST);
	else
		return(FILE_NOT_EXIST);
}


	int
sem_lock (
	int semid
	)
{
	struct sembuf waitop = {0,-1,SEM_UNDO};
	return(semop(semid,&waitop,1));
}


	int
sem_unlock (
	int semid
	)
{
	struct sembuf sops  = {0,+1,SEM_UNDO};
	return(semop(semid,&sops,1));
}


	int
set_monitor_signal(
	int		sig_num,
	sa_sigaction_t	act_func
	)
{
	struct itimerval itv;
	
	struct sigaction act;
	act.sa_handler	 = NULL;
	act.sa_flags	 = SA_SIGINFO | SA_NODEFER | SA_RESTART;
	act.sa_sigaction = act_func;

	if(sigaction(sig_num, &act, NULL)  == -1) return(ERR);

	itv.it_value.tv_sec  = itv.it_interval.tv_sec  = 1;
	itv.it_value.tv_usec = itv.it_interval.tv_usec = 0;

	if(setitimer(ITIMER_REAL, &itv, NULL) < 0)return(ERR);

	return(OK);
}


	void
heifeng_error(void)
{
	printf("cur_pos=====%x\n",		\
		g_mmap_file_info.cur_pos);
	printf("cur_pos_bk=====%x\n",		\
		g_mmap_file_info.cur_pos_bk);
	printf("libpcap_hdr_id=====%x\n",	\
		g_mmap_file_info.libpcap_hdr_id);
	printf("mmap_addr=====%x\n",		\
		g_mmap_file_info.mmap_addr);
	printf("pcap_hdr_id=====%x\n",		\
		g_mmap_file_info.pkt_file_hdr.pcap_hdr_id);
	printf("usr_hdr_id=====%x\n",		\
		g_mmap_file_info.pkt_file_hdr.usr_hdr_id);
	printf("rule_id_st_id=====%x\n",	\
		g_mmap_file_info.rule_id_st_id);
	printf("cap_len=====%d\n",		\
		g_mmap_file_info.libpcap_hdr_id->cap_len);
	printf("all_packets_num=====%d\n",	\
		g_mmap_file_info.pkt_file_hdr.usr_hdr_id->all_packets_num);
	printf("all_packets_size=====%d\n",	\
		g_mmap_file_info.pkt_file_hdr.usr_hdr_id->all_packets_size);

	printf("==============end\n");
	printf("\n");

}
