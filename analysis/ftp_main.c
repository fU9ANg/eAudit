/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "interface.h"
#include "db_config.h"
#include "debug.h"
#include "param.h"
#include "log.h"
#include "common.h"
#include "db.h"
#include "decode.h"
#include "net.h"
#include "crc32.h"
#include "authorize.h"

#include "ftp_interface.h"
#include "ftp_global.h"
#include "ftp_main.h"
#include "ftp_config.h"
#include "ftp_db.h"
#include "eAudit_sendtcp.h"



int 
main(int argc, char** argv)
{
#ifdef _HEIFENG
sleep(10);
#endif

	PAR_ITF_ANALYZE par_itf_analyze;
	CALLBACK_FUNC_SET callback_func_set;
	char *p_par;

	if(argc <= 0)
	{	
		error("The parameters err[<0]!");
		exit(EXIT_FAILURE);
	}
   	p_par = strdup(argv[0]);
	if (NULL == p_par)
	{
		error("strup parameters error.");
		exit(EXIT_FAILURE);
	}

	if(argc == 2 && strncmp((char *)argv[1], "version", 7) == 0)
	{
		printf("¸§Ë³ftp label :2.0\n");
		exit(0);
	}

	
	//init_global_var(); EQ
	/* begining for initialize */
	time_t t;
	g_interval_time = 60;
	g_data_interval_time = 120;
	g_max_supported_session = 100;
	
	g_session_tbl_sum = 0;
	g_valid_ds = FALSE;
	g_session_pos = NULL;
	g_data_session_pos = NULL;
	g_supported_cmd_num = MAX_CMD_TBL_NUM;
	time(&t);
	g_old_time = *localtime(&t);
	get_current_date(g_cur_date, 32);	/* where is get_current_date? */
        /* ended for initialize */

	get_itf_par(&par_itf_analyze, p_par, FALSE);				/* in param.h/c     */
	convet_par_itf(&g_itf_par_info, &par_itf_analyze, FALSE);		/* in param.h/c     */
	init_log(g_model_name, g_itf_par_info.protocol_name, FILE_LOG, 0);	/* in log.h/c	    */
	if(read_db_cfg_info(&db_cfg_info)== ERR)				/* in db_config.h/c */				
	{
		write_log(g_model_name, g_itf_par_info.protocol_name, LOG_ERR, FILE_LOG,  __FILE__, __LINE__, SINGLE,"Read DB Configure File Fail.");
	}

	DEBUG("[DEBUG]***db_cfg_info.ip:%s", db_cfg_info.ip);
	DEBUG("[DEBUG]***db_cfg_info.port:%d", db_cfg_info.port);
	DEBUG("[DEBUG]***db_cfg_info.db:%s", db_cfg_info.db);
	DEBUG("[DEBUG]***db_cfg_info.usr_name:%s", db_cfg_info.usr_name);
	DEBUG("[DEBUG]***db_cfg_info.password:%s", db_cfg_info.password);
										/* in db.h/pgc      */
	connect_db(&g_data_conn, db_cfg_info.ip, db_cfg_info.port, db_cfg_info.db, db_cfg_info.usr_name, db_cfg_info.password);
	write_log(g_model_name, g_itf_par_info.protocol_name, LOG_INFO, FILE_LOG,  __FILE__, __LINE__, SINGLE,"Connect Database OK.");

	/* in ftp_config.h/c */
	if(read_ftp_cfg_file() == ERR)
	{
		write_log(g_model_name, g_itf_par_info.protocol_name, LOG_ERR, FILE_LOG,  __FILE__, __LINE__, SINGLE,"Read Configure File Fail.");
	}
	if(read_ftp_cmd_cfg_file() == ERR)
	{
		write_log(g_model_name, g_itf_par_info.protocol_name, LOG_ERR, FILE_LOG,  __FILE__, __LINE__, SINGLE,"Read  Cmmand Configure File Fail");
	}
	if(read_ftp_monitor_cfg_file() == ERR)
	{
		write_log(g_model_name, g_itf_par_info.protocol_name, LOG_ERR, FILE_LOG,  __FILE__, __LINE__, SINGLE,"Read  Monitor Configure File Fail");
	}
	if(set_monitor_signal(SIGALRM , monitor_signal_handler) == ERR)
	{
		write_log(g_model_name, g_itf_par_info.protocol_name, LOG_ERR, FILE_LOG,  __FILE__, __LINE__, SINGLE,"Set Monitor Signal Fail");
	}

 	g_itf_par_info.deposit_ivl_sec = g_interval_time;
	initialize_tbls();
	
	set_callback_fun_set(&callback_func_set);
	/* we got going */
	analyze_common(&g_itf_par_info ,&g_mmap_file_info, &callback_func_set);
	return 0;
}

/*
 *  here the f**king beginning for ftp analysis.
 */
void ftp_analyze(
	EA_ITF_PAR_INFO_ID	itf_par_info_id,
	MMAP_FILE_INFO_ID	mmap_file_info_id
	)
{
	g_pkt_file_hdr 	= mmap_file_info_id->pkt_file_hdr;
	g_rule_id_st_id = mmap_file_info_id->rule_id_st_id;
	g_libpcap_hdr_id= mmap_file_info_id->libpcap_hdr_id;

	force_sessions_into_db();				//

	/*
	 *  get the format data from mmap_file_info,
	 *  then save to user data type(PKT_BASIC_INFO).
   	 */
	if(set_pkt_basic_info() == OK) {
		if(is_new_session())
			add_new_session();			//
		else
			handle_session();			//

		monitor_conn_times();				//
		terminate();					//

		if(g_pkt_basic_info.data_len > 0 && g_session_pos != NULL) {
			if(g_data_session_pos == NULL) /* no data session */
				ftp_analyze_process();		////
			else
				ftp_data_session_process();	////
		}
		write_abnormal_session_into_db(FALSE);		//
	} /* fi */
}


int is_new_session() {

	unsigned long		i;
	unsigned long		session_sum = 0;
	EA_SESSION_TBL_ID	first_empty_session_tbl_id = NULL;

	g_session_pos		= NULL;
	g_data_session_pos	= NULL;
	monitor_flux();		//
	for(i = 0; i <g_max_supported_session; i++) {

		if(g_session_tbl_id[i].flag == EXIST_ENTRY) {

			if(g_rule_id_st_id->hit_direct == UP_DIRECT) {
                                /* checking mac, ip and port of src and dst */
				if(memcmp(g_session_tbl_id[i].src_mac, g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE) == 0 &&\
				   memcmp(g_session_tbl_id[i].dst_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE) == 0 &&\
				   g_session_tbl_id[i].src_ip   == g_pkt_basic_info.src_ip &&\
				   g_session_tbl_id[i].dst_ip   == g_pkt_basic_info.dst_ip &&\
				   g_session_tbl_id[i].src_port == g_pkt_basic_info.th_sport &&\
				   g_session_tbl_id[i].dst_port == g_pkt_basic_info.th_dport)
                                {
					g_session_pos = g_session_tbl_id + i;
					g_data_session_pos = NULL;
					return(FALSE);

				} else if(g_session_tbl_id[i].data_session_tbl.flag == EXIST_ENTRY ) {

					if(g_session_tbl_id[i].data_session_tbl.state == STATE_PASV) {

						if(g_session_tbl_id[i].data_session_tbl.dst_ip == g_pkt_basic_info.dst_ip &&\
							g_session_tbl_id[i].data_session_tbl.dst_port == g_pkt_basic_info.th_dport)
                                                {
							g_session_pos = g_session_tbl_id + i;
							g_data_session_pos = &g_session_tbl_id[i].data_session_tbl;
							return FALSE;
						}
					} else if(g_session_tbl_id[i].data_session_tbl.state == STATE_PORT) {

						if(g_session_tbl_id[i].data_session_tbl.src_ip == g_pkt_basic_info.src_ip &&\
							g_session_tbl_id[i].data_session_tbl.src_port == g_pkt_basic_info.th_sport)
						{
							g_session_pos = g_session_tbl_id + i;
							g_data_session_pos = &g_session_tbl_id[i].data_session_tbl;
							return FALSE;
						}
					} else  {
						if(memcmp(g_session_tbl_id[i].data_session_tbl.src_mac, \
                                                   g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE) == 0 &&  \
						   memcmp(g_session_tbl_id[i].dst_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE) == 0 &&\
						   g_session_tbl_id[i].data_session_tbl.src_ip == g_pkt_basic_info.src_ip &&\
						   g_session_tbl_id[i].data_session_tbl.dst_ip == g_pkt_basic_info.dst_ip &&\
						   g_session_tbl_id[i].data_session_tbl.src_port == g_pkt_basic_info.th_sport &&\
						   g_session_tbl_id[i].data_session_tbl.dst_port == g_pkt_basic_info.th_dport)
						{
							g_session_pos = g_session_tbl_id + i;
							g_data_session_pos = &g_session_tbl_id[i].data_session_tbl;
							return FALSE;
						}
					} /* FI STATE_PASV */
				}

			} else  { /* ELSE UP_DIRECT */

				if(memcmp(g_session_tbl_id[i].src_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE) == 0 &&\
				   memcmp(g_session_tbl_id[i].dst_mac, g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE) == 0 &&\
				   g_session_tbl_id[i].src_ip == g_pkt_basic_info.dst_ip &&\
				   g_session_tbl_id[i].dst_ip == g_pkt_basic_info.src_ip &&\
				   g_session_tbl_id[i].src_port == g_pkt_basic_info.th_dport &&\
				   g_session_tbl_id[i].dst_port == g_pkt_basic_info.th_sport)
				{
					g_session_pos = g_session_tbl_id + i;
					g_data_session_pos = NULL;
					return FALSE;
				} else if(g_session_tbl_id[i].data_session_tbl.flag == EXIST_ENTRY)  {

					if(g_session_tbl_id[i].data_session_tbl.state == STATE_PASV) {

						if(g_session_tbl_id[i].data_session_tbl.dst_ip == g_pkt_basic_info.src_ip &&\
							g_session_tbl_id[i].data_session_tbl.dst_port == g_pkt_basic_info.th_sport)
						{	
							g_session_pos = g_session_tbl_id + i;
							g_data_session_pos = &g_session_tbl_id[i].data_session_tbl;
							return FALSE;
						}
					} else if(g_session_tbl_id[i].data_session_tbl.state == STATE_PORT) {

						if(g_session_tbl_id[i].data_session_tbl.src_ip == g_pkt_basic_info.dst_ip &&\
							g_session_tbl_id[i].data_session_tbl.src_port == g_pkt_basic_info.th_dport)
						{
							g_session_pos = g_session_tbl_id + i;
							g_data_session_pos = &g_session_tbl_id[i].data_session_tbl;
							return FALSE;
						}
					} else  {

						if(memcmp(g_session_tbl_id[i].data_session_tbl.src_mac, \
                                                   g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE) == 0 &&  \
						   memcmp(g_session_tbl_id[i].data_session_tbl.dst_mac, \
                                                   g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE) == 0 &&  \
						   g_session_tbl_id[i].data_session_tbl.src_ip == g_pkt_basic_info.dst_ip &&\
						   g_session_tbl_id[i].data_session_tbl.dst_ip == g_pkt_basic_info.src_ip &&\
						   g_session_tbl_id[i].data_session_tbl.src_port == g_pkt_basic_info.th_dport &&\
						   g_session_tbl_id[i].data_session_tbl.dst_port == g_pkt_basic_info.th_sport)
						{
							g_session_pos = g_session_tbl_id + i;
							g_data_session_pos = &g_session_tbl_id[i].data_session_tbl;
							return FALSE;
						}
					} /* FI STATE_PASV */
				}
			} /* FI UP_DIRECT */

			session_sum++;
		} else if(first_empty_session_tbl_id == NULL) {

			first_empty_session_tbl_id = g_session_tbl_id + i;
		} /* FI EXIST_ENTRY */

		if(session_sum >= g_session_tbl_sum)
		{
			if(first_empty_session_tbl_id  == NULL && session_sum < g_max_supported_session)
			{
				first_empty_session_tbl_id  = g_session_tbl_id + session_sum;
			}
			g_session_pos = first_empty_session_tbl_id;
			g_data_session_pos = NULL;
			break;
		}
	} /* ROF */
	return TRUE;
}


void handle_session()
{
	char buffer[128];
	struct in_addr src_ip;
	struct in_addr dst_ip;

	g_session_pos->flux += g_pkt_basic_info.pkt_len;

	if(g_data_session_pos == NULL)   /*Ö÷»á»°*/
	{
		g_session_pos->pgt_len += g_pkt_basic_info.pkt_len;
		g_session_pos->pgt_num++;
		g_session_pos->ts_end = g_pkt_basic_info.ts;
		g_session_pos->ts_last = g_pkt_basic_info.ts.tv_sec;

/*		if(g_rule_id_st_id->hit_direct == DN_DIRECT)
		{
			g_session_pos->up_ackno = g_pkt_basic_info.th_ack;
		}else--
		{
			g_session_pos->dn_ackno = g_pkt_basic_info.th_ack;
		}*/
	}else							/*Êý¾Ý»á»°*/
	{
		if(g_data_session_pos->state == STATE_PASV)
		{
			if(g_rule_id_st_id->hit_direct == UP_DIRECT)
			{
				memcpy(g_data_session_pos->src_mac, g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE);
				memcpy(g_data_session_pos->dst_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE);
				g_data_session_pos->src_ip = g_pkt_basic_info.src_ip;
				g_data_session_pos->src_port = g_pkt_basic_info.th_sport;
			}else
			{
				memcpy(g_data_session_pos->src_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE);
				memcpy(g_data_session_pos->dst_mac, g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE);
				g_data_session_pos->src_ip = g_pkt_basic_info.dst_ip;
				g_data_session_pos->src_port = g_pkt_basic_info.th_dport;
			}
		}else if(g_data_session_pos->state == STATE_PORT)
		{
			if(g_rule_id_st_id->hit_direct == UP_DIRECT)
			{
				memcpy(g_data_session_pos->src_mac, g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE);
				memcpy(g_data_session_pos->dst_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE);
				g_data_session_pos->dst_ip = g_pkt_basic_info.dst_ip;
				g_data_session_pos->dst_port = g_pkt_basic_info.th_dport;
			}else
			{
				memcpy(g_data_session_pos->src_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE);
				memcpy(g_data_session_pos->dst_mac, g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE);
				g_data_session_pos->dst_ip = g_pkt_basic_info.src_ip;
				g_data_session_pos->dst_port = g_pkt_basic_info.th_sport;
			}
		}
		if(g_data_session_pos->state != STATE_CONN)
		{
			src_ip.s_addr = g_data_session_pos->src_ip;
			dst_ip.s_addr = g_data_session_pos->dst_ip;
			sprintf(buffer,"%s%s%d%d%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%ld%ld",\
					inet_ntoa(src_ip), inet_ntoa(dst_ip),\
					ntohs(g_data_session_pos->src_port), ntohs(g_data_session_pos->dst_port),\
					g_data_session_pos->src_mac[0], g_data_session_pos->src_mac[1], \
					g_data_session_pos->src_mac[2], g_data_session_pos->src_mac[3], \
					g_data_session_pos->src_mac[4], g_data_session_pos->src_mac[5],\
					g_data_session_pos->dst_mac[0], g_data_session_pos->dst_mac[1],\
					g_data_session_pos->dst_mac[2], g_data_session_pos->dst_mac[3], \
					g_data_session_pos->dst_mac[4], g_data_session_pos->dst_mac[5],\
					g_pkt_basic_info.ts.tv_sec, g_pkt_basic_info.ts.tv_usec);
			g_data_session_pos->data_session_id = crc32(0, (const unsigned char*)buffer, 128);
			g_data_session_pos->ts_start = g_pkt_basic_info.ts;
			g_data_session_pos->state = STATE_CONN;
		}

		g_data_session_pos->pgt_len += g_pkt_basic_info.pkt_len;
		g_data_session_pos->pgt_num++;
		g_data_session_pos->ts_end = g_pkt_basic_info.ts;
		g_data_session_pos->ts_last = g_pkt_basic_info.ts.tv_sec;


/*		if(g_rule_id_st_id->hit_direct == DN_DIRECT)
		{
			g_data_session_pos->up_ackno = g_pkt_basic_info.th_ack;
		}else
		{
			g_data_session_pos->dn_ackno = g_pkt_basic_info.th_ack;
		}		*/
		
	}

}
void terminate()
{
	if(g_session_pos == NULL)
	{
		return;
	}
	if(g_pkt_basic_info.th_flags & TCP_RST)
	{
		terminate_session();
		return;
	}


	if(g_pkt_basic_info.th_flags & TCP_FIN)
	{
//		getchar();
		if(g_rule_id_st_id->hit_direct == DN_DIRECT)
		{
			if(g_data_session_pos == NULL)
			{
				g_session_pos->up_ackno = g_pkt_basic_info.th_ack;
			}else
			{
				g_data_session_pos->up_ackno = g_pkt_basic_info.th_ack;
			}
		}else
		{
			if(g_data_session_pos == NULL)
			{
				g_session_pos->dn_ackno = g_pkt_basic_info.th_ack;
			}else
			{
				g_data_session_pos->dn_ackno = g_pkt_basic_info.th_ack;
			}
		}
	}

	if(g_pkt_basic_info.th_flags & TCP_ACK)
	{

		if(g_rule_id_st_id->hit_direct == UP_DIRECT)
		{
			if(g_data_session_pos == NULL)
			{
				if(g_session_pos->up_ackno == g_pkt_basic_info.th_seq)
				{
//					getchar();
					g_session_pos->recv_closeflag = 1;
				}
			}else
			{
				if(g_data_session_pos->up_ackno == g_pkt_basic_info.th_seq)
				{
//					getchar();
					g_data_session_pos->recv_closeflag = 1;
				}
			}
		}else
		{
			if(g_data_session_pos == NULL)
			{
				if(g_session_pos->dn_ackno == g_pkt_basic_info.th_seq)
				{
					g_session_pos->send_closeflag = 1;
				}
			}else
			{
				if(g_data_session_pos->dn_ackno == g_pkt_basic_info.th_seq)
				{
					g_data_session_pos->send_closeflag = 1;
				}
			}
		}
	}

	if(g_data_session_pos != NULL)
	{
		if(g_data_session_pos->send_closeflag == 1 && g_data_session_pos->recv_closeflag == 1)
		{
			terminate_session();
		}
	}else
	{
		if(g_session_pos->send_closeflag == 1 && g_session_pos->recv_closeflag == 1)
		{
			terminate_session();
		}
	}
}

void terminate_session()
{
	EA_DATA_SESSION_TBL_ID data_session_tbl_id;
	EA_RECORD_FILE_TBL record_file_tbl;
	EA_DETAIL_DIVIDE detail_divide;
	EA_RECORD_DATA_FILE_TBL record_data_file_tbl;

	int record_index;
	char* str_mmaped = NULL;
	int count;
	
	unsigned long i;
	
	DEBUG("Terminate session.");


	if(g_session_pos->data_session_tbl.flag == EXIST_ENTRY && g_session_pos->detail_tbl.fd >=0)
	{
		data_session_tbl_id = &g_session_pos->data_session_tbl;

		record_file_tbl.session_id = g_session_pos->session_id;
		record_file_tbl.file_no = g_session_pos->detail_tbl.file_no++;
		record_file_tbl.p_type_id = PRO_TYPE_FTP;
		record_file_tbl.start_time = data_session_tbl_id->ts_start;
		record_file_tbl.end_time = data_session_tbl_id->ts_end;
		strcpy(record_file_tbl.file_name, g_session_pos->detail_tbl.file_name);
		strcpy(record_file_tbl.file_suffix, g_session_pos->detail_tbl.file_suffix);
		record_file_tbl.real_size = data_session_tbl_id->data_len;
		record_file_tbl.nego_size = g_session_pos->detail_tbl.file_size;
		record_file_tbl.result = RESULT_SUCCESS;
		strcpy(record_file_tbl.save_path, g_session_pos->detail_tbl.save_path);
		write_record_file_db_tbl(&record_file_tbl);

		if((str_mmaped = mmap(0, g_session_pos->data_session_tbl.data_len, PROT_READ, MAP_SHARED, g_session_pos->detail_tbl.fd, 0)) != MAP_FAILED)
		{
			detail_divide.session_id  = g_session_pos->session_id;
			detail_divide.analysis_index = g_session_pos->detail_tbl.cur_analysis_index;
			record_index = 0;
			
			count = g_session_pos->data_session_tbl.data_len/DETAIL_RECORD_LEN;
			i = 0;
			detail_divide.detail_record_ptr = str_mmaped;
			while(i < count)
			{
				detail_divide.record_index = record_index++;
				write_detail_data_ftp_db_tbl(&detail_divide, DETAIL_RECORD_LEN);	
				detail_divide.detail_record_ptr += DETAIL_RECORD_LEN;
				i++;
			}
			detail_divide.record_index = record_index;
			write_detail_data_ftp_db_tbl(&detail_divide, g_session_pos->data_session_tbl.data_len%DETAIL_RECORD_LEN);	




			record_data_file_tbl.session_id = g_session_pos->session_id;
			record_data_file_tbl.record_id = g_session_pos->detail_tbl.file_no-1;
			record_index = 0;
			count = g_session_pos->data_session_tbl.data_len/DETAIL_RECORD_LEN;
			i = 0;
			record_data_file_tbl.save_content= str_mmaped;			
			while(i < count)
			{
				record_data_file_tbl.file_neaf_id = record_index++;
				write_record_data_file_db_tbl(&record_data_file_tbl, RECORD_DATA_LEN);	
				record_data_file_tbl.save_content += RECORD_DATA_LEN;
				i++;
			}
			record_data_file_tbl.file_neaf_id = record_index;
			write_record_data_file_db_tbl(&record_data_file_tbl, g_session_pos->data_session_tbl.data_len%RECORD_DATA_LEN);				

			munmap(str_mmaped, g_session_pos->data_session_tbl.data_len);
		}

		close(g_session_pos->detail_tbl.fd);
		unlink(g_session_pos->detail_tbl.save_path);
		g_session_pos->detail_tbl.fd  = -1;
		
		memset(data_session_tbl_id, 0x00, EA_DATA_SESSION_TBL_SIZE);
	}
	
	if(g_data_session_pos == NULL)
	{
		/*Ð´»á»°*/
		if(g_session_pos->data_flag == 1)
		{
			write_session_into_db(g_session_pos);
		}
		memset(g_session_pos, 0x00, EA_SESSION_TBL_SIZE);
		g_session_tbl_sum--;
	}

}

void add_new_session()
{
	char buffer[128];
	struct in_addr src_ip;
	struct in_addr dst_ip;

	struct in_addr src_net;
	struct in_addr dst_net;

    	SRC_INFO src_info;

	if(g_session_pos == NULL)
	{
		error("The Number of Supported Session is too small. ");
		write_log(g_model_name, g_itf_par_info.protocol_name, LOG_DEBUG,\
                          FILE_LOG, __FILE__, __LINE__, SINGLE,                 \
                          "The Number of Supported Session is too small.");
		return;
	}

	g_session_pos->flag = EXIST_ENTRY;

    	src_net.s_addr =  g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].sip.ip & g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].sip.mask;
     	dst_net.s_addr =  g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].dip.ip & g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].dip.mask;

 	switch(g_rule_id_st_id->hit_direct)
   	{
   		case UP_DIRECT:

			memcpy(g_session_pos->src_mac, g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE);
			memcpy(g_session_pos->dst_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE);
			g_session_pos->src_ip   = g_pkt_basic_info.src_ip;
    			g_session_pos->dst_ip   = g_pkt_basic_info.dst_ip;
     			g_session_pos->src_port = g_pkt_basic_info.th_sport;
			g_session_pos->dst_port = g_pkt_basic_info.th_dport;
            		g_session_pos->src_net  = src_net.s_addr;
		break;
		case DN_DIRECT:

			memcpy(g_session_pos->src_mac, g_pkt_basic_info.dst_mac, MAC_ADDRESS_SIZE);
			memcpy(g_session_pos->dst_mac, g_pkt_basic_info.src_mac, MAC_ADDRESS_SIZE);
			g_session_pos->src_ip   = g_pkt_basic_info.dst_ip;
			g_session_pos->dst_ip   = g_pkt_basic_info.src_ip;
			g_session_pos->src_port = g_pkt_basic_info.th_dport;
			g_session_pos->dst_port = g_pkt_basic_info.th_sport;
           		g_session_pos->dst_net  = dst_net.s_addr;
		break;
		case ALL_DIRECT:
			if ((g_pkt_basic_info.src_ip & g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].sip.mask) == \
           			(g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].sip.ip& g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].sip.mask))
            			g_session_pos->src_net = src_net.s_addr;
      			if ((g_pkt_basic_info.dst_ip & g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].dip.mask) == \
           			(g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].dip.ip& g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].dip.mask))
           			g_session_pos->dst_net = dst_net.s_addr;
		default:
			break;
	}

	g_session_pos->ts_start = g_pkt_basic_info.ts;
	g_session_pos->ts_end   = g_pkt_basic_info.ts;
	g_session_pos->pgt_len  = g_pkt_basic_info.pkt_len;
	g_session_pos->flux     = g_pkt_basic_info.pkt_len;

 	g_session_pos->pgt_num  = 1;
	g_session_pos->ts_last  = g_pkt_basic_info.ts.tv_sec;
	g_session_pos->pro_type_id = PRO_TYPE_FTP;
	src_ip.s_addr = g_session_pos->src_ip;
	dst_ip.s_addr = g_session_pos->dst_ip;
	sprintf(buffer,"%s%s%d%d%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%ld%ld",\
			inet_ntoa(src_ip), inet_ntoa(dst_ip),                           \
			ntohs(g_session_pos->src_port), ntohs(g_session_pos->dst_port), \
			g_session_pos->src_mac[0], g_session_pos->src_mac[1],           \
			g_session_pos->src_mac[2], g_session_pos->src_mac[3],           \
			g_session_pos->src_mac[4], g_session_pos->src_mac[5],           \
			g_session_pos->dst_mac[0], g_session_pos->dst_mac[1],           \
			g_session_pos->dst_mac[2], g_session_pos->dst_mac[3],           \
			g_session_pos->dst_mac[4], g_session_pos->dst_mac[5],           \
			g_pkt_basic_info.ts.tv_sec, g_pkt_basic_info.ts.tv_usec);
	g_session_pos->session_id=crc32(0, (const unsigned char*)buffer, 128);
	
	
    	src_info.src_ip = g_session_pos->src_ip;
    	sprintf((char*)src_info.src_mac,"%.2X%.2X%.2X%.2X%.2X%.2X", g_session_pos->src_mac[0], g_session_pos->src_mac[1],\
		 g_session_pos->src_mac[2], g_session_pos->src_mac[3], g_session_pos->src_mac[4], g_session_pos->src_mac[5]);
    	src_info.sport = ntohs(g_session_pos->src_port);
	get_usr_info(&(g_session_pos->usr_info),g_itf_par_info.usr_list_id,g_itf_par_info.usr_all_num,&src_info, g_rule_id_st_id->usr_id);
	strcpy((char*)(g_session_pos->protected_res_name),(char*)(g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].rule_name));	

	set_eaudit_authorize_info(&(g_session_pos->eaudit_authorize_info), g_itf_par_info.protect_res_id,g_itf_par_info.authorize_network_id, g_rule_id_st_id);

	change_current_date(g_pkt_basic_info.ts.tv_sec, 32);



	 /*µÃµ½ÊÚÈ¨¸÷¸öÊÚÈ¨ÎÄ¼þË÷ÒýÖµ£¬±ãÓÚºóÃæ*/
	g_session_pos->eaudit_authorize_info.cmd_index = search_in_cmd_authorize_list(&(g_session_pos->eaudit_authorize_info.authorize_cmd_content_addr), g_itf_par_info.authorize_cmd_id, g_itf_par_info.authorize_cmd_num, g_rule_id_st_id->authorize_id);
	g_session_pos->eaudit_authorize_info.account_index = search_in_account_authorize_list(&(g_session_pos->eaudit_authorize_info.authorize_account_content_addr), g_itf_par_info.authorize_account_id, g_itf_par_info.authorize_account_num, g_rule_id_st_id->authorize_id);
	g_session_pos->eaudit_authorize_info.custom_made_index = search_in_custom_authorize_list(&(g_session_pos->eaudit_authorize_info.authorize_custom_content_addr), g_itf_par_info.authorize_custom_id, g_itf_par_info.authorize_custom_num, g_rule_id_st_id->authorize_id);
	g_session_pos->eaudit_authorize_info.custom_made_pro_index = search_in_custom_protol_authorize_list(g_session_pos->eaudit_authorize_info.authorize_protocol_type, g_itf_par_info.authorize_pro_feature_id, g_itf_par_info.authorize_pro_feature_num, g_rule_id_st_id->authorize_id);

	if(g_session_pos->eaudit_authorize_info.account_index > -1)     {

		g_session_pos->account.block = g_itf_par_info.authorize_account_id[g_session_pos->eaudit_authorize_info.account_index].against_authorize_event.block_flag;
		g_session_pos->account.log = g_itf_par_info.authorize_account_id[g_session_pos->eaudit_authorize_info.account_index].against_authorize_event.log_flag;
		g_session_pos->account.warn = g_itf_par_info.authorize_account_id[g_session_pos->eaudit_authorize_info.account_index].against_authorize_event.warn_flag;
	}


	if(g_session_pos->eaudit_authorize_info.cmd_index > -1)         {

		g_session_pos->cmd.block = g_itf_par_info.authorize_cmd_id[g_session_pos->eaudit_authorize_info.cmd_index].against_authorize_event.block_flag;
		g_session_pos->cmd.log = g_itf_par_info.authorize_cmd_id[g_session_pos->eaudit_authorize_info.cmd_index].against_authorize_event.log_flag;
		g_session_pos->cmd.warn = g_itf_par_info.authorize_cmd_id[g_session_pos->eaudit_authorize_info.cmd_index].against_authorize_event.warn_flag;
	}


	if(g_session_pos->eaudit_authorize_info.custom_made_index > -1)
	{
		g_session_pos->custom.block = g_itf_par_info.authorize_custom_id[g_session_pos->eaudit_authorize_info.custom_made_index].against_authorize_event.block_flag;
		g_session_pos->custom.log = g_itf_par_info.authorize_custom_id[g_session_pos->eaudit_authorize_info.custom_made_index].against_authorize_event.log_flag;
		g_session_pos->custom.warn = g_itf_par_info.authorize_custom_id[g_session_pos->eaudit_authorize_info.custom_made_index].against_authorize_event.warn_flag;
	}


	if(g_session_pos->eaudit_authorize_info.custom_made_pro_index > -1)
	{	
		g_session_pos->pro_feature.block = g_itf_par_info.authorize_pro_feature_id[g_session_pos->eaudit_authorize_info.custom_made_pro_index].against_authorize_event.block_flag;
		g_session_pos->pro_feature.log = g_itf_par_info.authorize_pro_feature_id[g_session_pos->eaudit_authorize_info.custom_made_pro_index].against_authorize_event.log_flag;
		g_session_pos->pro_feature.warn = g_itf_par_info.authorize_pro_feature_id[g_session_pos->eaudit_authorize_info.custom_made_pro_index].against_authorize_event.warn_flag;
	}


    g_session_pos->protected_res_no = g_itf_par_info.protect_res_id[g_rule_id_st_id->res_index].rule_id;
	construct_protected_res_content(g_session_pos->protected_res_content,  g_itf_par_info.protect_res_id, g_rule_id_st_id->res_index);

	g_session_pos->detail_tbl.fd = -1;
	g_session_tbl_sum++;
	
	add_conn_times();

 	
}


void ftp_analyze_process() {

	unsigned char*	data_addr = g_pkt_basic_info.data_addr;
	int		data_len  = g_pkt_basic_info.data_len;
	int		realdata_len;
	int		len;
	char*		p 	  = NULL;
	int		cmd_len;

	char		log_detail[MAX_LOG_DETAIL_SIZE + 1];
	char		warn_des  [MAX_ALARM_DES_SIZE  + 1];
	int		n;

	int		tmp_len   = 0;

	EA_ANALYSIS_FTP_CMD_TBL	analysis_ftp_cmd_tbl; /* CMD_TBL */

	memset(&analysis_ftp_cmd_tbl, 0x00, EA_ANALYSIS_FTP_CMD_TBL_SIZE);

	g_session_pos->data_flag = 1;
	if(g_rule_id_st_id->hit_direct == UP_DIRECT) {

		realdata_len = (data_len > MAX_REQUEST_LEN ? MAX_REQUEST_LEN : data_len) - 2;
		memcpy(g_session_pos->detail_tbl.request, data_addr, realdata_len);
		g_session_pos->detail_tbl.request[realdata_len] = '\0';
		g_session_pos->detail_tbl.cur_cmd_time = g_pkt_basic_info.ts;
		g_session_pos->up_seq = g_pkt_basic_info.th_seq;
		g_session_pos->up_ack = g_pkt_basic_info.th_ack;

	} else {
		g_session_pos->down_seq = g_pkt_basic_info.th_seq;
		g_session_pos->down_ack = g_pkt_basic_info.th_ack;

		if(g_session_pos->detail_tbl.request[0]== '\0') return;
		if(analysis_delay())				return;

		p = g_session_pos->detail_tbl.request;
		while(*p != ' ' && *p != '\0') p++;

		/*
		 *  get request command name of FTP
		 *  so save to analysis_ftp_cmd_tbl.cmd_name
		 */
		cmd_len = p - g_session_pos->detail_tbl.request;
		memcpy(analysis_ftp_cmd_tbl.cmd_name, g_session_pos->detail_tbl.request, cmd_len);
		analysis_ftp_cmd_tbl.cmd_name[cmd_len] 	= '\0';	/* example: cmd_name = "pass" */
		search_in_cmd_tbl(analysis_ftp_cmd_tbl.cmd_name);


		analysis_ftp_cmd_tbl.session_id 	=  \
			g_session_pos->session_id;
		analysis_ftp_cmd_tbl.analysis_index 	=  \
			g_session_pos->detail_tbl.cur_analysis_index;
		analysis_ftp_cmd_tbl.request_time 	=  \
			g_session_pos->detail_tbl.cur_cmd_time;
		analysis_ftp_cmd_tbl.response_time 	=  \
			g_pkt_basic_info.ts;
		
		
		/*
		 *  get request command number of FTP
		 *  so save to analysis_ftp_cmd_tbl.cmd_no.
		 */
		if(g_cmd_pos != NULL) {
			analysis_ftp_cmd_tbl.cmd_no = g_cmd_pos->cmd_no;
			strcpy(analysis_ftp_cmd_tbl.cmd_chinese, g_cmd_pos->cmd_ch);
		} else  analysis_ftp_cmd_tbl.cmd_no = 0;

		
		/*
		 *  get request command parameter of FTP
		 *  so save to analysis_ftp_cmd_tbl.cmd_param.
		 */
		if((len=strlen(g_session_pos->detail_tbl.request)-cmd_len-1) > 0) {
			if(strcmp(analysis_ftp_cmd_tbl.cmd_name, "PASS") == 0)
				strcpy(analysis_ftp_cmd_tbl.cmd_param, "******");
			else {
				tmp_len = 64;
				if(g_session_pos->utf8_flag == 1) {
					if(utf8_to_gb2312(g_session_pos->detail_tbl.request+cmd_len + 1, \
						len, analysis_ftp_cmd_tbl.cmd_param, &tmp_len) == -1) 	 {
						memset(analysis_ftp_cmd_tbl.cmd_param, 0x00, 64);
						memcpy(analysis_ftp_cmd_tbl.cmd_param, 			 \
						       g_session_pos->detail_tbl.request+cmd_len + 1, len);
					}
				} else
					memcpy(analysis_ftp_cmd_tbl.cmd_param, 	\
					g_session_pos->detail_tbl.request +	\
					cmd_len + 1, len );

				analysis_ftp_cmd_tbl.cmd_param[len] = 0x00;
			}
		}
		else analysis_ftp_cmd_tbl.cmd_param[0] = 0x00;


		/*
		 *  get response command information of FTP
		 *  so save to analysis_ftp_cmd_tbl.res_info.
		 */		
		if((len = strlen((char*)g_pkt_basic_info.data_addr) - 2) > 0) {
			len = len > 255 ? 255 : len;
			
			tmp_len   = 256;
			if(g_session_pos->utf8_flag == 1) {
				if(utf8_to_gb2312(g_pkt_basic_info.data_addr, 	\
					len, analysis_ftp_cmd_tbl.res_info, &tmp_len) == -1) {
					memset(analysis_ftp_cmd_tbl.res_info, 0x00, 256);
					memcpy(analysis_ftp_cmd_tbl.res_info, g_pkt_basic_info.data_addr, len);
				}
			} else memcpy(analysis_ftp_cmd_tbl.res_info, g_pkt_basic_info.data_addr, len);

			analysis_ftp_cmd_tbl.res_info[len] = '\0';
		}


		if(search_in_cmd_list(analysis_ftp_cmd_tbl.cmd_name, g_itf_par_info.authorize_cmd_id, \
			g_session_pos->eaudit_authorize_info.authorize_cmd_content_addr,\
			g_session_pos->eaudit_authorize_info.cmd_index)) {

			n = snprintf(warn_des, MAX_ALARM_DES_SIZE+1, "ÓÃ»§%sÎÞÈ¨Ê¹ÓÃÃüÁî%s", \
				g_session_pos->usr_info.src_usrname, analysis_ftp_cmd_tbl.cmd_name);
			warn_des[n] = 0x00;
			n = snprintf(log_detail, MAX_LOG_DETAIL_SIZE+1, "ÓÃ»§%sÎÞÈ¨Ê¹ÓÃÃüÁî%s", \
				g_session_pos->usr_info.src_usrname, analysis_ftp_cmd_tbl.cmd_name);
			log_detail[n] = 0x00;
			
			handle_ultravires(g_session_pos, analysis_ftp_cmd_tbl.cmd_name, log_detail, warn_des, CMD);
		}
		if(search_in_custom_list(analysis_ftp_cmd_tbl.cmd_name, g_itf_par_info.authorize_custom_id,\
			g_session_pos->eaudit_authorize_info.authorize_custom_content_addr, \
			g_session_pos->eaudit_authorize_info.custom_made_index, FULL_MATCH_MODE)) {

			n = snprintf(warn_des, MAX_ALARM_DES_SIZE+1, "ÓÃ»§%sÎÞÈ¨Ê¹ÓÃÃüÁî%s", \
				g_session_pos->usr_info.src_usrname, analysis_ftp_cmd_tbl.cmd_name);
			warn_des[n] = 0x00;
			n = snprintf(log_detail, MAX_LOG_DETAIL_SIZE+1, "ÓÃ»§%sÎÞÈ¨Ê¹ÓÃÃüÁî%s", \
				g_session_pos->usr_info.src_usrname, analysis_ftp_cmd_tbl.cmd_name);
			log_detail[n] = 0x00;
			handle_ultravires(g_session_pos, analysis_ftp_cmd_tbl.cmd_name, log_detail, warn_des, CUSTOM);

		}
		
		if(g_session_pos->eaudit_authorize_info.eaudit_info & EVENT_LEVEL)
			g_session_pos->detail_tbl.event_seq++;

		write_detail_ftp_db_tbl(&analysis_ftp_cmd_tbl);		//
		analysis_ftp_cmd();

		g_session_pos->detail_tbl.cur_analysis_index++;
		g_session_pos->detail_tbl.request[0] = '\0';
	}
}


/*
 *  ANALYSIS ALL COMMAND OF FTP; 
 *  IF HAVE CONTENT OF COMMAND,
 *  SO WRITE TO DATABASE.
 */
void analysis_ftp_cmd() {

	if(analysis_cmd_user())		return;
	if(analysis_cmd_cwd ())		return;
	if(analysis_cmd_pwd ())		return;
	if(analysis_cmd_size())		return;
	if(analysis_cmd_dele())		return;
	if(analysis_cmd_rnfr())		return;
	if(analysis_cmd_rnto())		return;
	if(analysis_cmd_pasv())		return;
	if(analysis_cmd_port())		return;
	if(analysis_cmd_retr())		return;
	if(analysis_cmd_stor())		return;
	if(analysis_cmd_quit()) 	return;
	if(analysis_cmd_opts()) 	return;
}


int analysis_delay() {
	/*
	 * 125
	 * 数据连接已打开，准备传送
	 * 150
	 * 文件状态良好，打开数据连接
	 */
	/* 
 	 * 获得文件(RETR)
	 * 此命令使服务器DTP传送指定路径内的文件复本到服务器或用户DTP.
	 */
	if(memcmp(g_session_pos->detail_tbl.request, "RETR", 4)  == 0) 		{

		if((memcmp(g_pkt_basic_info.data_addr, "125", 3) == 0) ||	\
			(memcmp(g_pkt_basic_info.data_addr, "150", 3) == 0))	{

			strcpy(g_session_pos->detail_tbl.file_name, 		\
				g_session_pos->detail_tbl.request + 5);
			g_session_pos->data_session_tbl.flag = EXIST_ENTRY;
			return(TRUE);
		}
		return(FALSE);
	}

	/* 
 	 * 保存(STOR)
	 * 此命令使服务器DTP接收数据连接上传送过来的数据，并将数据保存在服务器的文件中.
	 * 如果文件已存在，原文件将被覆盖.如果文件不存在，则新建文件. 
	 */
	if(memcmp(g_session_pos->detail_tbl.request, "STOR", 4) == 0)   	{

		if((memcmp(g_pkt_basic_info.data_addr, "150", 3) == 0) ||	\
			(memcmp(g_pkt_basic_info.data_addr, "125", 3) == 0))	{

			strcpy(g_session_pos->detail_tbl.file_name,		\
				g_session_pos->detail_tbl.request + 5);
			g_session_pos->data_session_tbl.flag = EXIST_ENTRY;
			return(TRUE);
		}
		return(FALSE);
	}
	return(FALSE);
}


int analysis_cmd_user()
{
	int len, n;
	EA_EVENT_AUTH_TBL event_auth_tbl;
	struct in_addr dst_addr;

	char log_detail[MAX_LOG_DETAIL_SIZE+1];
	char warn_des[MAX_ALARM_DES_SIZE+1];

	memset(&event_auth_tbl, 0x00, EA_EVENT_AUTH_TBL_SIZE);

	if(memcmp(g_session_pos->detail_tbl.request, "USER", 4) == 0) { /* EQ */

		/* 
 		 *  get login user name, 
 		 *  so save to g_session_pos->detail_tbl.login_user.
 		 */

		len = strlen(g_session_pos->detail_tbl.request);
		if(len - 5 > 0) {
			memcpy(g_session_pos->detail_tbl.login_user, 	\
				g_session_pos->detail_tbl.request + 5, len - 5);
			g_session_pos->detail_tbl.login_user[len -5] = '\0';
		}
		return(TRUE);
	} else if(memcmp(g_session_pos->detail_tbl.request, "PASS", 4) == 0) {

		/* fill data type event_auth_tbl */
		if(memcmp(g_pkt_basic_info.data_addr, "230", 3) == 0)
			event_auth_tbl.result = RESULT_SUCCESS;
		else
			event_auth_tbl.result = RESULT_FAIL;
		
		event_auth_tbl.session_id     = g_session_pos->session_id;
		event_auth_tbl.event_seq      = g_session_pos->detail_tbl.event_seq;
		event_auth_tbl.p_type_id      = PRO_TYPE_FTP;
		event_auth_tbl.event_type     = EVENT_LOGIN;
		
		event_auth_tbl.event_time     = g_session_pos->detail_tbl.cur_cmd_time;
		event_auth_tbl.analysis_start = g_session_pos->detail_tbl.cur_analysis_index;
		event_auth_tbl.analysis_end   = g_session_pos->detail_tbl.cur_analysis_index;

		
		strcpy(event_auth_tbl.user_name, g_session_pos->detail_tbl.login_user);
		event_auth_tbl.object_name[0] = '\0';
		dst_addr.s_addr               = g_session_pos->dst_ip;
		sprintf(event_auth_tbl.event_des, "ÓÃ»§%sÊ¹ÓÃÕËºÅ%sµÇÂ¼%sµÄFTP·þÎñÆ÷", 	\
			g_session_pos->usr_info.src_usrname, event_auth_tbl.user_name, 	\
			inet_ntoa(dst_addr));		
		write_event_auth_db_tbl(&event_auth_tbl, "ftp"); /* write to db*/
		g_session_pos->login_flag = 1;
		
		if(search_in_account_list(event_auth_tbl.user_name, g_itf_par_info.authorize_account_id,\
			g_session_pos->eaudit_authorize_info.authorize_account_content_addr,\
			g_session_pos->eaudit_authorize_info.account_index))
		{
			n = snprintf(warn_des, MAX_ALARM_DES_SIZE+1, "ÓÃ»§%sÎÞÈ¨Ê¹ÓÃÕÊºÅ%sµÇÂ¼", \
				g_session_pos->usr_info.src_usrname, event_auth_tbl.user_name);
			warn_des[n] = 0x00;
			n = snprintf(log_detail, MAX_LOG_DETAIL_SIZE+1, "ÓÃ»§%sÎÞÈ¨Ê¹ÓÃÕÊºÅ%sµÇÂ¼", \
				g_session_pos->usr_info.src_usrname, event_auth_tbl.user_name);
			log_detail[n] = 0x00;
			handle_ultravires(g_session_pos, "login", log_detail, warn_des, ACCOUNT);
		}

		if(search_in_custom_list(event_auth_tbl.user_name, g_itf_par_info.authorize_custom_id,\
			g_session_pos->eaudit_authorize_info.authorize_custom_content_addr, \
			g_session_pos->eaudit_authorize_info.custom_made_index, FULL_MATCH_MODE))
		{
			n = snprintf(warn_des, MAX_ALARM_DES_SIZE+1, "ÓÃ»§%sÎÞÈ¨Ê¹ÓÃÕÊºÅ%sµÇÂ¼", \
				g_session_pos->usr_info.src_usrname, event_auth_tbl.user_name);
			warn_des[n] = 0x00;
			n = snprintf(log_detail, MAX_LOG_DETAIL_SIZE+1, "ÓÃ»§%sÎÞÈ¨Ê¹ÓÃÕÊºÅ%sµÇÂ¼", \
				g_session_pos->usr_info.src_usrname, event_auth_tbl.user_name);
			log_detail[n] = 0x00;
			handle_ultravires(g_session_pos, event_auth_tbl.user_name, log_detail, warn_des, CUSTOM);
		}
		
		return(TRUE);

	}
	return(FALSE);
}


int analysis_cmd_pwd()
{
	unsigned char*	p = NULL;
	int		i;

	/*
	 * 打印工作目录(PWD)
	 * 在响应是返回当前工作目录.
	 */
	if(memcmp(g_session_pos->detail_tbl.request, "PWD", 3) == 0) {

		if(memcmp(g_pkt_basic_info.data_addr, "257", 3) == 0){
			p = g_pkt_basic_info.data_addr + 5;
			i = 0;
			while(*p != '\"' && i < g_pkt_basic_info.data_len - 7)
				g_session_pos->detail_tbl.cur_dir[i++] = *p++;

			g_session_pos->detail_tbl.cur_dir[i] = '\0';
		}
		return(TRUE);
	}
	return(FALSE);
}



int analysis_cmd_cwd()
{
	unsigned char*	p = NULL;
	int		i;
	/*
	 * 改变工作目录(CWD)
	 * 此命令使用户可以在不同的目录或数据集下工作而不用改变它的登录或帐户信息.	
	 * 传输参数也不变.参数一般是目录名或与系统相关的文件集合.
	 */
	if(memcmp(g_session_pos->detail_tbl.request, "CWD", 3) == 0) {

		if(memcmp(g_pkt_basic_info.data_addr, "250", 3) == 0){
			p = g_pkt_basic_info.data_addr;
			while(*p != '\n') {
				if(*p == '/')	break;
				p++;
			}
			if(*p == '/') {
				i = 0;
				while(*p != '\n' && *p != '\r')
					g_session_pos->detail_tbl.cur_dir[i++] = *p++;

				g_session_pos->detail_tbl.cur_dir[i] = '\0';

			} else printf("response packet formate diffient.\n");
		}
		return(TRUE);
	}
	return(FALSE);
}


int analysis_cmd_size()
{
	if(memcmp(g_session_pos->detail_tbl.request, "SIZE", 4) == 0) {

		if(memcmp(g_pkt_basic_info.data_addr, "213", 3) == 0) {
			strcpy(g_session_pos->detail_tbl.file_name,		\
				g_session_pos->detail_tbl.request + 5);
			g_session_pos->detail_tbl.file_size = strtol(		\
				(char*)g_pkt_basic_info.data_addr + 4, NULL, 10);
		}
		return(TRUE);
	}
	return(FALSE);
}


/* GET REMOVE COMMAND CONTEXT OF FTP, THEN WRITE THIS TO DATABASE */
int analysis_cmd_dele()
{
	EA_EVENT_REMOVE_TBL	ea_event_remove_tbl;

	memset(&ea_event_remove_tbl, 0x00, EA_EVENT_REMOVE_TBL_SIZE);
	
	if(memcmp(g_session_pos->detail_tbl.request, "DELE", 4) == 0) {

		ea_event_remove_tbl.session_id = g_session_pos->session_id;
		ea_event_remove_tbl.event_seq  = g_session_pos->detail_tbl.event_seq;
		ea_event_remove_tbl.p_type_id  = PRO_TYPE_FTP;
		ea_event_remove_tbl.event_type = EVENT_REMOVE;
		
		if(memcmp(g_pkt_basic_info.data_addr, "250", 3) == 0)
			ea_event_remove_tbl.result = RESULT_SUCCESS;
		else
			ea_event_remove_tbl.result = RESULT_FAIL;

		ea_event_remove_tbl.event_time 	   = 				\
				g_session_pos->detail_tbl.cur_cmd_time;
		ea_event_remove_tbl.analysis_start = 				\
				g_session_pos->detail_tbl.cur_analysis_index;
		ea_event_remove_tbl.analysis_end   = 				\
				g_session_pos->detail_tbl.cur_analysis_index;

		strcpy(ea_event_remove_tbl.object_name, g_session_pos->detail_tbl.cur_dir);
		strcat(ea_event_remove_tbl.object_name, "/");
		strcat(ea_event_remove_tbl.object_name, g_session_pos->detail_tbl.request + 5);

		sprintf(ea_event_remove_tbl.event_des, "É¾³ýÎÄ¼þ%s", ea_event_remove_tbl.object_name);
		write_event_remove_db_tbl(&ea_event_remove_tbl); /* write to db */

		return(TRUE);
	}
	return(FALSE);
}


int analysis_cmd_rnfr()
{
	if(memcmp(g_session_pos->detail_tbl.request, "RNFR", 4) == 0) {
	/* 重命名(RNFR)
	 * 这个命令和我们在其它操作系统中使用的一样, 只不过后面要跟
	 * "rename to"指定新的文件名.
	 */
		if(memcmp(g_pkt_basic_info.data_addr, "350", 3) == 0) {

			strcpy(g_session_pos->detail_tbl.rename_from, 		\
				g_session_pos->detail_tbl.cur_dir);
			strcat(g_session_pos->detail_tbl.rename_from, "/");
			strcat(g_session_pos->detail_tbl.rename_from, 		\
				g_session_pos->detail_tbl.request + 5);
			
			g_session_pos->detail_tbl.start_anlaysis_index  = 	\
				g_session_pos->detail_tbl.cur_analysis_index;
			g_session_pos->detail_tbl.start_cmd_time 	=	\
				g_session_pos->detail_tbl.cur_cmd_time;
			
		}
		return(TRUE);
	}

	return(FALSE);
}

int analysis_cmd_rnto()
{
	EA_EVENT_RENAME_TBL ea_event_rename_tbl;

	memset(&ea_event_rename_tbl, 0x00, EA_EVENT_RENAME_TBL_SIZE);
	/*
   	 * 重命名为(RNTO)
	 * 此命令和上面的命令共同完成对文件的重命名.
 	 */
	if(memcmp(g_session_pos->detail_tbl.request, "RNTO", 4) == 0)
	{
		ea_event_rename_tbl.session_id = g_session_pos->session_id;
		ea_event_rename_tbl.event_seq = g_session_pos->detail_tbl.event_seq;
		ea_event_rename_tbl.p_type_id = PRO_TYPE_FTP;
		ea_event_rename_tbl.event_type = EVENT_RENAME;
		
		if(memcmp(g_pkt_basic_info.data_addr, "250", 3) == 0)
		{
			ea_event_rename_tbl.result = RESULT_SUCCESS;
		}else
		{
			ea_event_rename_tbl.result = RESULT_FAIL;
		}
		ea_event_rename_tbl.event_time = g_session_pos->detail_tbl.start_cmd_time;
		ea_event_rename_tbl.analysis_start = g_session_pos->detail_tbl.start_anlaysis_index;
		ea_event_rename_tbl.analysis_end = g_session_pos->detail_tbl.cur_analysis_index;
		strcpy(ea_event_rename_tbl.object_src, g_session_pos->detail_tbl.rename_from);
		
		strcpy(ea_event_rename_tbl.object_dst, g_session_pos->detail_tbl.cur_dir);
		strcat(ea_event_rename_tbl.object_dst, "/");
		strcat(ea_event_rename_tbl.object_dst, g_session_pos->detail_tbl.request + 5);

		sprintf(ea_event_rename_tbl.event_des, "ÎÄ¼þ%s±»ÖØÃüÃûÎª%s", ea_event_rename_tbl.object_src, ea_event_rename_tbl.object_dst);
		write_event_rename_db_tbl(&ea_event_rename_tbl); /* write to db */

		return TRUE;
	}
	return FALSE;
}


int analysis_cmd_port()
{
	char addr[16];
	char* p = NULL;
	char port1[4];
	char port2[4];
	int i;
	int j;
	struct in_addr in;

	
	if(memcmp(g_session_pos->detail_tbl.request, "PORT", 4) == 0)
	{
		if(memcmp(g_pkt_basic_info.data_addr, "200", 3) == 0)
		{
			p = g_session_pos->detail_tbl.request + 5;
			i = 0;
			j = 0;
			while(i < 4)
			{
				if(*p == ',')
				{
					addr[j++] = '.';
					i++;
				}else
				{
					addr[j++] = *p;
				}
				p++;
			}
			addr[j-1] = '\0';
			
//			p++;
			i = 0;
			while(*p != ',')
			{
				port1[i++] = *p++;
			}
			port1[i] = '\0';
			
			p++;
			i = 0;
			while(*p !='\0')
			{
				port2[i++] = *p++;
			}
			port2[i] = '\0';


			if(inet_aton(addr, &in) != 0)
			{
				g_session_pos->data_session_tbl.src_ip = in.s_addr;
				g_session_pos->data_session_tbl.src_port = htons((unsigned short)(strtoul(port1, NULL, 10) * 256 + strtoul(port2, NULL, 10)));
				g_session_pos->data_session_tbl.state = STATE_PORT;
			}

		}
		return TRUE;
	}
	return FALSE;
}

int analysis_cmd_pasv()
{
	char addr[16];
	char* p = NULL;
	char port1[4];
	char port2[4];
	int i;
	int j;
	struct in_addr in;
	
	if(memcmp(g_session_pos->detail_tbl.request, "PASV", 4) == 0)
	{
		if(memcmp(g_pkt_basic_info.data_addr, "227", 3) == 0)
		{
			if((p = strchr((char*)g_pkt_basic_info.data_addr, '(')) != NULL)
			{
				p++;
				
				i = 0;
				j = 0;
				while(i < 4)
				{
					if(*p == ',')
					{
						addr[j++] = '.';
						i++;
					}else
					{
						addr[j++] = *p;
					}
					p++;
				}
				addr[j-1] = '\0';
				
//				p++;
				i = 0;
				while(*p != ',')
				{
					port1[i++] = *p++;
				}
				port1[i] = '\0';
				
				p++;
				i = 0;
				while(*p != ')')
				{
					port2[i++] = *p++;
				}
				port2[i] = '\0';


				if(inet_aton(addr, &in) != 0)
				{
					g_session_pos->data_session_tbl.dst_ip = in.s_addr;
					g_session_pos->data_session_tbl.dst_port = htons((unsigned short)(strtoul(port1, NULL, 10) * 256 + strtoul(port2, NULL, 10)));
					g_session_pos->data_session_tbl.state = STATE_PASV;
				}
			}
		}
		return TRUE;
	}
	return FALSE;
}


int analysis_cmd_retr()  //down
{

	EA_EVENT_DOWNLOAD_TBL ea_event_download_tbl;
	char* p = NULL;
	char* p1 = NULL;
	struct in_addr dst_addr;

	char log_detail[MAX_LOG_DETAIL_SIZE+1];
	char warn_des[MAX_ALARM_DES_SIZE+1];
	int n;
	
	memset(&ea_event_download_tbl, 0x00, EA_EVENT_DOWNLOAD_TBL_SIZE);
	
	if(memcmp(g_session_pos->detail_tbl.request, "RETR", 4) == 0)
	{
		ea_event_download_tbl.session_id = g_session_pos->session_id;
		ea_event_download_tbl.event_seq = g_session_pos->detail_tbl.event_seq;
		ea_event_download_tbl.p_type_id = PRO_TYPE_FTP;
		ea_event_download_tbl.event_type = EVENT_DOWNLOAD;
		if(memcmp(g_pkt_basic_info.data_addr, "226", 3) == 0)
		{
			ea_event_download_tbl.result = RESULT_SUCCESS;
		}else
		{
			ea_event_download_tbl.result = RESULT_FAIL;
		}
		ea_event_download_tbl.event_time = g_session_pos->detail_tbl.cur_cmd_time;
		ea_event_download_tbl.analysis_start = g_session_pos->detail_tbl.cur_analysis_index;
		ea_event_download_tbl.analysis_end = g_session_pos->detail_tbl.cur_analysis_index;
		
		strcpy(ea_event_download_tbl.object_src, g_session_pos->detail_tbl.cur_dir);
		strcat(ea_event_download_tbl.object_src, "/");
		strcat(ea_event_download_tbl.object_src, g_session_pos->detail_tbl.request + 5);
		ea_event_download_tbl.object_dst[0] = '\0';
		if(strcmp(g_session_pos->detail_tbl.file_name, g_session_pos->detail_tbl.request+5) != 0)
		{
			g_session_pos->detail_tbl.file_size = 0;
			strcpy(g_session_pos->detail_tbl.file_name, g_session_pos->detail_tbl.request+5);

		}
		if((p = strrchr(g_session_pos->detail_tbl.request+5, '/')) != NULL)
		{
			p++;
		}else
		{
			p = g_session_pos->detail_tbl.request+5;
		}
		if(*p != '\0' && (p1 = strrchr(p, '.')) != NULL)
		{
			strcpy(g_session_pos->detail_tbl.file_suffix, p1++);
		}
		
		ea_event_download_tbl.object_size = g_session_pos->detail_tbl.file_size;
		
		dst_addr.s_addr = g_session_pos->dst_ip;


		if(strlen(g_session_pos->detail_tbl.cur_dir) > 0)
		{
			sprintf(ea_event_download_tbl.event_des, "ÏÂÔØ%sÉÏÄ¿Â¼%sÏÂµÄÎÄ¼þ%s", inet_ntoa(dst_addr), g_session_pos->detail_tbl.cur_dir, g_session_pos->detail_tbl.request+5);
		}else
		{
			sprintf(ea_event_download_tbl.event_des, "ÏÂÔØ%sÉÏµÄÎÄ¼þ%s", inet_ntoa(dst_addr), g_session_pos->detail_tbl.request+5);
		}
		write_event_download_db_tbl(&ea_event_download_tbl);


		if(search_in_custom_list(g_session_pos->detail_tbl.file_name, g_itf_par_info.authorize_custom_id, \
			g_session_pos->eaudit_authorize_info.authorize_custom_content_addr,\
			g_session_pos->eaudit_authorize_info.custom_made_index, FULL_MATCH_MODE))
		{
			n = snprintf(warn_des, MAX_ALARM_DES_SIZE+1, "ÓÃ»§%sÎÞÈ¨ÏÂÔØÎÄ¼þ%s", \
				g_session_pos->usr_info.src_usrname,g_session_pos->detail_tbl.file_name);
			warn_des[n] = 0x00;
			n = snprintf(log_detail, MAX_LOG_DETAIL_SIZE+1, "ÓÃ»§%sÎÞÈ¨ÏÂÔØÎÄ¼þ%s", \
				g_session_pos->usr_info.src_usrname,g_session_pos->detail_tbl.file_name);
			log_detail[n] = 0x00;
			handle_ultravires(g_session_pos, g_session_pos->detail_tbl.file_name, log_detail, warn_des, CUSTOM);
		}

		return TRUE;
	}
	return FALSE;
}


int analysis_cmd_stor()
{
	EA_EVENT_UPLOAD_TBL ea_event_upload_tbl;
	char* p = NULL;
	char* p1 = NULL;
	struct in_addr dst_addr;
	char str_num[16];
	int i;
	char* succ_key = "Transfer complete.";
	
	char log_detail[MAX_LOG_DETAIL_SIZE+1];
	char warn_des[MAX_ALARM_DES_SIZE+1];
	int n;
	
	memset(&ea_event_upload_tbl, 0x00, EA_EVENT_UPLOAD_TBL_SIZE);
	
	if(memcmp(g_session_pos->detail_tbl.request, "STOR", 4) == 0)
	{

		ea_event_upload_tbl.session_id = g_session_pos->session_id;
		ea_event_upload_tbl.event_seq = g_session_pos->detail_tbl.event_seq;
		ea_event_upload_tbl.p_type_id = PRO_TYPE_FTP;
		ea_event_upload_tbl.event_type = EVENT_UPLOAD;
		if(memcmp(g_pkt_basic_info.data_addr, "226", 3) == 0)
		{
			p = (char*)g_pkt_basic_info.data_addr + strlen(succ_key) + 5;
			i = 0;
			while(*p != ' ' && *p != '\r')
			{
				if(*p == ',')
				{
					p++;
				}else if(*p >= '0' && *p <= '9')
				{
					str_num[i++] = *p++;
				}else
				{
					break;
				}
			}
			str_num[i] = '\0';

			if(i > 0)
			{
				g_session_pos->detail_tbl.file_size = strtol(str_num, NULL, 10);
			}else
			{
				g_session_pos->detail_tbl.file_size = 0;
			}
			
			ea_event_upload_tbl.result = RESULT_SUCCESS;
		}else
		{
			g_session_pos->detail_tbl.file_size = 0;
			
			ea_event_upload_tbl.result = RESULT_FAIL;
		}
		ea_event_upload_tbl.event_time = g_session_pos->detail_tbl.cur_cmd_time;
		ea_event_upload_tbl.analysis_start = g_session_pos->detail_tbl.cur_analysis_index;
		ea_event_upload_tbl.analysis_end = g_session_pos->detail_tbl.cur_analysis_index;
		
		strcpy(ea_event_upload_tbl.object_dst, g_session_pos->detail_tbl.cur_dir);
		strcat(ea_event_upload_tbl.object_dst, "/");
		strcat(ea_event_upload_tbl.object_dst, g_session_pos->detail_tbl.request + 5);
		
		strcpy(g_session_pos->detail_tbl.file_name, g_session_pos->detail_tbl.request+5);

		if((p = strrchr(g_session_pos->detail_tbl.request+5, '/')) != NULL)
		{
			p++;
		}else
		{
			p = g_session_pos->detail_tbl.request+5;
		}
		if(*p != '\0' && (p1 = strrchr(p, '.')) != NULL)
		{
			strcpy(g_session_pos->detail_tbl.file_suffix, p1++);
		}
		
		ea_event_upload_tbl.object_size = g_session_pos->detail_tbl.file_size;

		dst_addr.s_addr = g_session_pos->dst_ip;

		if(strlen(g_session_pos->detail_tbl.cur_dir) > 0)
		{
			sprintf(ea_event_upload_tbl.event_des, "ÉÏ´«±¾µØÎÄ¼þ%sµ½%sµÄ%sÄ¿Â¼", g_session_pos->detail_tbl.request + 5, inet_ntoa(dst_addr), g_session_pos->detail_tbl.cur_dir);
		}else
		{
			sprintf(ea_event_upload_tbl.event_des, "ÉÏ´«±¾µØÎÄ¼þ%sµ½%s", g_session_pos->detail_tbl.request + 5, inet_ntoa(dst_addr));
		}

		write_event_upload_db_tbl(&ea_event_upload_tbl);

		if(search_in_custom_list(g_session_pos->detail_tbl.file_name, g_itf_par_info.authorize_custom_id, \
			g_session_pos->eaudit_authorize_info.authorize_custom_content_addr,\
			g_session_pos->eaudit_authorize_info.custom_made_index, FULL_MATCH_MODE))
		{
			n = snprintf(warn_des, MAX_ALARM_DES_SIZE+1, "ÓÃ»§%sÎÞÈ¨ÉÏ´«ÎÄ¼þ%s", \
				g_session_pos->usr_info.src_usrname,g_session_pos->detail_tbl.file_name);
			warn_des[n] = 0x00;
			n = snprintf(log_detail, MAX_LOG_DETAIL_SIZE+1, "ÓÃ»§%sÎÞÈ¨ÉÏ´«ÎÄ¼þ%s", \
				g_session_pos->usr_info.src_usrname,g_session_pos->detail_tbl.file_name);
			log_detail[n] = 0x00;
			handle_ultravires(g_session_pos, g_session_pos->detail_tbl.file_name, log_detail, warn_des, CUSTOM);
		}

		return TRUE;
	}
	return FALSE;
}

int analysis_cmd_quit()
{
	struct in_addr dst_addr;
	
	EA_EVENT_AUTH_TBL event_auth_tbl;
	if(memcmp(g_session_pos->detail_tbl.request, "QUIT", 4) == 0)
	{

		if(g_session_pos->login_flag == 1)
		{
			event_auth_tbl.session_id = g_session_pos->session_id;
			event_auth_tbl.event_seq = g_session_pos->detail_tbl.event_seq;
			event_auth_tbl.p_type_id = PRO_TYPE_FTP;
			event_auth_tbl.event_type = EVENT_LOGOUT;

			if(memcmp(g_pkt_basic_info.data_addr, "221", 3) == 0)
			{
				event_auth_tbl.result = RESULT_SUCCESS;
			}else
			{
				event_auth_tbl.result = RESULT_FAIL;
			}
			event_auth_tbl.event_time = g_session_pos->detail_tbl.cur_cmd_time;
			event_auth_tbl.analysis_start = g_session_pos->detail_tbl.cur_analysis_index;
			event_auth_tbl.analysis_end = g_session_pos->detail_tbl.cur_analysis_index;
			strcpy(event_auth_tbl.user_name, g_session_pos->detail_tbl.login_user);
			
			dst_addr.s_addr = g_session_pos->dst_ip;
			sprintf(event_auth_tbl.event_des, "Ê¹ÓÃÕËºÅ%sµÇÂ¼%sµÄFTP·þÎñÆ÷µÄÓÃ»§%sÍË³ö", event_auth_tbl.user_name, inet_ntoa(dst_addr), g_session_pos->usr_info.src_usrname);		
			
			event_auth_tbl.object_name[0] = '\0';

			write_event_auth_db_tbl(&event_auth_tbl, "ftp"); /* write to db */
			g_session_pos->login_flag = 0;
		}
		return TRUE;
	}
	return FALSE;

}


int analysis_cmd_opts()
{
	if(strncasecmp(g_session_pos->detail_tbl.request, "opts", 4) == 0)
	{
		if(strncasecmp(g_session_pos->detail_tbl.request + 5, "utf8", 4) == 0 && strncasecmp(g_session_pos->detail_tbl.request + 10, "on", 2) == 0)
		{
			if(memcmp(g_pkt_basic_info.data_addr, "200", 3) == 0)
			{
				g_session_pos->utf8_flag = 1;
				return TRUE;
			}
		}
	}
	return FALSE;
}


void ftp_data_session_process()
{
	if(g_session_pos->detail_tbl.fd == -1) {
		snprintf(g_session_pos->detail_tbl.save_path,	\
			 MAX_FILE_PATH_SIZE + 1,		\
			 "%s/FTP/(%lu_%lu)%s", FILE_DATA_PATH,	\
			 g_session_pos->session_id,		\	
			 g_data_session_pos->data_session_id, 	\
			 g_session_pos->detail_tbl.file_name );
		g_session_pos->detail_tbl.fd = open(g_session_pos->detail_tbl.save_path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
	}

	if(g_session_pos->detail_tbl.fd >= 0)
	{
		write(g_session_pos->detail_tbl.fd, g_pkt_basic_info.data_addr, g_pkt_basic_info.data_len);
		g_session_pos->data_session_tbl.data_len += g_pkt_basic_info.data_len;
	}
}


void search_in_cmd_tbl(
	char*	cmd_name
	)
{ 
	int		i;

	g_cmd_pos  = NULL;

	for(i = 0; i < g_cmd_tbl_sum; i++) {

		if(strcasecmp(cmd_name, g_cmd_tbl_id[i].cmd_name) == 0) {
			sprintf(cmd_name, "%s", g_cmd_tbl_id[i].cmd_name);
			g_cmd_pos = g_cmd_tbl_id + i;
			break;
		}
	}
}


/* rewrite the f**king source code .*/
int set_pkt_basic_info() 
{

	NET_HDR net_hdr;

	g_pkt_basic_info.ts 	  = g_mmap_file_info.libpcap_hdr_id->ts;
	g_pkt_basic_info.pkt_len  = g_mmap_file_info.libpcap_hdr_id->cap_len;
	g_pkt_basic_info.pkt_addr = g_mmap_file_info.cur_pos; 
	
	g_mmap_file_info.next_pkt_pos = g_pkt_basic_info.pkt_addr + g_pkt_basic_info.pkt_len;

	if(decode_net_pkt(&net_hdr, &(g_mmap_file_info.cur_pos), g_pkt_basic_info.pkt_len) == ERR)
	{
		return ERR;
	}

	if(net_hdr.ether_hdr_id != NULL)
	{
		memcpy(g_pkt_basic_info.dst_mac, net_hdr.ether_hdr_id->ether_dhost, MAC_ADDRESS_SIZE);
		memcpy(g_pkt_basic_info.src_mac, net_hdr.ether_hdr_id->ether_shost, MAC_ADDRESS_SIZE);	
	}else
	{
		return ERR;
	}

	if(net_hdr.ip_hdr_id != NULL)
	{
		g_pkt_basic_info.data_len = ntohs(net_hdr.ip_hdr_id->ip_len);
    		g_pkt_basic_info.ip_hdr_len = IP_HL(net_hdr.ip_hdr_id) << 2;
    		g_pkt_basic_info.ip_proto = net_hdr.ip_hdr_id->ip_p;
		g_pkt_basic_info.src_ip = net_hdr.ip_hdr_id->ip_src.s_addr;
		g_pkt_basic_info.dst_ip = net_hdr.ip_hdr_id->ip_dst.s_addr;
	}else
	{
		return ERR;
	}

	if(net_hdr.tcp_hdr_id != NULL)
	{
		g_pkt_basic_info.tcp_hdr_len=TH_OFF(net_hdr.tcp_hdr_id) << 2;
		g_pkt_basic_info.th_seq = net_hdr.tcp_hdr_id->th_seq;
		g_pkt_basic_info.th_ack = net_hdr.tcp_hdr_id->th_ack;
		g_pkt_basic_info.th_flags = net_hdr.tcp_hdr_id->th_flags;
		g_pkt_basic_info.th_sport = net_hdr.tcp_hdr_id->th_sport;
		g_pkt_basic_info.th_dport = net_hdr.tcp_hdr_id->th_dport;
		g_pkt_basic_info.data_len -=(g_pkt_basic_info.ip_hdr_len+g_pkt_basic_info.tcp_hdr_len);
		g_pkt_basic_info.data_addr = g_pkt_basic_info.pkt_addr + ETHERNET_HEADER_LEN + g_pkt_basic_info.ip_hdr_len + g_pkt_basic_info.tcp_hdr_len;
	}else if(net_hdr.udp_hdr_id!= NULL)
	{
		g_mmap_file_info.next_pkt_pos = g_pkt_basic_info.pkt_addr + g_pkt_basic_info.pkt_len;
		return ERR;
	}
	return OK;
}


/*
 *	init session table.
 */
void initialize_tbls()
{
	if(g_max_supported_session == 0)
	{
		error("max_supported_session is invalid.");
		exit(EXIT_FAILURE);
	}

	if((g_session_tbl_id = (EA_SESSION_TBL_ID)calloc(g_max_supported_session, EA_SESSION_TBL_SIZE)) == NULL)
	{
		error("allocate session table failed.");
		exit(EXIT_FAILURE);
	}

	if((g_conn_times_tbl_id = (EA_CONN_TIMES_TBL_ID)calloc(g_max_supported_session, EA_CONN_TIMES_TBL_SIZE)) == NULL)
	{
		error("allocate connection times tbl failed.");
		exit(EXIT_FAILURE);
	}
	
	raw_socket = RawSocket();
	raw_socket_arp = raw_arp_socket();

	DEBUG("Initianlze Completed.\n");
}

void init_global_var()
{
	/* initialize all global variable for use by ftp analysis module */
	time_t t;
	g_interval_time = 60;
	g_data_interval_time = 120;
	g_max_supported_session = 100;
	
	g_session_tbl_sum = 0;
	g_valid_ds = FALSE;
	g_session_pos = NULL;
	g_data_session_pos = NULL;
	g_supported_cmd_num = MAX_CMD_TBL_NUM;
	time(&t);
	g_old_time = *localtime(&t);
	get_current_date(g_cur_date, 32);	/* where is get_current_date? */
}

	void
set_callback_fun_set(
	CALLBACK_FUNC_SET_ID	callback_func_set_id
	)
{
	
	callback_func_set_id->analyze_fptr 	=ftp_analyze;
	callback_func_set_id->flush_fpt         =write_abnormal_session_into_db;
	callback_func_set_id->force_into_db_fptr=force_sessions_into_db;
}


	void
monitor_signal_handler(
	int		signum,
	siginfo_t*	siginfo,
	void*		arg
	)
{
	g_tick_time++;
	if(monitor_info->conn_interval) {

		if(g_tick_time % monitor_info->conn_interval == 0)
			g_check_conn_flag = 1;
	}

	if(monitor_info->flux_interval) {

		if(g_tick_time % monitor_info->flux_interval == 0)
			g_check_flux_flag = 1;
	}
	
	if(g_tick_time >= (monitor_info->conn_interval  > 			\
			monitor_info->flux_interval?monitor_info->conn_interval:\
			monitor_info->flux_interval)) {
		g_tick_time = 0;
}


void add_conn_times()
{
	if(!monitor_info)
		return;

	unsigned long i;
	EA_CONN_TIMES_TBL_ID first_empty_conn_times_id = NULL;
	unsigned long conn_times_sum = 0;
	char find_flag = 0;

	for(i = 0; i<g_max_supported_session; i++)
	{
		if(g_conn_times_tbl_id[i].flag == EXIST_ENTRY)
		{
			if(g_conn_times_tbl_id[i].src_addr == g_session_pos->src_ip&&\
				g_conn_times_tbl_id[i].dst_addr == g_session_pos->dst_ip&&\
				g_conn_times_tbl_id[i].dst_port == g_session_pos->dst_port)
			{
				g_conn_times_tbl_id[i].conn_time++;
				find_flag = 1;
				break;
			}
			conn_times_sum++;
		}else if(first_empty_conn_times_id == NULL)
		{
			first_empty_conn_times_id = g_conn_times_tbl_id + i;
		}
		if(conn_times_sum >= g_conn_times_tbl_sum)
		{
			break;
		}
	}

	if(find_flag == 0)
	{
		if(first_empty_conn_times_id  == NULL)
		{
			if(conn_times_sum < g_max_supported_session)
			{
				first_empty_conn_times_id = g_conn_times_tbl_id + conn_times_sum;
			}else
			{
				error("The number of connection session exceed the max number.");
				return;
			}
		}

		first_empty_conn_times_id->flag = EXIST_ENTRY;
		memcpy(first_empty_conn_times_id->dst_mac, g_session_pos->dst_mac, MAC_ADDRESS_SIZE);
		memcpy(first_empty_conn_times_id->src_mac, g_session_pos->src_mac, MAC_ADDRESS_SIZE);
		first_empty_conn_times_id->dst_addr = g_session_pos->dst_ip;
		first_empty_conn_times_id->src_addr = g_session_pos->src_ip;
		first_empty_conn_times_id->dst_port = g_session_pos->dst_port;
		first_empty_conn_times_id->conn_time = 1;
		first_empty_conn_times_id->session_id = 0;
		first_empty_conn_times_id->usr_info = g_session_pos->usr_info;
		first_empty_conn_times_id->protected_res_no = g_session_pos->protected_res_no;
		memcpy(first_empty_conn_times_id->protected_res_name, g_session_pos->protected_res_name, MAX_RES_NAME_SIZE);

		
		g_conn_times_tbl_sum++;
	}
}


void monitor_conn_times()
{
	if(monitor_info)
	{
		if(monitor_info->conn_interval == 0)
			return;
	}
	else
		return;

	
	unsigned long i;
	char operater_type = 0x00;
	char log_detail[MAX_LOG_DETAIL_SIZE+1];
	char warn_des[MAX_ALARM_DES_SIZE+1];
	int n;
	EA_LOG_TBL log_tbl;
	EA_ALARM_TBL alarm_tbl;
	struct in_addr dst_addr;

	char* pro_name = "ftp";	

	if(g_check_conn_flag == 1)
	{
		for(i =0; i<g_max_supported_session; i++)
		{
			if(g_conn_times_tbl_id[i].flag == EXIST_ENTRY)
			{
				if(g_conn_times_tbl_id[i].conn_time >= monitor_info->conn_threshold)
				{					
					memset(&log_tbl, 0x00, EA_LOG_TBL_SIZE);

					log_tbl.logdate_time = g_pkt_basic_info.ts;
					log_tbl.logdetail = log_detail;
					log_tbl.model_name = g_model_name;
					log_tbl.p_type_id = PRO_TYPE_FTP;
					log_tbl.operater_type = &operater_type;
					dst_addr.s_addr = g_conn_times_tbl_id[i].dst_addr;

					n = sprintf(log_detail, "ÓÃ»§%sÔÚ%dÃëÄÚÁ¬½Ó%s:%d %d´Î,³¬¹ý×î´óÏÞ¶¨Öµ%d´Î", \
						g_conn_times_tbl_id[i].usr_info.src_usrname, monitor_info->conn_interval, inet_ntoa(dst_addr), \
						ntohs(g_conn_times_tbl_id[i].dst_port),g_conn_times_tbl_id[i].conn_time, monitor_info->conn_threshold);
					log_detail[n] = 0x00;
					log_tbl.logdetail = log_detail;

					
					if(monitor_info->not_authorize_event.log_flag)
						write_log_into_db(&log_tbl, g_cur_date);
					


					memset(&alarm_tbl, 0x00, EA_ALARM_TBL_SIZE);
					alarm_tbl.p_type_id = PRO_TYPE_FTP;
					alarm_tbl.pro_id = g_conn_times_tbl_id[i].protected_res_no;
					alarm_tbl.pro_name = g_conn_times_tbl_id[i].protected_res_name;
					alarm_tbl.model_name = g_model_name;
					alarm_tbl.src_mac = g_conn_times_tbl_id[i].src_mac;
					alarm_tbl.src_ip = g_conn_times_tbl_id[i].src_addr;
					alarm_tbl.dst_mac = g_conn_times_tbl_id[i].dst_mac;
					alarm_tbl.dst_ip = g_conn_times_tbl_id[i].dst_addr;
					alarm_tbl.src_username = g_conn_times_tbl_id[i].usr_info.src_usrname;
					alarm_tbl.usr_id = g_conn_times_tbl_id[i].usr_info.src_usrid;
					alarm_tbl.alarm_date = g_pkt_basic_info.ts;
					alarm_tbl.session_id = 0;
					
					n = sprintf(warn_des, "ÓÃ»§%sÔÚ%dÃëÄÚÁ¬½Ó%s:%d %d´Î,³¬¹ý×î´óÏÞ¶¨Öµ%d´Î", \
						g_conn_times_tbl_id[i].usr_info.src_usrname, monitor_info->conn_interval, inet_ntoa(dst_addr), \
						ntohs(g_conn_times_tbl_id[i].dst_port),g_conn_times_tbl_id[i].conn_time, monitor_info->conn_threshold);
					warn_des[n] = 0x00;						
					alarm_tbl.description = warn_des;
				

					if(monitor_info->not_authorize_event.warn_flag)
						write_alarm_into_db(&alarm_tbl, g_cur_date);


					if(monitor_info->not_authorize_event.block_flag)
						close_tcp(0, &alarm_tbl);


				
				}
				memset(g_conn_times_tbl_id+i, 0x00, EA_CONN_TIMES_TBL_SIZE);
				g_conn_times_tbl_sum--;
			}
			if(g_conn_times_tbl_sum <= 0)
			{
				break;
			}
		}

		g_check_conn_flag = 0;
	}

}


void monitor_flux()
{
	if(monitor_info)
	{
		if(monitor_info->flux_interval == 0)
			return;
	}
	else
		return;
	unsigned long i;
	unsigned long interval;
	int flux;
	unsigned long session_sum = 0;
	char operater_type = 0x00;
	char log_detail[MAX_LOG_DETAIL_SIZE+1];
	char warn_des[MAX_ALARM_DES_SIZE+1];
	int n;
	EA_LOG_TBL log_tbl;
	EA_ALARM_TBL alarm_tbl;
	
	if(g_check_flux_flag == 1)
	{
		for(i = 0; i < g_max_supported_session; i++)
		{
			if(g_session_tbl_id[i].flag == EXIST_ENTRY)
			{
				interval = abs(g_session_tbl_id[i].ts_end.tv_sec - g_session_tbl_id[i].ts_start.tv_sec);
				if(interval > 0)
				{
					flux = (g_session_tbl_id[i].flux) / interval;
				}
				else
				{
					flux = (g_session_tbl_id[i].flux);
				}
				g_session_tbl_id[i].flux = 0;
				
				if(flux >= monitor_info->flux_threshold)
				{
					memset(warn_des, 0x00, MAX_ALARM_DES_SIZE + 1);
					memset(log_detail, 0x00, MAX_LOG_DETAIL_SIZE + 1);
	
					n = sprintf(warn_des, "ÓÃ»§%s·ÃÎÊÍøÂçÁ÷Á¿Îª%d ³¬¹ýÉÏÏÞÖµ%d", \
						g_session_tbl_id[i].usr_info.src_usrname, flux, monitor_info->flux_threshold);
			//		warn_des[n] = 0x00;
					
					n = sprintf(log_detail, "ÓÃ»§%s·ÃÎÊÍøÂçÁ÷Á¿Îª%d ³¬¹ýÉÏÏÞÖµ%d", \
						g_session_tbl_id[i].usr_info.src_usrname, flux, monitor_info->flux_threshold);
			//		log_detail[n] = 0x00;

				
					memset(&log_tbl, 0x00, EA_LOG_TBL_SIZE);
					log_tbl.logdate_time = g_session_tbl_id[i].ts_end;
					log_tbl.logdetail = log_detail;
					log_tbl.model_name = g_model_name;
					log_tbl.p_type_id = g_session_tbl_id[i].pro_type_id;
					log_tbl.operater_type = operater_type;

					if(monitor_info->not_authorize_event.log_flag)
						write_log_into_db(&log_tbl, g_cur_date);


						
					memset(&alarm_tbl, 0x00, EA_ALARM_TBL_SIZE);
					alarm_tbl.session_id = 0;
					alarm_tbl.p_type_id = g_session_tbl_id[i].pro_type_id;
					alarm_tbl.pro_id = g_session_tbl_id[i].protected_res_no;
					alarm_tbl.pro_name = g_session_tbl_id[i].protected_res_name;
					alarm_tbl.model_name = g_model_name;
					alarm_tbl.src_mac = g_session_tbl_id[i].src_mac;
					alarm_tbl.src_ip = g_session_tbl_id[i].src_ip;
					alarm_tbl.dst_mac = g_session_tbl_id[i].dst_mac;
					alarm_tbl.dst_ip = g_session_tbl_id[i].dst_ip;
					alarm_tbl.src_username = g_session_tbl_id[i].usr_info.src_usrname;
					alarm_tbl.usr_id = g_session_tbl_id[i].usr_info.src_usrid;
					alarm_tbl.alarm_date = g_pkt_basic_info.ts;
					alarm_tbl.description = warn_des;

					if(monitor_info->not_authorize_event.warn_flag)
						write_alarm_into_db(&alarm_tbl, g_cur_date);
					
					
					if(monitor_info->not_authorize_event.block_flag)
						close_tcp(0, &alarm_tbl);


					
				}
				session_sum++;
			}
			if(session_sum >= g_session_tbl_sum)
			{
				break;
			}
		}

		g_check_flux_flag = 0;
	}
	
}


void display_pkt_basic_info(PKT_BASIC_INFO_ID pkt_basic_info_id)
{
	int i;
	struct in_addr tmp_addr;
	
//	if(pkt_basic_info_id->ip_proto != 0x11)		//+++
//		return;									//+++

	printf("mac_src:");
	for(i = 0; i < 6; i++)
		printf("%.2X-", pkt_basic_info_id->src_mac[i]);
	printf("\b\040\n");
	printf("mac_dst:");
	for(i = 0; i < 6; i++)
		printf("%.2X-", pkt_basic_info_id->dst_mac[i]);
	printf("\b\040\n");

	tmp_addr.s_addr = pkt_basic_info_id->src_ip;
	printf("src_ip:%s\n", inet_ntoa(tmp_addr));
	tmp_addr.s_addr = pkt_basic_info_id->dst_ip;
	printf("dst_ip:%s\n", inet_ntoa(tmp_addr));

	printf("dst_port:%u\n", ntohs(pkt_basic_info_id->th_dport));
	printf("src_port:%u\n", ntohs(pkt_basic_info_id->th_sport));
	printf("flag:%.2X\n", pkt_basic_info_id->th_flags);
	printf("\n\n\n");
}
void display_data(PKT_BASIC_INFO_ID pkt_basic_info_id)
{	int i;
	unsigned char* data_addr = pkt_basic_info_id->data_addr;
	printf("\n");
	for(i=0 ;i<pkt_basic_info_id->data_len; i++)
	{
	   if(data_addr[i] == '\n' || data_addr[i] == '\r')
	   {
			if(data_addr[i] == '\n')
				printf("\\n\n");
			else
				printf("\\r");
		}else if(data_addr[i] < 0x20 || data_addr[i]&0x80)
		{
			printf("\\%o", data_addr[i]);
		}
		else
		{
			printf("%c", data_addr[i]);
		}
	}
	printf("\n");
}


