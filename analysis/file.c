/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "file.h"
#include "debug.h"
#include "common.h"

/*
 * 根据结构EA_ITF_PAR_INFO_ID的内容信息(报文的存放目录), 把对应
 * 的报文文件通过mmap系统调用影射到内存中, 然后再根据成功影射
 * 的内存内容来填充MMAP_FILE_INFO_ID结构体
 */
void read_mmap_file(
	EA_ITF_PAR_INFO_ID	itf_par_info_id,
	MMAP_FILE_INFO_ID	mmap_file_info_id,
	CALLBACK_FUNC_SET_ID	callback_func_set_id
	)
{

	char	file_path[MAX_FILE_PATH_SIZE + 1];
	char	file_newpath[MAX_FILE_PATH_SIZE + 1];
	unsigned long	file_no;
	int	read_times, fileno_fd, sec_elapsed = 0;
	
	while(TRUE) {
		if((fileno_fd = open_fileno_file(itf_par_info_id)) == ERR) {
			fprintf(stderr, "open fileno file error.\n");
			sleep(MAX_DELAY_SEC);
			continue;
		}
		if((file_no = read_file_no(fileno_fd))== ERR) {
			fprintf(stderr, "read file no error.\n");
			close(fileno_fd);
			sleep(MAX_DELAY_SEC);
			continue;
		}

		/* example: /data/FTP/1.pdat */
		snprintf(file_path,MAX_FILE_PATH_SIZE + 1, 			\
			 "%s/%s/%ld%s",			 			\
			 itf_par_info_id->pkt_file_dir, 			\
			 itf_par_info_id->protocol_name,			\
			 file_no,PKT_FILE_SUFFIX);

		if(file_is_exist(file_path) == FILE_EXIST) {

			/* example: /data/FTP/1.tmp */
			snprintf(file_newpath, 					\
				 MAX_FILE_PATH_SIZE + 1, 			\
				 "%s/%s/%ld%s",					\
				 itf_par_info_id->pkt_file_dir, 		\
				 itf_par_info_id->protocol_name,		\
				 file_no, PKT_FILE_TMP_SUFFIX);
			read_times = 0;
			
			/* call the "mmap" */
			while(read_times <= MAX_RPT_RD_MMAP_FILE_TIMES) {
				if(OK == mmap_file(itf_par_info_id, 
					 mmap_file_info_id, file_path)) break;

				read_times++;
				sleep(MAX_DELAY_SEC);
			}
			
			mmap_file_info_id->file_no = file_no;
			file_no = inc_fileno(itf_par_info_id, file_no);

			if(set_file_no(fileno_fd, file_no) == ERR) {
				fprintf(stderr, "set file no error.\n");
				close(fileno_fd);
				sleep(MAX_DELAY_SEC);
				continue;
			}
			close(fileno_fd);

			if(read_times > MAX_RPT_RD_MMAP_FILE_TIMES) {

				rename(file_path, file_newpath);
				continue;
			} else return;

		} else {
			file_no = inc_fileno(itf_par_info_id, file_no);
			snprintf(file_path,					\
				 MAX_FILE_PATH_SIZE + 1,			\
				 "%s/%s/%ld%s",					\
				 itf_par_info_id->pkt_file_dir, 		\
				 itf_par_info_id->protocol_name,		\
				 file_no, PKT_FILE_SUFFIX);
			if(file_is_exist(file_path) == FILE_EXIST)
				set_file_no(fileno_fd, file_no);
			else {
				file_no = inc_fileno(itf_par_info_id, file_no);
				snprintf(file_path,				\
					 MAX_FILE_PATH_SIZE + 1,		\
				 	 "%s/%s/%ld%s",				\
					 itf_par_info_id->pkt_file_dir,		\
					 itf_par_info_id->protocol_name,	\
					 file_no, PKT_FILE_SUFFIX);

				if(file_is_exist(file_path) == FILE_EXIST)
					set_file_no(fileno_fd, file_no);
			}
			close(fileno_fd);
			sleep(MAX_DELAY_SEC);
			if(++sec_elapsed >= itf_par_info_id->deposit_ivl_sec)
				(*(callback_func_set_id->flush_fptr))(TRUE);

			(*(callback_func_set_id->force_into_db_fptr))();
		} /* fi */
	} /* elihw */
}


int inc_fileno(
	EA_ITF_PAR_INFO_ID	itf_par_info_id,
	unsigned long		fileno
	)
{
	unsigned long new_fileno = ++fileno;
	
	return(new_fileno>(itf_par_info_id->cfg_file_set.maxPktFileNum))?1:new_fileno;
}


int open_fileno_file(
	EA_ITF_PAR_INFO_ID	itf_par_info_id
	)
{
	int	fd;
	char	read_fileno_path[64];

	memset(read_fileno_path,0x00,64);
	sprintf(read_fileno_path, "%s/%s/%s", itf_par_info_id->pkt_file_dir,	\
		itf_par_info_id->protocol_name, PKT_RD_NO_FILE_NAME);

	if ((fd = open(read_fileno_path,O_RDWR)) < 0) {
		perror("fileno");
		return(ERR);
	}
	return(fd);
}


unsigned long read_file_no(
	int	fd
	)
{

	int		ret;
	char		buf[U_LONG_SIZE+1];
	unsigned long	file_no;
	
	lseek(fd, 0, SEEK_SET);
	if ((ret = read(fd,buf,U_LONG_SIZE+1)) <= 0) return(ERR);

	buf[ret] = 0x00;
	file_no  = strtoul(buf,NULL,10);

	return(file_no);
}


int set_file_no(
	int		fd,
	unsigned long 	file_no
	)
{

	char	buf[U_LONG_SIZE+1];
	int	ret;

	ret = snprintf(buf, U_LONG_SIZE+1, "%ld", file_no);

	if(ret <= 0)			return(ERR);
	if(ftruncate(fd, 0L) < 0)	return(ERR);
	if(lseek(fd,0,SEEK_SET) < 0)	return(ERR);
	if(write(fd,buf,ret) != ret)	return(ERR);

	return(OK);
}


int mmap_file(
	EA_ITF_PAR_INFO_ID	itf_par_info_id,
	MMAP_FILE_INFO_ID	mmap_file_info_id,
	char*			file_path
	)
{
	int		fd;
	unsigned char*	str_mmaped = NULL;

	DEBUG("%s\n", file_path);
	if ((fd = open(file_path, RD_PKT_FILE_FLAGS)) < 0)
		return(ERR);

	/*
	 *  mapping the content of file to mem
	 *  if success then return the address
         *  of shared space.
	 */
	str_mmaped = (unsigned char*)						\
		      mmap(0, itf_par_info_id->cfg_file_set.maxPktFileSize, 	\
			   PROT_READ, MAP_SHARED, fd, 0);

	if (MAP_FAILED == str_mmaped) {
		close(fd);
		return(ERR);
	}

	mmap_file_info_id->mmap_addr = str_mmaped;
	mmap_file_info_id->cur_pos   = str_mmaped;
	mmap_file_info_id->fd        = fd;

	analyze_pkt_file_hdr(mmap_file_info_id);

	return(OK);   
}


int unmmap_file(
	EA_ITF_PAR_INFO_ID	itf_par_info_id,
	MMAP_FILE_INFO_ID	mmap_file_info_id
	)
{
	char file_path[MAX_FILE_PATH_SIZE + 1];
	char file_newpath[MAX_FILE_PATH_SIZE + 1];
	
	if(munmap(mmap_file_info_id->mmap_addr, 				\
		  itf_par_info_id->cfg_file_set.maxPktFileSize) < 0)
		error("[ERROR]***Munmap error.");

	close(mmap_file_info_id->fd);
	snprintf(file_path, MAX_FILE_PATH_SIZE + 1, "%s/%s/%ld%s", 		\
		 itf_par_info_id->pkt_file_dir, 				\
		 itf_par_info_id->protocol_name,				\
		 mmap_file_info_id->file_no,					\
		 PKT_FILE_SUFFIX);

	snprintf(file_newpath, MAX_FILE_PATH_SIZE + 1, "%s/%s/%ld%s",		\
		 itf_par_info_id->pkt_file_dir,					\
		 itf_par_info_id->protocol_name,				\
		 mmap_file_info_id->file_no,					\
		 PKT_FILE_TMP_SUFFIX);

	rename(file_path, file_newpath);
	return(OK);
}


void analyze_pkt_file_hdr(
	MMAP_FILE_INFO_ID	mmap_file_info_id
	)
{
	/* get all header of packet, from a string */
	mmap_file_info_id->pkt_file_hdr.usr_hdr_id = (PKT_FILE_USR_HDR_ID)	\
						      (mmap_file_info_id->cur_pos);
	mmap_file_info_id->cur_pos 		  += PKT_FILE_USR_HDR_SIZE;

	mmap_file_info_id->pkt_file_hdr.pcap_hdr_id= (PKT_FILE_PCAP_HDR_ID)	\
						      (mmap_file_info_id->cur_pos);
	mmap_file_info_id->cur_pos 		  += PKT_FILE_PCAP_HDR_SIZE;

	mmap_file_info_id->cur_pos_bk		   = mmap_file_info_id->cur_pos;
}


void get_protect_rule_id( /* alias get_protect_resource_id */
	MMAP_FILE_INFO_ID	mmap_file_info_id
	)
{
	mmap_file_info_id->rule_id_st_id = (RULE_ID_ST_ID)(mmap_file_info_id->cur_pos);
	mmap_file_info_id->cur_pos 	+=  RULE_ID_ST_SIZE;
	mmap_file_info_id->cur_pos_bk 	+=  RULE_ID_ST_SIZE;
}


void get_libpcap_pkt_hdr(
	MMAP_FILE_INFO_ID	mmap_file_info_id
	)
{
	mmap_file_info_id->libpcap_hdr_id= (PKT_USR_HDR_ID)(mmap_file_info_id->cur_pos);
	mmap_file_info_id->cur_pos 	+=  PKT_USR_HDR_SIZE;
	mmap_file_info_id->cur_pos_bk 	+=  PKT_USR_HDR_SIZE;
}
