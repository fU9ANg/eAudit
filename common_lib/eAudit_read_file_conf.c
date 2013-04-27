/*
 *  Author: fU9ANg
 *  E-mail: bb.newlife@gmail.com
 *
 *  Written 2009
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "eAudit_read_file_conf.h"
#include "eAudit_read_file_conf_define.h"

static int clear_enter(char *tmp, int len)
{
	if(len < 4)
		return FALSE;
	
	if(tmp[len - 3] == ';')
	{
		tmp[len - 3] = 0x00;
		return TRUE;
	}
	else if(tmp[len - 2] == 0x0a || tmp[len - 2] == 0x0d || tmp[len - 2] == ';')
	{
		tmp[len - 2] = 0x00;
		return TRUE;
	}
	else if(tmp[len - 1] == 0x0a || tmp[len - 1] == 0x0d || tmp[len - 1] == ';')
	{
		tmp[len - 1] = 0x00;
		return TRUE;
	}
	
	return TRUE;
}


P_MONITOR_INFO_ID read_monitor_conf(int id, P_MONITOR_INFO_ID p_monitor_conf_id, int *flag)
{
	if(!p_monitor_conf_id || !flag || id < 0)
	{
		return NULL;
	}

	int num = 0;
	
	char path[128];
	memset(path, 0x00, 128);
	sprintf(path, "%s/%s", CONF_PATH, MONITOR_FILE);

	FILE *fd = NULL;
	char buff[LINE_LEN];
	memset(buff, 0x00, LINE_LEN);
	
	if((fd = fopen(path, "r")) == NULL)
	{
		*flag = 1;
		return NULL;
	}

	if(!read_conf_front(fd, buff, &num))
	{
		*flag = 2;
		goto ERROR_RETURN;
	}

	if(!num)
	{
		*flag = 3;
		goto ERROR_RETURN;
	}
	
	if(read_monitor_conf_data(fd, buff, num, p_monitor_conf_id, id))
	{
		*flag = 5;
		goto OK_RETURN;
	}
	else
	{
		*flag = 2;
		goto ERROR_RETURN;
	}


ERROR_RETURN:
	fclose(fd);
	return NULL;
OK_RETURN:
	fclose(fd);
	return p_monitor_conf_id;
}


static int read_monitor_conf_data(FILE *fd, char *buff, int num, P_MONITOR_INFO_ID p_monitor_conf_id, int id)
{
	int buff_len = 0;
	int i = 0;
	char *p = NULL;
	char delim[] = " =+/";
	
	for(i = 0; i < num; i++)
	{
		memset(buff, 0x00, buff_len);

		if(fgets(buff, LINE_LEN, fd))
		{
			buff_len = strlen(buff);

			if(!memcmp(buff, "INFO", 4))
			{
				if(clear_enter(buff, buff_len) == FALSE)
					goto ERROR_RETURN;

				if((p = strtok(buff, delim)) == NULL)
					goto ERROR_RETURN;


				if(i != atoi(buff + 4))			//index
					goto ERROR_RETURN;

				p = strtok(NULL, delim);		//p_type_id
				if(p)
				{
					if(id == atoi(p))
					{
						p = strtok(NULL, delim);
						if(p)
						{
							p_monitor_conf_id->p_type_id = id;
							p_monitor_conf_id->flux_threshold = atoi(p);

							p = strtok(NULL, delim);
							if(p)
							{
								p_monitor_conf_id->flux_interval = atoi(p);

								p = strtok(NULL, delim);
								if(p)
								{
									p_monitor_conf_id->conn_threshold = atoi(p);

									p = strtok(NULL, delim);
									if(p)
									{
										p_monitor_conf_id->conn_interval = atoi(p);

										p = strtok(NULL, delim);
										if(p)
										{
											p_monitor_conf_id->not_authorize_event.block_flag = atoi(p);
										
											p = strtok(NULL, delim);
											if(p)
											{
												p_monitor_conf_id->not_authorize_event.warn_flag = atoi(p);
											
												p = strtok(NULL, delim);
												if(p)
												{
													p_monitor_conf_id->not_authorize_event.log_flag = atoi(p);
													goto OK_RETURN;
												}
												else
												{
													goto ERROR_RETURN;

												}
											}
											else
											{
												goto ERROR_RETURN;
											}
										}
										else
										{
											goto ERROR_RETURN;
										}
									}
									else
									{
										goto ERROR_RETURN;
									}
								}
								else
								{
									goto ERROR_RETURN;
								}						
							}
							else
							{
								goto ERROR_RETURN;
							}

						}
						else
						{
							goto ERROR_RETURN;
						}
					}
				}
				else
				{
					goto ERROR_RETURN;
				}
			}
			else
			{
				goto ERROR_RETURN;
			}
		}
		else
		{
			goto ERROR_RETURN;
		}
	}



ERROR_RETURN:
	return FALSE;
OK_RETURN:
	return TRUE;

}



static int read_conf_front(FILE *fd, char *buff, int *num)
{
	char *p = NULL;
	char delim[] = " =+/";
	int buff_len = 0;
	
	if(fgets(buff, LINE_LEN, fd))
	{
		buff_len = strlen(buff);

		if(memcmp(buff, "[COMMON]", 8))
		{
			goto ERROR_RETURN;
		}
	}
	else
	{
		goto ERROR_RETURN;
	}
	memset(buff, 0x00, buff_len);


	if(fgets(buff, LINE_LEN, fd))
	{
		buff_len = strlen(buff);

		if(memcmp(buff, "LIST_NUM", 8) == 0)
		{
			if(clear_enter(buff, buff_len) == FALSE)
			{
				goto ERROR_RETURN;
			}
			
			if(strtok(buff, delim) == NULL)
			{
				goto ERROR_RETURN;
			}
			
			p = strtok(NULL, delim);
			if(p == NULL)
			{
				goto ERROR_RETURN;
			}
			*num = atol(p);

			if(*num == 0)
			{
				goto ERROR_RETURN;
			}
		}
		else
		{
			goto ERROR_RETURN;
		}
	}
	else
	{
		goto ERROR_RETURN;

	}
	memset(buff, 0x00, buff_len);


	if(fgets(buff, LINE_LEN, fd))
	{
		buff_len = strlen(buff);

		if(memcmp(buff, "MODE_GETE", 9))
		{
			goto ERROR_RETURN;
		}
	}
	else
	{
		goto ERROR_RETURN;
	}
	memset(buff, 0x00, buff_len);

	
	if(fgets(buff, LINE_LEN, fd))
	{
		buff_len = strlen(buff);

		if(memcmp(buff, "[LIST_INFO]", 11))
		{
			goto ERROR_RETURN;
		}
	}
	else
	{
		goto ERROR_RETURN;
	}

	goto OK_RETURN;

ERROR_RETURN:
	return FALSE;
OK_RETURN:
	return TRUE;
}


static P_USER_INFO_ID read_user_conf_data(FILE *fd, char *buff, int num)
{
	P_USER_INFO_ID p_user_info_id = NULL;
	int i = 0;
	int buff_len = 0;
	char *p = NULL;
	char delim[] = " =+/";

	p_user_info_id = (P_USER_INFO_ID)calloc(num, P_USER_INFO_SIZE);

	if(!p_user_info_id)
		goto ERROR_RETURN;
	
	for(i = 0; i < num; i++)
	{
		memset(buff, 0x00, buff_len);
		if(fgets(buff, LINE_LEN, fd))
		{
			buff_len = strlen(buff);

			if(!memcmp(buff, "INFO", 4))
			{
				if(clear_enter(buff, buff_len) == FALSE)
					goto ERROR_RETURN;

				if((p = strtok(buff, delim)) == NULL)
					goto ERROR_RETURN;

				if(i != atoi(buff + 4)) 		//index
					goto ERROR_RETURN;
				
				p = strtok(NULL, delim);
				if(p)
				{
					p_user_info_id[i].num = num;
					p_user_info_id[i].usr_id = atoi(p);

					p = strtok(NULL, delim);
					if(p)
					{
						p_user_info_id[i].ip = inet_addr(p);

						p = strtok(NULL, delim);
						if(p)
						{
							if(strlen(p) > 12)
								goto ERROR_RETURN;

							strcpy(p_user_info_id[i].mac, p);

							p = strtok(NULL, delim);
							if(p)
							{
								if(strlen(p) > 255)
									goto ERROR_RETURN;

								strcpy(p_user_info_id[i].user, p);

								p = strtok(NULL, delim);
								if(p)
								{
									p_user_info_id[i].flag = atoi(p);
								}
								else
									goto ERROR_RETURN;
							}
							else
								goto ERROR_RETURN;
						}
						else
							goto ERROR_RETURN;
					}
					else
						goto ERROR_RETURN;
				}
				else
					goto ERROR_RETURN;
			}
		}
	}
	goto OK_RETURN;

OK_RETURN:
	return p_user_info_id;


ERROR_RETURN:
	return NULL;
	

}



P_USER_INFO_ID read_user_conf()
{
	P_USER_INFO_ID p_user_info_id = NULL;
	int num = 0;
	char path[128];
	memset(path, 0x00, 128);

	sprintf(path, "%s/%s", CONF_PATH, USER_FILE);

	
	FILE *fd = NULL;
	char buff[LINE_LEN];
	memset(buff, 0x00, LINE_LEN);
	
	if((fd = fopen(path, "r")) == NULL)
		return NULL;

	read_conf_front(fd, buff, &num);
	if(!num)
		return NULL;

	p_user_info_id = read_user_conf_data(fd, buff, num);
	if(p_user_info_id)
		return p_user_info_id;
	else
		return NULL;	
}



void close_user_conf(P_USER_INFO_ID p_user_info_id)
{
	free(p_user_info_id);
}







