/* Processed by ecpg (4.4.1) */
/* These include files are added by the preprocessor */
#include <ecpgtype.h>
#include <ecpglib.h>
#include <ecpgerrno.h>
#include <sqlca.h>
/* End of automatic include section */

#line 1 "ctl_db.pgc"

#include <sqlca.h>
#include "ctl_db.h"
#include "ctl_monitor.h"


#line 1 "/data/database/include/sqlca.h"
#ifndef POSTGRES_SQLCA_H
#define POSTGRES_SQLCA_H

#ifndef PGDLLIMPORT
#if  defined(WIN32) || defined(__CYGWIN__)
#define PGDLLIMPORT __declspec (dllimport)
#else
#define PGDLLIMPORT
#endif   /* __CYGWIN__ */
#endif   /* PGDLLIMPORT */

#define SQLERRMC_LEN	150

#ifdef __cplusplus
extern		"C"
{
#endif

struct sqlca_t
{
	char		sqlcaid[8];
	long		sqlabc;
	long		sqlcode;
	struct
	{
		int			sqlerrml;
		char		sqlerrmc[SQLERRMC_LEN];
	}			sqlerrm;
	char		sqlerrp[8];
	long		sqlerrd[6];
	/* Element 0: empty						*/
	/* 1: OID of processed tuple if applicable			*/
	/* 2: number of rows processed				*/
	/* after an INSERT, UPDATE or				*/
	/* DELETE statement					*/
	/* 3: empty						*/
	/* 4: empty						*/
	/* 5: empty						*/
	char		sqlwarn[8];
	/* Element 0: set to 'W' if at least one other is 'W'	*/
	/* 1: if 'W' at least one character string		*/
	/* value was truncated when it was			*/
	/* stored into a host variable.				*/

	/*
	 * 2: if 'W' a (hopefully) non-fatal notice occurred
	 */	/* 3: empty */
	/* 4: empty						*/
	/* 5: empty						*/
	/* 6: empty						*/
	/* 7: empty						*/

	char		sqlstate[5];
};

struct sqlca_t *ECPGget_sqlca(void);

#ifndef POSTGRES_ECPG_INTERNAL
#define sqlca (*ECPGget_sqlca())
#endif

#ifdef __cplusplus
}
#endif

#endif

#line 31 "ctl_db.pgc"

#define ESQL_PRINT_ERR() fprintf(stderr, "%ld %s\n",sqlca.sqlcode, sqlca.sqlerrm.sqlerrmc);
/* exec sql begin declare section */
      

#line 34 "ctl_db.pgc"
 unsigned char  g_sqlstr [ 10000 ]    ;
/* exec sql end declare section */
#line 35 "ctl_db.pgc"


/**********************************
*func name:main
*function:
*parameters:
*call:
*called:
*return:
*/
int conn_db(const char *host, const int port, const char *database,
		        const char *user, const char *password)
{
	/* exec sql begin declare section */
		 
		 
		 
	
#line 49 "ctl_db.pgc"
 char  db_target [ 64 ]    ;
 
#line 50 "ctl_db.pgc"
 char  db_user [ 32 ]    ;
 
#line 51 "ctl_db.pgc"
 char  db_password [ 64 ]    ;
/* exec sql end declare section */
#line 52 "ctl_db.pgc"


	if(!strcmp(host,"127.0.0.1") || !strcmp(host, "localhost"))
		snprintf(db_target, 64, "unix:postgresql://%s:%d/%s",host, port, database);
	else
		snprintf(db_target, 64, "tcp:postgresql://%s:%d/%s",host, port, database);
    
	snprintf(db_user, 32,"%s",user);
	snprintf(db_password, 64, "%s", password);
	
	{ ECPGconnect(__LINE__, 0, db_target , db_user , db_password , NULL, 0); }
#line 62 "ctl_db.pgc"

	if(sqlca.sqlcode < 0) 
	{
//		fprintf(stderr, "%ld %s\n",sqlca.sqlcode, sqlca.sqlerrm.sqlerrmc);
		return ESQL_ERR;
	}
	
	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "set CLIENT_ENCODING to 'GBK'", ECPGt_EOIT, ECPGt_EORT);}
#line 69 "ctl_db.pgc"

	return ESQL_OK;
}

int conn_local_db()
{
	/* exec sql begin declare section */
		 
		 
	
#line 76 "ctl_db.pgc"
 char  db_target [ 64 ]    ;
 
#line 77 "ctl_db.pgc"
 char  db_user [ 32 ]    ;
/* exec sql end declare section */
#line 78 "ctl_db.pgc"

	
	snprintf(db_target, 64, "unix:postgresql://%s:%d/%s","127.0.0.1", 5432, "eAudit");
	snprintf(db_user, 32, "%s","postgres");
	
	{ ECPGconnect(__LINE__, 0, db_target , db_user , NULL , NULL, 0); }
#line 83 "ctl_db.pgc"

	if(sqlca.sqlcode < 0)
	{
//		fprintf(stderr, "%ld %s\n",sqlca.sqlcode, sqlca.sqlerrm.sqlerrmc);
		return ESQL_ERR;
	}
	{ ECPGdo(__LINE__, 0, 1, NULL, 0, ECPGst_normal, "set CLIENT_ENCODING to 'GBK'", ECPGt_EOIT, ECPGt_EORT);}
#line 89 "ctl_db.pgc"

	return ESQL_OK;
}




/**********************************
*func name:main
*function:
*parameters:
*call:
*called:
*return:
*/
int close_db(void)
{
    { ECPGdisconnect(__LINE__, "CURRENT");}
#line 106 "ctl_db.pgc"

    if(sqlca.sqlcode < 0) 
    {
        ESQL_PRINT_ERR();   
        return ESQL_ERR;
    }
    return ESQL_OK;
}

int write_process_log_into_db(unsigned char* str)
{    
	return ESQL_OK;
	char log_date[64];
	char cur_date[64];
	int ret=ESQL_OK;
	memset(log_date,0x00,64);
    	memset(g_sqlstr,0x00,10000);
	get_now_time((char *)log_date);
	get_current_date((char*)cur_date);
	sprintf((unsigned char *)g_sqlstr,"INSERT INTO \"public\".ea_log_system_%s (p_type_id,logdate_time,sys_name,operate_type,model_name,log_details) values(%d,'%s','%s','%s','%s','%s')",\
		(char *)cur_date,23,(char *)log_date,"SNAM","SNAM系统状态","eAudit",(unsigned char *)str);

 	 //fprintf(stdout, "\t%s %d %s\n", __FILE__, __LINE__, g_sqlstr);
        { ECPGdo(__LINE__, 0, 1, NULL, 0, 2, g_sqlstr, ECPGt_EOIT, ECPGt_EORT);}
#line 129 "ctl_db.pgc"

	//printf(" session sqlca.sqlcode=%ld\n",sqlca.sqlcode);
       if (sqlca.sqlcode < 0)
        {
            ret = ESQL_ERR;
	    { ECPGtrans(__LINE__, NULL, "rollback");}
#line 134 "ctl_db.pgc"

        }
        else
        {
            { ECPGtrans(__LINE__, NULL, "commit");}
#line 138 "ctl_db.pgc"

            if(sqlca.sqlcode < 0)
            {
                printf( "COMMIT sqlca.sqlcode=%ld\n",sqlca.sqlcode);
                ESQL_PRINT_ERR();
		{ ECPGtrans(__LINE__, NULL, "rollback");}
#line 143 "ctl_db.pgc"

                ret = ESQL_ERR;
            }
        }   
    return ret;
	
}	



int write_process_alarm_into_db(unsigned char* str)
{    
        return ESQL_OK;
	char alarm_date[64];
	char cur_date[64];
	int ret=ESQL_OK;
	char ip_eth0[20],mac_eth0[20];
	memset(ip_eth0,0x00,20);
	memset(mac_eth0,0x00,20);
	memset(alarm_date,0x00,64);
    	memset(g_sqlstr,0x00,10000);
	get_now_time((char *)alarm_date);
        get_current_date((char*)cur_date);
	get_eth0_info(ip_eth0,mac_eth0);
	sprintf((unsigned char *)g_sqlstr,"INSERT INTO \"public\".ea_alarm_system_%s(session_id,p_type_id,pro_id,pro_name,model_name,sys_name,src_ip,src_mac,dst_ip,dst_mac,usr_id,src_usrname,warn_type,warn_state,alarm_date,warn_level,description)\
		values (%d,%d,%d,'%s','%s','%s','%s','%s','%s','%s',%d,'%s',%ld,'%s','%s',%ld,'%s')", \
		(char*)cur_date,0,23,0,"eAudit","eAudit","SNAM",ip_eth0,mac_eth0,ip_eth0,mac_eth0,0,"N/A",0,"一般",(char *)alarm_date,100,(unsigned char *)str);

 //	  fprintf(stdout, "\t%s %d %s\n", __FILE__, __LINE__, g_sqlstr);
        { ECPGdo(__LINE__, 0, 1, NULL, 0, 2, g_sqlstr, ECPGt_EOIT, ECPGt_EORT);}
#line 172 "ctl_db.pgc"

	//printf(" session sqlca.sqlcode=%ld\n",sqlca.sqlcode);
       if (sqlca.sqlcode < 0)
        {
 //       	 printf( "EXECUTE sqlca.sqlcode=%ld\n",sqlca.sqlcode);
            ret = ESQL_ERR;
	    { ECPGtrans(__LINE__, NULL, "rollback");}
#line 178 "ctl_db.pgc"

        }
        else
        {
            { ECPGtrans(__LINE__, NULL, "commit");}
#line 182 "ctl_db.pgc"

            if(sqlca.sqlcode < 0)
            {
                printf( "COMMIT sqlca.sqlcode=%ld\n",sqlca.sqlcode);
		{ ECPGtrans(__LINE__, NULL, "rollback");}
#line 186 "ctl_db.pgc"

                ESQL_PRINT_ERR();
                ret = ESQL_ERR;
            }
        }   
    return ret;
	
}	


int write_snam_sysinfo_into_db(unsigned char* str)
{    
	char log_date[64];
	int ret=ESQL_OK;
	return ESQL_OK;
	memset(log_date,0x00,64);
    	memset(g_sqlstr,0x00,10000);
	get_now_time((char *)log_date);
	sprintf((unsigned char *)g_sqlstr,"INSERT INTO crew_operatelog (logdatetime,loginname,operatetype,logdetails) values('%s','%s','%s','%s')",\
		(char *)log_date,"admin","SNAM系统信息",(unsigned char *)str);

 //	  fprintf(stdout, "\t%s %d %s\n", __FILE__, __LINE__, g_sqlstr);
        { ECPGdo(__LINE__, 0, 1, NULL, 0, 2, g_sqlstr, ECPGt_EOIT, ECPGt_EORT);}
#line 208 "ctl_db.pgc"

//	printf(" session sqlca.sqlcode=%ld\n",sqlca.sqlcode);
       if (sqlca.sqlcode < 0)
        {
            ret = ESQL_ERR;
        }
        else
        {
            { ECPGtrans(__LINE__, NULL, "commit");}
#line 216 "ctl_db.pgc"

            if(sqlca.sqlcode < 0)
            {
                printf( "COMMIT sqlca.sqlcode=%ld\n",sqlca.sqlcode);
                ESQL_PRINT_ERR();
                ret = ESQL_ERR;
            }
        }   
    return ret;
	
}
	
int write_authorizeinfo_into_db(char* str,int pro_num)
{    
        SUPPORT_PRO_NODE_ID pro_items_id = (SUPPORT_PRO_NODE_ID)str;
	int ret=ESQL_OK;
	return ESQL_OK;
        int i;
	return ret; 
    	memset(g_sqlstr,0x00,10000);

        strcpy((unsigned char *)g_sqlstr,"DELETE  FROM \"eAPUBLIC\".protocoltypeinfo");
	//fprintf(stdout, "\t%s %d %s\n", __FILE__, __LINE__, g_sqlstr);
        { ECPGdo(__LINE__, 0, 1, NULL, 0, 2, g_sqlstr, ECPGt_EOIT, ECPGt_EORT);}
#line 239 "ctl_db.pgc"

	//printf(" session sqlca.sqlcode=%ld\n",sqlca.sqlcode);
       	if (sqlca.sqlcode < 0)
        {
            ret = ESQL_ERR;
        }
        else
        {
            { ECPGtrans(__LINE__, NULL, "commit");}
#line 247 "ctl_db.pgc"

            if(sqlca.sqlcode < 0)
            {
                printf( "COMMIT sqlca.sqlcode=%ld\n",sqlca.sqlcode);
                ESQL_PRINT_ERR();
                ret = ESQL_ERR;
            }
        }   
    
        for(i=0;i<pro_num;i++){
        	memset(g_sqlstr,0x00,10000);
		sprintf((unsigned char *)g_sqlstr,"INSERT INTO \"eAPUBLIC\".protocoltypeinfo (protocoltypeid,protocolname,remark,default_etype,default_etype_id,default_ttype_id,\
		default_ttype,default_port,default_deal) values('%d','%s','%s','%s','%ld','%ld','%s','%d','%d')",\
		pro_items_id[i].pro_no,(char *)(pro_items_id[i].pro_name),(char *)(pro_items_id[i].pro_name),"TCP",1,1,"IP",100,100);

        	//fprintf(stdout, "\t%s %d %s\n", __FILE__, __LINE__, g_sqlstr);
        	{ ECPGdo(__LINE__, 0, 1, NULL, 0, 2, g_sqlstr, ECPGt_EOIT, ECPGt_EORT);}
#line 263 "ctl_db.pgc"

		//printf(" session sqlca.sqlcode=%ld\n",sqlca.sqlcode);
       		if (sqlca.sqlcode < 0)
        	{
            		ret = ESQL_ERR;
        	}
        	else
        	{
            		{ ECPGtrans(__LINE__, NULL, "commit");}
#line 271 "ctl_db.pgc"

            		if(sqlca.sqlcode < 0)
            		{
                		printf( "COMMIT sqlca.sqlcode=%ld\n",sqlca.sqlcode);
                		ESQL_PRINT_ERR();
                		ret = ESQL_ERR;
            		}
        	}  
     } 
    return ret;
}

