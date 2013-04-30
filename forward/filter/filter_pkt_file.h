
#ifdef _FILTER_PKT_FILE
#define _FILTER_PKT_FILE

/*function declaration*/
extern FILE *pkt_file_fopen(const char *fname);
extern void pf_write_pkt(File *fp,unsigned char *pkt,unsigned long pkt_size);
extern int pf_pkt_flush(FILE *fp);

#endif
