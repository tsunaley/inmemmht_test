#ifndef UTILS_H
#define UTILS_H

#include "defs.h"
#include "mht.h"

typedef struct _DB_PAGE_INFO{
	int m_pg_index;
	char m_hash[SHA256_BLOCK_SIZE];
} DB_PAGE_INFO, *PDB_PAGE_INFO;

int get_page_count_from_db(char* dbfile_name);

void gen_ds_file(const char* file_name, int data_block_num, int string_len);

void gen_hashed_ds_file(const char* file_name, int data_block_num, int string_len);

void gen_ds_from_dbfile(IN char* db_filename, OUT PDATA_SET *pds);

void gen_ds(int data_block_num, int string_len, OUT PDATA_SET *pds);

void print_ds(IN PDATA_SET pds);

void print_ds_with_hash(IN PDATA_SET pds);

void print_pg_info_vector(PDB_PAGE_INFO pdb_pg_info, int pg_num);

#endif