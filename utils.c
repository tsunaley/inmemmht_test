#include "utils.h"
#include "dataelem.h"
#include "sha256.h"
#include "mht.h"
#include "sqlite3.h"

int get_page_count_from_db(char* dbfile_name){
	sqlite3 *db;
	char* errmsg = NULL;
	int pg_num = -1;

	if(SQLITE_OK != sqlite3_open(dbfile_name, &db)){
    	debug_print("get_page_count_from_db", "sqlite3_open error\n");
        return -1;
    }

    char* sql = "SELECT name FROM sqlite_master WHERE type='table'";
    if(SQLITE_OK != sqlite3_exec(db,sql,NULL,NULL,&errmsg)){
    	debug_print("get_page_count_from_db", "process_database_info:sqlite3_exec() falied！\n");
        return -1;
    }

	pg_num = getCount(db, dbfile_name);
	//pg_num = getPageCount(db, dbfile_name);
	sqlite3_close(db);

	return pg_num;
}

int gen_page_info_array_from_db(sqlite3 *db, PDB_PAGE_INFO *pg_info_ptr){
	int i = 0;
	int* pgno_array = NULL;
	int* pghash_array = NULL;
	int page_num = 0;
	int page_size = 0;

	return 0;
}

void gen_ds_from_dbfile(IN char* db_filename, OUT PDATA_SET *pds){
	const char* FUNC_NAME = "gen_ds_from_dbfile";
	int i = 0;
	PDB_PAGE_INFO pg_info_ptr = NULL;
	PDATA_SET ds_ptr = NULL;
	sqlite3 *db;
	char* sql_q1 = "SELECT name FROM sqlite_master WHERE type='table'";
	char* errmsg = NULL;
	int pg_num = -1;
	int* tmp_pgno_array = NULL;
	char* tmp_hash_array = NULL;
	int pg_num_processed = 0;

	if(*pds)
		free_ds(pds);

	if(SQLITE_OK != sqlite3_open(db_filename, &db)){
    	debug_print("gen_ds_from_dbfile", "sqlite3_open error\n");
        return;
    }

    if(SQLITE_OK != sqlite3_exec(db,sql_q1,NULL,NULL,&errmsg)){
    	debug_print("gen_ds_from_dbfile", "process_database_info:sqlite3_exec() falied！\n");
        return;
    }

    pg_num = getCount(db, db_filename); //get the number of db file pages
    tmp_pgno_array = (int*) malloc (sizeof(int) * pg_num);
    tmp_hash_array = (char*) malloc (sizeof(char) * pg_num * SHA256_BLOCK_SIZE);
    memset(tmp_hash_array, 0, sizeof(char) * pg_num * SHA256_BLOCK_SIZE);

    pg_num_processed = getInfo1(db, db_filename, 
    							(unsigned int*)tmp_pgno_array, 
    							(unsigned char*)tmp_hash_array, 1, 0x7fffffff, pg_num);

    printf("Processed %d pages.\n", pg_num_processed);

    /* copying tmp_pgno_array and tmp_hash_array into pg_info_ptr */
    pg_info_ptr = (PDB_PAGE_INFO) malloc (sizeof(DB_PAGE_INFO) * pg_num_processed);
    for (i = 0; i < pg_num_processed; ++i){
    	pg_info_ptr[i].m_pg_index = *(tmp_pgno_array + i);
    	memcpy(pg_info_ptr[i].m_hash, (tmp_hash_array + i * SHA256_BLOCK_SIZE), SHA256_BLOCK_SIZE);
    }

    free(tmp_pgno_array);
    free(tmp_hash_array);

    // building dataset
    ds_ptr = (PDATA_SET) malloc (sizeof(DATA_SET));
    check_pointer_ex(ds_ptr, "ds_ptr", FUNC_NAME, "null pointer");
    ds_ptr->m_pDE = (PDATA_ELEM) malloc (sizeof(DATA_ELEM) * pg_num_processed);
    ds_ptr->m_size = pg_num_processed;
    ds_ptr->m_is_hashed = TRUE;
    // print_pg_info_vector(pg_info_ptr, pg_num_processed);
    for (i = 0; i < ds_ptr->m_size; ++i)
    {
    	ds_ptr->m_pDE[i].m_index = pg_info_ptr[i].m_pg_index;
    	ds_ptr->m_pDE[i].m_pdata = (unsigned char*) malloc(SHA256_BLOCK_SIZE);
    	memcpy(ds_ptr->m_pDE[i].m_pdata, pg_info_ptr[i].m_hash, SHA256_BLOCK_SIZE);
    	ds_ptr->m_pDE[i].m_data_len = SHA256_BLOCK_SIZE;
    }

    // print_ds_with_hash(ds_ptr);

    *pds = ds_ptr;

    return;
}

void gen_ds_file(const char* file_name, int data_block_num, int string_len){
	int fd = -1;
	int open_flags;
	mode_t file_perms;
	int i = 0;
	int index = 0;
	char* gen_str = NULL;
	char* buffer = NULL;
	int buffer_len = sizeof(int) + string_len;

	check_pointer_ex((char*)file_name, "file_name", "gen_ds_file", "null file name");
	data_block_num <= 0 || string_len <= 0 ? debug_print("gen_ds_file", "neither data_block_num nor string_len can be <= 0") : nop();

	open_flags = O_CREAT | O_WRONLY | O_TRUNC;
	file_perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	fd = open(file_name, open_flags, file_perms);

	buffer = (char*) malloc (buffer_len);

	for(i = 0; i < data_block_num; i++){
		index = i + 1;
		memset(buffer, 0, buffer_len);
		memcpy(buffer, &index, sizeof(uint32));
		gen_str = generate_random_string(string_len);
		memcpy(buffer + sizeof(uint32), gen_str, string_len);
		free(gen_str); gen_str = NULL;
		write(fd, buffer, buffer_len);
	}

	close(fd);
}

void gen_hashed_ds_file(const char* file_name, int data_block_num, int string_len){
	int fd = -1;
	int open_flags;
	mode_t file_perms;
	int i = 0;
	int index = 0;
	char* gen_str = NULL;
	char* buffer = NULL;
	int buffer_len = sizeof(int) + SHA256_BLOCK_SIZE;
	SHA256_CTX ctx;
	char* sha256_buffer = NULL;

	check_pointer_ex((char*)file_name, "file_name", "gen_ds_file", "null file name");
	data_block_num <= 0 || string_len <= 0 ? debug_print("gen_ds_file", "neither data_block_num nor string_len can be <= 0") : nop();

	open_flags = O_CREAT | O_WRONLY | O_TRUNC;
	file_perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	fd = open(file_name, open_flags, file_perms);

	buffer = (char*) malloc (buffer_len);
	sha256_buffer = (char*) malloc (SHA256_BLOCK_SIZE);

	for(i = 0; i < data_block_num; i++){
		index = i + 1;
		memset(sha256_buffer, 0, SHA256_BLOCK_SIZE);
		memset(buffer, 0, buffer_len);
		memcpy(buffer, &index, sizeof(uint32));
		gen_str = generate_random_string(string_len);
		sha256_init(&ctx);
		sha256_update(&ctx, gen_str, string_len);
		sha256_final(&ctx, sha256_buffer);
		memcpy(buffer + sizeof(uint32), sha256_buffer, SHA256_BLOCK_SIZE);
		free(gen_str); gen_str = NULL;
		write(fd, buffer, buffer_len);
	}

	close(fd);
}

void gen_ds(int data_block_num, int string_len, OUT PDATA_SET *pds){
	int i = 0;
	int index = 0;
	char* gen_str = NULL;

	if(*pds)
		free_ds(pds);

	*pds = (PDATA_SET) malloc (sizeof(DATA_SET));
	(*pds)->m_is_hashed = FALSE;
	(*pds)->m_size = data_block_num;
	(*pds)->m_pDE = (PDATA_ELEM) malloc (sizeof(DATA_ELEM) * data_block_num);

	for(i = 0; i < data_block_num; i++){
		index = i + 1;
		gen_str = generate_random_string(string_len);
		(*pds)->m_pDE[i].m_pdata = (char*) malloc (string_len);
		memcpy((*pds)->m_pDE[i].m_pdata, gen_str, string_len);
		(*pds)->m_pDE[i].m_index = index;
		(*pds)->m_pDE[i].m_data_len = string_len;

		free(gen_str); gen_str = NULL;
	}
}

void print_ds(IN PDATA_SET pds){
	int i = 0;
	char* out_buffer = NULL;
	int out_buffer_len = 0;

	if(!pds){
		printf("Parameter %s is null.\n", "pds");
		return;
	}

	out_buffer_len = pds->m_pDE[0].m_data_len + 2;
	out_buffer = (char*) malloc (out_buffer_len);

	for (i = 0; i < pds->m_size; ++i)
	{
		memset(out_buffer, 0, out_buffer_len);
		memcpy(out_buffer, (char*)(pds->m_pDE[i].m_pdata), pds->m_pDE[i].m_data_len);
		printf("Index|Data: %d | %s\n", pds->m_pDE[i].m_index, out_buffer);
	}
	free(out_buffer);
}

void print_ds_with_hash(IN PDATA_SET pds){
	int i = 0;
	unsigned char* out_buffer = NULL;
	int out_buffer_len = 0;

	if(!pds){
		printf("Parameter %s is null.\n", "pds");
		return;
	}

	out_buffer_len = pds->m_pDE[0].m_data_len * 2 + 1;
	out_buffer = (unsigned char*) malloc (out_buffer_len);

	for (i = 0; i < pds->m_size; ++i)
	{
		memset(out_buffer, 0, out_buffer_len);
		convert_hash_to_string((BYTE*)(pds->m_pDE[i].m_pdata), out_buffer, out_buffer_len);
		printf("Index|Data: %d | %s\n", pds->m_pDE[i].m_index, out_buffer);
	}
	free(out_buffer);
}

void print_pg_info_vector(PDB_PAGE_INFO pdb_pg_info, int pg_num){
	unsigned char sha256_string[SHA256_BLOCK_SIZE * 2 + 1] = {0};
	int i = 0;

	for (i = 0; i < pg_num; ++i)
	{
		memset(sha256_string, 0, SHA256_BLOCK_SIZE * 2 + 1);
		convert_hash_to_string(pdb_pg_info[i].m_hash, sha256_string, SHA256_BLOCK_SIZE * 2 + 1);
		printf("PageNo: %d, Hash: %s\n", pdb_pg_info[i].m_pg_index, sha256_string);
	}

	return;
}