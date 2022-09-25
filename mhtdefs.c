#include "sha256.h"
#include "mhtdefs.h"

PMHTNode makeMHTNode(int pageno, int level, const char d[]){
	PMHTNode node_ptr = NULL;
	if(d == NULL)
		return NULL;
	node_ptr = (PMHTNode) malloc(sizeof(MHTNode));
	if(node_ptr == NULL)
		return NULL;
	node_ptr->m_pageNo = pageno;
	node_ptr->m_level = level;
	memcpy(node_ptr->m_hash, d, HASH_LEN);	// HASH_LEN == SHA256_BLOCK_SIZE == 32
	node_ptr->m_is_supplement_node = FALSE;
	node_ptr->m_lchild = NULL;
	node_ptr->m_rchild = NULL;

	node_ptr->m_lchildPageNo = node_ptr->m_rchildPageNo = node_ptr->m_parentPageNo = UNASSIGNED_PAGENO;
	node_ptr->m_lchildOffset = node_ptr->m_rchildOffset = node_ptr->m_parentOffset = UNASSIGNED_OFFSET;
	//node_ptr->m_lchildOffset = node_ptr->m_lchildPageNo = UNASSIGNED_PAGENO;
	//node_ptr->m_rchildOffset = node_ptr->m_rchildPageNo = UNASSIGNED_PAGENO;
	//node_ptr->m_parentOffset = node_ptr->m_parentPageNo = UNASSIGNED_PAGENO;

	return node_ptr;
}

PMHTNode combineNodes(PMHTNode lchild, PMHTNode rchild){
	const char* FUNC_NAME = "combineNodes";
	PMHTNode node_ptr = NULL;
	SHA256_CTX ctx;
	unsigned char* hash_buffer = NULL;

	if(!check_pointer_ex(lchild, "lchild", FUNC_NAME, "null pointer") || 
		!check_pointer_ex(rchild, "rchild", FUNC_NAME, "null pointer"))
		return NULL;

	/* calculating combined hash */
	hash_buffer = (unsigned char*) malloc (SHA256_BLOCK_SIZE);
	memset(hash_buffer, 0, SHA256_BLOCK_SIZE);
	generateCombinedHash_SHA256(lchild->m_hash, rchild->m_hash, hash_buffer, SHA256_BLOCK_SIZE);

	/* if the nodes being combined are leaf nodes */
	if(lchild->m_level == NODELEVEL_LEAF){
		node_ptr = makeMHTNode(lchild->m_pageNo, lchild->m_level + 1, hash_buffer);
	}
	else {
		node_ptr = makeMHTNode(get_the_right_most_child(lchild)->m_pageNo, lchild->m_level + 1, hash_buffer);
	}

	node_ptr->m_is_supplement_node = FALSE;
	node_ptr->m_lchild = lchild;
	node_ptr->m_rchild = rchild;

	return node_ptr;
}

PMHTNode makeZeroMHTNode(int pageno){
	PMHTNode mhtnode_ptr = NULL;

	mhtnode_ptr = makeMHTNode(pageno, NODELEVEL_LEAF, g_zeroHash);
	mhtnode_ptr->m_is_supplement_node = TRUE;
	return mhtnode_ptr;
}

void deleteMHTNode(PMHTNode *node_ptr){
	if(*node_ptr){
		free(*node_ptr);
		*node_ptr = NULL;
	}

	return;
}

void generateHashByPageNo_SHA256(int page_no, char *buf, uint32 buf_len){
	char tmp_buf[32]={0};

	if(page_no < 0){
		printf("Page number must larger than 0.\n");
		return;
	}

	if(!buf || buf_len < SHA256_BLOCK_SIZE){
		printf("buf cannot be NULL and buf_len must larger than 32 bytes.\n");
		return;
	}

	sprintf(tmp_buf, "%d", page_no);
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, tmp_buf, strlen(tmp_buf));
	sha256_final(&ctx, buf);

	return;
}

void generateHashByBuffer_SHA256(char *in_buf, uint32 in_buf_len, char *buf, uint32 buf_len){
	if(!in_buf || !buf || buf_len < SHA256_BLOCK_SIZE){
		printf("in_buf and buf cannot be NULL and buf_len must larger than 32 bytes.\n");
		return;
	}

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, in_buf, in_buf_len);
	sha256_final(&ctx, buf);

	return;
}

void generateCombinedHash_SHA256(char *hash1, char *hash2, char *buf, uint32 buf_len){
	char tmp_buf[SHA256_BLOCK_SIZE * 2 + 1] = {0};

	if(!hash1 || !hash2){
		printf("Parameters \"hash1\" and \"hash2\" cannot be NULL.\n");
		return;
	}

	if(!buf || buf_len < SHA256_BLOCK_SIZE){
		printf("buf cannot be NULL and buf_len must larger than 32 bytes.\n");
		return;
	}

	memcpy(tmp_buf, hash1, SHA256_BLOCK_SIZE);
	memcpy(tmp_buf + SHA256_BLOCK_SIZE, hash2, SHA256_BLOCK_SIZE);
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, tmp_buf, strlen(tmp_buf));
	sha256_final(&ctx, buf);

	return;
}

PMHTNode get_the_right_most_child(PMHTNode node){
	const char* FUNC_NAME = "get_the_right_most_child";
	PMHTNode node_ptr = node;
	if(!check_pointer_ex(node, "node", FUNC_NAME, "null pointer")){
		return NULL;
	}

	while(node_ptr->m_level != NODELEVEL_LEAF) {
		node_ptr = node_ptr->m_rchild;
	}

	return node_ptr;
}

void print_mhtnode_info(PMHTNode mhtnode_ptr){
	if(!mhtnode_ptr)
		return;

	printf("Index|Level|ISN|LIdx|LLevel|RIdx|RLevel: %d|%d|%d|%d|%d|%d|%d\n", 
			mhtnode_ptr->m_pageNo, 
			mhtnode_ptr->m_level,
			(int)mhtnode_ptr->m_is_supplement_node,
			(mhtnode_ptr->m_lchild) ? (mhtnode_ptr->m_lchild)->m_pageNo : -1,
			(mhtnode_ptr->m_lchild) ? (mhtnode_ptr->m_lchild)->m_level : -1,
			(mhtnode_ptr->m_rchild) ? (mhtnode_ptr->m_rchild)->m_pageNo : -1,
			(mhtnode_ptr->m_rchild) ? (mhtnode_ptr->m_rchild)->m_level : -1);

	return;
}