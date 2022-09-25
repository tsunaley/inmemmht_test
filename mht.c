#include "mht.h"

void free_ds(IN PDATA_SET *pds){
	const char* FUNC_NAME = "free_ds";
	int i = 0;

	if(!check_pointer_ex(*pds, "*pds", FUNC_NAME, "null pointer"))
		return;

	for (i = 0; i < (*pds)->m_size; ++i)
	{
		if((*pds)->m_pDE[i].m_pdata){
			free((*pds)->m_pDE[i].m_pdata);
			(*pds)->m_pDE[i].m_pdata = NULL;
		}
	}

	free((*pds)->m_pDE); (*pds)->m_pDE = NULL;
	free(*pds); *pds = NULL;

	return;
}

int create_mht_from_ordered_ds_file(const char* filename, int block_num, int block_size){
	int ret_val = 0;

	return ret_val;
}

int create_mht_from_ordered_ds(IN PDATA_SET pds, OUT PMHTNode *pmhtroot){
	const char* FUNC_NAME = "create_mht_from_ordered_ds";
	int ret_val = 0;
	int i = 0;
	PMHTNode node = NULL;
	PMHTNode sub_root = NULL;
	PMHTNode sub_root2 = NULL;
	unsigned char* hash_buffer = NULL;
	SHA256_CTX ctx;
	PQNODE pQHeader = NULL;
	PQNODE pQ = NULL;	// tail
	PQNODE new_qnode = NULL;
	PQNODE popped_qnode_ptr = NULL;

	if (!check_pointer_ex(pds, "pds", FUNC_NAME, "Null pointer")){
		ret_val = -1;
		goto RETURN;
	}

	hash_buffer = (unsigned char*) malloc (SHA256_BLOCK_SIZE);
	initQueue(&pQHeader, &pQ);
	
	for(i = 0; i < pds->m_size; i++){
		if(!pds->m_is_hashed){	/* data within dataset is not hashed */
			/* calculating sha256 hash from string */
			sha256_init(&ctx);
			sha256_update(&ctx, (unsigned char*)(pds->m_pDE[i].m_pdata), pds->m_pDE[i].m_data_len);
			sha256_final(&ctx, hash_buffer);
		}
		else {
			memcpy(hash_buffer, (unsigned char*)(pds->m_pDE[i].m_pdata), SHA256_BLOCK_SIZE); /* pds->m_pDE[i].m_data_len is equal to SHA256_BLOCK_SIZE */
		}
		node = makeMHTNode(pds->m_pDE[i].m_index, NODELEVEL_LEAF, hash_buffer);
		new_qnode = makeQNode(node);
		check_pointer_ex(new_qnode, "new_qnode", FUNC_NAME, "null pointer");
		enqueue(&pQHeader, &pQ, new_qnode);
		
		process_queue(&pQHeader, &pQ);
	} // for
	
	if(pQHeader->m_qsize > 1){
		deal_with_remaining_nodes_in_queue(&pQHeader, &pQ);
	}

	//dequeue remaining nodes (actually, only root node remains)
	popped_qnode_ptr = dequeue(&pQHeader, &pQ);
	check_pointer_ex(popped_qnode_ptr, "popped_qnode_ptr", FUNC_NAME, "null pointer");
	print_qnode_info(popped_qnode_ptr);
	*pmhtroot = TOMHTNODE(popped_qnode_ptr);
	deleteQNode(&popped_qnode_ptr);

	freeQueue(&pQHeader, &pQ);

	/*
	while(popped_qnode_ptr = dequeue(&pQHeader, &pQ)){
		check_pointer_ex(popped_qnode_ptr, "popped_qnode_ptr", FUNC_NAME, "null pointer");
	
		print_qnode_info(popped_qnode_ptr);

		// free queue node
		deleteQNode(&popped_qnode_ptr);
	} //while
	*/

RETURN:	
	return ret_val;
}

int verify_spfc_dataelem_int(IN PMHTNode pmhtroot, IN int pgno){
	int ret_val = 0;

	return ret_val;
}

int process_queue(PQNODE *pQHeader, PQNODE *pQ){
	const char* FUNC_NAME = "process_queue";
	int ret_val = 0;
	bool bCombined = FALSE;
	bool bDequeueExec = FALSE;
	PQNODE qnode_ptr = NULL;
	PQNODE bkwd_ptr = NULL;
	PQNODE lchild_ptr = NULL, rchild_ptr = NULL;
	PQNODE cbd_qnode_ptr = NULL;
	PQNODE peeked_qnode_ptr = NULL;
	PQNODE popped_qnode_ptr = NULL;
	PMHTNode cbd_mhtnode_ptr = NULL;

	if(!check_pointer_ex(*pQHeader, "*pQHeader", FUNC_NAME, "null pointer") || 
		!check_pointer_ex(*pQ, "*pQ", FUNC_NAME, "null pointer")){
		return -1;
	}

	qnode_ptr = *pQ;
	while((bkwd_ptr = lookBackward(qnode_ptr)) && bkwd_ptr != *pQHeader){
		if(((PMHTNode)(bkwd_ptr->m_ptr))->m_level > ((PMHTNode)((*pQ)->m_ptr))->m_level)
			break;
		if(((PMHTNode)(bkwd_ptr->m_ptr))->m_level == ((PMHTNode)((*pQ)->m_ptr))->m_level) {
			lchild_ptr = bkwd_ptr;
			rchild_ptr = *pQ;
			cbd_mhtnode_ptr = combineNodes((PMHTNode)(lchild_ptr->m_ptr), (PMHTNode)(rchild_ptr->m_ptr));
			check_pointer_ex(cbd_mhtnode_ptr, "cbd_mhtnode_ptr", FUNC_NAME, "null pointer");
			cbd_qnode_ptr = makeQNode(cbd_mhtnode_ptr);
			bCombined = TRUE;
			check_pointer_ex(cbd_qnode_ptr, "cbd_qnode_ptr", FUNC_NAME, "null pointer");
			enqueue(pQHeader, pQ, cbd_qnode_ptr);
		}

		qnode_ptr = qnode_ptr->prev;
	}

	//dequeue till encountering the new created combined node
	if(bCombined) {
		while ((peeked_qnode_ptr = peekQueue(*pQHeader)) && 
			((PMHTNode)(peeked_qnode_ptr->m_ptr))->m_level < ((PMHTNode)(cbd_qnode_ptr->m_ptr))->m_level) {
			popped_qnode_ptr = dequeue(pQHeader, pQ);
			check_pointer_ex(popped_qnode_ptr, "popped_qnode_ptr", FUNC_NAME, "null pointer");

			// record the offset of the first supplementary leaf node
			if(((PMHTNode)(popped_qnode_ptr->m_ptr))->m_level == NODELEVEL_LEAF && 
				((PMHTNode)(popped_qnode_ptr->m_ptr))->m_pageNo >= UNASSIGNED_INDEX){
				// mark the supplementary leaf node
				((PMHTNode)(popped_qnode_ptr->m_ptr))->m_is_supplement_node = TRUE;
			}

			print_qnode_info(popped_qnode_ptr);

			deleteQNode(&popped_qnode_ptr);
			bDequeueExec = TRUE;
		} //while

		if(bDequeueExec){
			printf("\n\n");
		}

		bDequeueExec = FALSE;
		bCombined = FALSE;
	}// if

	return ret_val;
}

void deal_with_remaining_nodes_in_queue(PQNODE *pQHeader, PQNODE *pQ){
	const char* FUNC_NAME = "deal_with_remaining_nodes_in_queue";
	PQNODE qnode_ptr = NULL;
	PQNODE current_qnode_ptr = NULL;
	PQNODE bkwd_ptr = NULL;
	PQNODE cbd_qnode_ptr = NULL;
	PQNODE peeked_qnode_ptr = NULL;
	PQNODE popped_qnode_ptr = NULL;
	PQNODE lchild_ptr = NULL;
	PQNODE rchild_ptr = NULL;
	PMHTNode mhtnode_ptr = NULL;
	PMHTNode cbd_mhtnode_ptr = NULL;
	int last_mhtnode_index = UNASSIGNED_INDEX;
	int qHeaderLevel = 0;
	bool bCombined = FALSE;
	bool bDequeueExec = FALSE;	// whether dequeue is executed (for printf control)
	bool bEnctrFirstSplymtLeaf = FALSE;		// whether firstly encountering the first supplementary leaf
	char tmp_hash_buffer[SHA256_BLOCK_SIZE] = {0};
	uchar *mhtblk_buffer = NULL;

	// Both of these two pointer cannot be NULL.
	if(!*pQHeader || !*pQ){
		check_pointer_ex(*pQHeader, "*pQHeader", FUNC_NAME, "null pointer");
		check_pointer_ex(*pQ, "*pQ", FUNC_NAME, "null pointer");
		return;
	}

	// Queue cannot be empty.
	if(*pQHeader == *pQ){
		return debug_print(FUNC_NAME, "queue cannot be empty");
	}

	/* When pQ->level > pHeader->next->m_level, loop ends.
	Note that the loop ending condition reveals that the final root node
	has been created. */

	last_mhtnode_index = get_the_last_leaf_node_index(*pQHeader, *pQ);
	if(last_mhtnode_index == UNASSIGNED_INDEX){
		debug_print(FUNC_NAME, "Get the last MHT node's index failed");
		last_mhtnode_index = DEF_UPPER_BOUND_INDEX; // 0x70000000, there are 
	}
	// temporarily storing header level
	qHeaderLevel = ((PMHTNode)((*pQHeader)->next->m_ptr))->m_level;
	while(((PMHTNode)((*pQ)->m_ptr))->m_level <= qHeaderLevel){
		mhtnode_ptr = makeZeroMHTNode(++last_mhtnode_index);
		check_pointer(mhtnode_ptr, "mhtnode_ptr");
		qnode_ptr = makeQNode(mhtnode_ptr);
		check_pointer_ex(qnode_ptr, "qnode_ptr", FUNC_NAME, "null pointer");
		enqueue(pQHeader, pQ, qnode_ptr);

		current_qnode_ptr = *pQ;
		while((bkwd_ptr = lookBackward(current_qnode_ptr)) 
			&& bkwd_ptr != *pQHeader) {
			check_pointer_ex(bkwd_ptr, "bkwd_ptr", FUNC_NAME, "null pointer");
			if(((PMHTNode)(bkwd_ptr->m_ptr))->m_level > ((PMHTNode)((*pQ)->m_ptr))->m_level)
				break;
			if(((PMHTNode)(bkwd_ptr->m_ptr))->m_level == ((PMHTNode)((*pQ)->m_ptr))->m_level) {
				lchild_ptr = bkwd_ptr;
				rchild_ptr = *pQ;
				cbd_mhtnode_ptr = combineNodes((PMHTNode)(lchild_ptr->m_ptr), (PMHTNode)(rchild_ptr->m_ptr));
				cbd_qnode_ptr = makeQNode(cbd_mhtnode_ptr);
				bCombined = TRUE;
				check_pointer_ex(cbd_qnode_ptr, "cbd_qnode_ptr", FUNC_NAME, "null pointer");
				enqueue(pQHeader, pQ, cbd_qnode_ptr);
			} //if
			current_qnode_ptr = current_qnode_ptr->prev;
		} // while
		if(bCombined) {	
			while((peeked_qnode_ptr = peekQueue(*pQHeader)) && 
				   TOMHTNODE(peeked_qnode_ptr)->m_level < TOMHTNODE(cbd_qnode_ptr)->m_level) {
				popped_qnode_ptr = dequeue(pQHeader, pQ);
				check_pointer_ex(popped_qnode_ptr, "popped_qnode_ptr", FUNC_NAME, "null pointer");
				
				print_qnode_info(popped_qnode_ptr);

				deleteQNode(&popped_qnode_ptr);
				bDequeueExec = TRUE;
			} // while

			if(bDequeueExec){
				printf("\n\n");
			}

			bDequeueExec = FALSE;
			bCombined = FALSE;
		}// if
	} // while
}

int get_the_last_leaf_node_index(PQNODE pQHeader, PQNODE pQ){
	const char* FUNC_NAME = "get_the_last_leaf_node_index";
	PQNODE node_ptr = NULL;
	PMHTNode mhtnode_ptr = NULL;

	if(!check_pointer_ex(pQHeader, "pQHeader", FUNC_NAME, "null pointer") || 
		!check_pointer_ex(pQ, "pQ", FUNC_NAME, "null pointer")){
		return UNASSIGNED_INDEX;
	}

	node_ptr = pQ;
	while(node_ptr != pQHeader){
		mhtnode_ptr = (PMHTNode)(node_ptr->m_ptr);
		if(mhtnode_ptr->m_level == NODELEVEL_LEAF)
			return mhtnode_ptr->m_pageNo;
		node_ptr = node_ptr->prev;
	}

	return UNASSIGNED_INDEX;
}

void print_mht_preorder(PMHTNode pmhtroot){
	if(!pmhtroot){
		return;
	}

	print_mhtnode_info(pmhtroot);
	print_mht_preorder(pmhtroot->m_lchild);
	print_mht_preorder(pmhtroot->m_rchild);
}

void free_mht_postorder(PMHTNode *pmhtroot){
	if(!*pmhtroot){
		return;
	}

	free_mht_postorder(&((*pmhtroot)->m_lchild));
	free_mht_postorder(&((*pmhtroot)->m_rchild));
	if(!*pmhtroot){
		free(*pmhtroot);
		*pmhtroot = NULL;
	}
}