#include "defs.h"
#include "mhtdefs.h"
#include "sha256.h"
#include "dbqueue.h"

PQNODE makeQHeader() {
	PQNODE node_ptr = NULL;
	node_ptr = (PQNODE) malloc(sizeof(QNODE));
	if(node_ptr == NULL)
		return NULL;
	node_ptr->m_qsize = 0;
	node_ptr->prev = NULL;
	node_ptr->next = NULL;

	return node_ptr;
}

PQNODE makeQNode(PMHTNode pmhtnode){
	PQNODE node_ptr = NULL;
	if(pmhtnode == NULL)
		return NULL;
	node_ptr = (PQNODE) malloc (sizeof(QNODE));
	if(node_ptr == NULL)
		return NULL;
	node_ptr->m_ptr = (void*)pmhtnode;
	node_ptr->prev = NULL;
	node_ptr->next = NULL;

	return node_ptr;
}


void deleteQNode(PQNODE *node_ptr){
	if(*node_ptr){
		/* NOTE: the MHT node within the queue node will NOT be released */
		(*node_ptr)->m_ptr ? (*node_ptr)->m_ptr = NULL : nop();
		free(*node_ptr);
		*node_ptr = NULL;
	}

	return;
}

PQNODE lookBackward(PQNODE pNode){
	if(!pNode)
		return NULL;

	if(!pNode->prev) {	//header node
		return NULL;
	}

	return pNode->prev;
}

PQNODE search_node_by_level(PQNODE pQHeader, PQNODE pQ, int level){
	const char* FUNC_NAME = "search_node_by_level";
	PQNODE tmp_ptr = NULL;
	PMHTNode mhtnode_ptr = NULL;

	if(!check_pointer_ex(pQHeader, "pQHeader", FUNC_NAME, "null pointer") || 
		!check_pointer_ex(pQ, "pQ", FUNC_NAME, "null pointer"))
		return NULL;

	if(level < 0){
		debug_print(FUNC_NAME, "level cannot be less than zero");
		return NULL;
	}

	tmp_ptr = pQ;
	while(tmp_ptr != pQHeader){
		mhtnode_ptr = (PMHTNode)(tmp_ptr->m_ptr);
		if(mhtnode_ptr->m_level == level)
			return tmp_ptr;

		tmp_ptr = tmp_ptr->prev;
	}

	return NULL;
}

void initQueue(PQNODE *pQHeader, PQNODE *pQ){
	if(*pQHeader != NULL){
		free(*pQHeader);
		*pQHeader = NULL;
	}

	(*pQHeader) = makeQHeader();
	*pQ = *pQHeader;
	return;
}

PQNODE enqueue(PQNODE *pQHeader, PQNODE *pQ, PQNODE pNode){
	if(*pQHeader == NULL && *pQ == NULL && pNode == NULL)
		return NULL;
	(*pQ)->next = pNode;
	pNode->prev = *pQ;
	pNode->next = NULL;
	*pQ = pNode;
	(*pQHeader)->m_qsize++;

	return pNode;
}

PQNODE dequeue(PQNODE *pQHeader, PQNODE *pQ){
	PQNODE tmp_ptr = NULL;
	if(*pQ == *pQHeader){	// empty queue
		printf("Empty queue.\n");
		return NULL;
	}
	tmp_ptr = (*pQHeader)->next;
	(*pQHeader)->next = tmp_ptr->next;
	if(tmp_ptr->next)	//otherwise, tmp_ptr == pQ.
		tmp_ptr->next->prev = *pQHeader;
	else
		*pQ = *pQHeader;

	(*pQHeader)->m_qsize > 0 ? (*pQHeader)->m_qsize-- : nop();

	return tmp_ptr;
}

PQNODE dequeue_sub(PQNODE *pQHeader, PQNODE *pQ){
	PQNODE tmp_ptr = NULL;
	PQNODE first_elem_ptr = NULL;
	if(*pQ == *pQHeader){	// empty queue
		printf("Empty queue.\n");
		return NULL;
	}

	first_elem_ptr = (*pQHeader)->next;
	tmp_ptr = first_elem_ptr->next;
	if(!tmp_ptr) {
		check_pointer_ex(tmp_ptr, "tmp_ptr", "dequeue_sub", "null second element pointer");
		return NULL;
	}

	first_elem_ptr->next = tmp_ptr->next;
	if(tmp_ptr->next)	//otherwise, tmp_ptr == pQ.
		tmp_ptr->next->prev = first_elem_ptr;
	else
		*pQ = first_elem_ptr;

	(*pQHeader)->m_qsize > 0 ? (*pQHeader)->m_qsize-- : nop();

	return tmp_ptr;
}

PQNODE dequeue_sppos(PQNODE *pQHeader, PQNODE *pQ, PQNODE pos) {
	PQNODE tmp_ptr = NULL;
	
	if(*pQ == *pQHeader){	// empty queue
		printf("Empty queue.\n");
		return NULL;
	}

	if(pos == (*pQHeader)){   // invalid position
		printf("Invalid dequeue position.\n");
		return NULL;
	}

	tmp_ptr = pos;
	if(pos->next) {
		pos->prev->next = pos->next;
		pos->next->prev = pos->prev;
	}
	else{
		return dequeue(pQHeader, pQ);
	}
	
	(*pQHeader)->m_qsize > 0 ? (*pQHeader)->m_qsize-- : nop();

	return tmp_ptr;
}

PQNODE peekQueue(PQNODE pQHeader){
	if(pQHeader && pQHeader->next)
		return (PQNODE)(pQHeader->next);
	return NULL;
}

void freeQueue(PQNODE *pQHeader, PQNODE *pQ) {
	PQNODE tmp_ptr = NULL;
	if(!(*pQHeader))
		return;
	tmp_ptr = (*pQHeader)->next;
	if(!tmp_ptr){
		free(*pQHeader);
		*pQHeader = NULL;
		return;
	}
	while(tmp_ptr = dequeue(pQHeader, pQ)){
		/* NOTE: this function will release the memory that m_ptr takes */
		tmp_ptr->m_ptr != NULL ? free(tmp_ptr->m_ptr) : nop();
		free(tmp_ptr);
		tmp_ptr = NULL;
	}
	free(*pQHeader);
	*pQHeader = NULL;
	return;
}

void freeQueue2(PQNODE *pQHeader){
	PQNODE tmp_ptr = NULL;
	if(!(*pQHeader))
		return;
	tmp_ptr = (*pQHeader)->next;
	if(!tmp_ptr){
		free(*pQHeader);
		*pQHeader = NULL;
		return;
	}
	while(tmp_ptr = ((*pQHeader)->next)){
		(*pQHeader)->next = tmp_ptr->next;
		if(tmp_ptr->next) {
			tmp_ptr->next->prev = *pQHeader;
			/* NOTE: this function will release the memory that m_ptr takes */
			tmp_ptr->m_ptr != NULL ? free(tmp_ptr->m_ptr) : nop();
			free(tmp_ptr);
		}
	}
	free(*pQHeader);
	*pQHeader = NULL;
	return;
}

void freeQueue3(PQNODE *pQ) {
	PQNODE tmp_ptr = NULL;
	if(!(*pQ))
		return;
	tmp_ptr = *pQ;
	do{
		tmp_ptr = tmp_ptr->prev;
		if(tmp_ptr->prev == NULL)	//tmp_ptr == pQHeader
			break;
	}while(tmp_ptr);

	return freeQueue2(&tmp_ptr);
}

/********* Test & Debug ********/

void printQueue(PQNODE pQHeader) {
	PQNODE tmp_ptr = NULL;
	PMHTNode mhtnode_ptr = NULL;
	uint32 i = 1;

	if(!pQHeader){
		check_pointer(pQHeader, "printQueue: pQHeader");
		return;
	}

	tmp_ptr = pQHeader->next;
	while(tmp_ptr){
		mhtnode_ptr = (PMHTNode)(tmp_ptr->m_ptr);
		printf("%d: PageNo-Level: %d-%d\n", i, mhtnode_ptr->m_pageNo, mhtnode_ptr->m_level);
		tmp_ptr = tmp_ptr->next;
		i++;
	}

	return;
}


void print_qnode_info(PQNODE qnode_ptr){
	if(!qnode_ptr){
		check_pointer(qnode_ptr, "qnode_ptr");
		debug_print("print_qnode_info", "Null parameters");
		return;
	}

	PMHTNode mhtnode_ptr = (PMHTNode)(qnode_ptr->m_ptr);

	printf("PageNo|Level|ISN|LIdx|LLevel|RIdx|RLevel: %d|%d|%d|%d|%d|%d|%d\n", 
			mhtnode_ptr->m_pageNo, 
			mhtnode_ptr->m_level,
			(int)mhtnode_ptr->m_is_supplement_node,
			(mhtnode_ptr->m_lchild) ? (mhtnode_ptr->m_lchild)->m_pageNo : -1,
			(mhtnode_ptr->m_lchild) ? (mhtnode_ptr->m_lchild)->m_level : -1,
			(mhtnode_ptr->m_rchild) ? (mhtnode_ptr->m_rchild)->m_pageNo : -1,
			(mhtnode_ptr->m_rchild) ? (mhtnode_ptr->m_rchild)->m_level : -1);

	return;
}

void print_qnode_info_ex(PQNODE qnode_ptr, uint32 flags){
	const char* FUNC_NAME = "printQNode";

	if(!qnode_ptr){
		check_pointer_ex(qnode_ptr, "qnode_ptr", FUNC_NAME, "null qnode_ptr");
		return;
	}

	PMHTNode mhtnode_ptr = (PMHTNode)(qnode_ptr->m_ptr);

	printf("[");
	if(flags && PRINT_QNODE_FLAG_INDEX){
		printf("index: %d, ", mhtnode_ptr->m_pageNo);
	}
	if(flags && PRINT_QNODE_FLAG_HASH){
		print_hash_value(mhtnode_ptr->m_hash);
	}
}
