#ifndef _DBQUEUE
#define _DBQUEUE

#include "defs.h"
#include "mhtdefs.h"

#define PRINT_QNODE_FLAG_INDEX	0x00000001
#define PRINT_QNODE_FLAG_HASH	0x00000002
#define PRINT_QNODE_FLAG_LEVEL	0x00000004

typedef struct _QNODE
{
	union {
		void* m_ptr;
		int m_qsize;
	};
	
	struct _QNODE* next;
	struct _QNODE* prev;
} QNODE, *PQNODE;

PQNODE makeQHeader();

PQNODE makeQNode(PMHTNode pmhtnode);

void deleteQNode(PQNODE *node_ptr);

PQNODE lookBackward(PQNODE pNode);

PQNODE search_node_by_level(PQNODE pQHeader, PQNODE pQ, int level);

void initQueue(PQNODE *pQHeader, PQNODE *pQ);

PQNODE enqueue(PQNODE *pQHeader, PQNODE *pQ, PQNODE pNode);

PQNODE dequeue(PQNODE *pQHeader, PQNODE *pQ);

PQNODE dequeue_sub(PQNODE *pQHeader, PQNODE *pQ);

PQNODE dequeue_sppos(PQNODE *pQHeader, PQNODE *pQ, PQNODE pos);

PQNODE peekQueue(PQNODE pQHeader);

void freeQueue(PQNODE *pQHeader, PQNODE *pQ);

void freeQueue2(PQNODE *pQHeader);

void freeQueue3(PQNODE *pQ);

void printQueue(PQNODE pQHeader);

void print_qnode_info(PQNODE qnode_ptr);

void print_qnode_info_ex(PQNODE qnode_ptr, uint32 flags);

#endif