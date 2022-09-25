#ifndef MHT_H
#define MHT_H

#include "defs.h"
#include "mhtdefs.h"
#include "dataelem.h"
#include "sha256.h"
#include "dbqueue.h"

#define TOMHTNODE(x)    ((PMHTNode)((x)->m_ptr))

typedef struct _DATA_SET {
	PDATA_ELEM m_pDE;
	int m_size;
    bool m_is_hashed;
} DATA_SET, *PDATA_SET;

void free_ds(IN PDATA_SET *pds);

/**
 * @brief      Creates an MHT from a dataset with ordered indices.
 *
 * @param[in]  pds       The pointer to the dataset array
 * @param      pmhtnode  The pointer to the root node of the created MHT
 *
 * @return     { 0 if successful }
 */
int create_mht_from_ordered_ds(IN PDATA_SET pds, OUT PMHTNode *pmhtroot);

/**
 * @brief      Verifies the integrity of the specific data element (a leaf node of the MHT)
 *
 * @param[in]  pmht  The pointer to the root of the MHT
 *
 * @return     { 0 if successful }
 */
int verify_spfc_dataelem_int(IN PMHTNode pmhtroot, IN int pgno);

int process_queue(PQNODE *pQHeader, PQNODE *pQ);

void deal_with_remaining_nodes_in_queue(PQNODE *pQHeader, PQNODE *pQ);

int get_the_last_leaf_node_index(PQNODE pQHeader, PQNODE pQ);

void print_mht_preorder(PMHTNode pmhtroot);

void free_mht_postorder(PMHTNode *pmhtroot);

#endif