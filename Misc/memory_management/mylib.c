#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

struct FreeNode{
	unsigned long size;
	struct FreeNode* next;
	struct FreeNode* prev;
	void* memory;
};

struct FreeNode head;

void *memalloc(unsigned long size) 
{

	printf("memalloc() called\n");
	if (size == 0) return NULL;

	head.size = 0;
	head.prev = NULL;

	struct FreeNode* ptr_prev = &head;
	struct FreeNode* ptr = ptr_prev->next;
	unsigned long MEMVAL = sizeof(unsigned long) + 2 * sizeof(struct FreeNode *);

	size = size + (8 - size % 8) % 8 + sizeof(unsigned long);
	if(size < MEMVAL) size = MEMVAL;

	while(ptr){

		if (ptr->size >= size)
		{
			struct FreeNode* next_ptr = ptr->next;

			if(ptr->size < size + MEMVAL)
			{
				if (next_ptr) next_ptr->prev = ptr_prev;
				ptr_prev->next = next_ptr;	
			}

			else
			{
				struct FreeNode* new_free_node = (struct FreeNode *) ((char *) ptr + size);

				if (next_ptr) next_ptr->prev = ptr_prev;
				ptr_prev->next = next_ptr;	

				new_free_node->size = ptr->size - size;
				new_free_node->next = (&head)->next;
				new_free_node->prev = (&head);
				new_free_node->memory = (void *) ((char *) ptr + size + sizeof(unsigned long) + 2 * sizeof(struct FreeNode *));
				
				if(head.next)
				{
					head.next->prev = new_free_node;
				}
				(&head)->next = new_free_node;

				* (unsigned long *) ptr = size;
			}

			void* ret_mem = (unsigned long *) ptr + 1;
			return ret_mem;
		}

		else
		{
			ptr_prev = ptr_prev->next;
			ptr = ptr->next;
		} 
	}

	if (ptr == NULL)
	{

		unsigned long req_size = (size / (4096 * 1024))*(4096 * 1024);
		if (size % (4096 * 1024)) req_size += 4096 * 1024;

		char *mem = mmap(NULL, req_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if(mem == MAP_FAILED){
			perror("mmap");
			exit(-1);
		}

		* (unsigned long *) mem = size;
		void* ret_mem = (unsigned long *) mem + 1;

		struct FreeNode* new_free_mem = (struct FreeNode*) ((char *) mem + size);
		new_free_mem->size = req_size - size;
		new_free_mem->next = head.next;
		new_free_mem->prev = (&head);
		new_free_mem->memory = (void *) ((char *) mem + size + sizeof(unsigned long) + 2 * sizeof(struct FreeNode *));

		if(head.next)
		{
			head.next->prev = new_free_mem;
		}
		head.next = new_free_mem;

		return ret_mem;
	}

	return NULL;
}

int memfree(void *ptr)
{
	unsigned long curr_sz = * ((unsigned long *) ptr - 1);
	struct FreeNode* new_node = (struct FreeNode *)((unsigned long *) ptr - 1);

	struct FreeNode* start = (struct FreeNode *) ((unsigned long *) ptr - 1);
	struct FreeNode* end = (struct FreeNode*) ((char *) start + curr_sz);
	
	struct FreeNode* prev_ptr = &head;
	struct FreeNode* curr_ptr = prev_ptr->next;

	new_node->size = curr_sz;
	new_node->prev = &head;
	new_node->next = NULL;
	new_node->memory = (void *)((struct FreeNode **) ptr + 2);

	while(curr_ptr)
	{
		struct FreeNode* next_ptr = curr_ptr->next;

		// right contigious node
		if (curr_ptr == end)
		{
			new_node->size = new_node->size + curr_ptr->size;
			prev_ptr->next = next_ptr;
			if(next_ptr) next_ptr->prev = prev_ptr;
		}

		// left contigious node
		struct FreeNode* curr_end = (struct FreeNode *) ((char *) curr_ptr + curr_ptr->size);
		if(curr_end == start)
		{
			new_node->size = new_node->size + curr_ptr->size;
			new_node->memory = curr_ptr->memory;
			prev_ptr->next = next_ptr;
			if(next_ptr) next_ptr->prev = prev_ptr;
		}

		curr_ptr = curr_ptr->next;
		prev_ptr = prev_ptr->next;
	}

	head.next->prev = new_node;
	new_node->next = head.next;
	head.next = new_node;

	printf("memfree() called\n");
	return 0;
}	