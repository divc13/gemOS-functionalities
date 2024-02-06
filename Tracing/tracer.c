#include <context.h>
#include <memory.h>
#include <lib.h>
#include <entry.h>
#include <file.h>
#include <tracer.h>
///////////////////////////////////////////////////////////////////////////
//// 		Start of Trace buffer functionality 		      /////
///////////////////////////////////////////////////////////////////////////

int current_pid;

int is_valid_mem_range(unsigned long buff, u32 count, int access_bit)
{
	struct exec_context *current = get_current_ctx();
	struct mm_segment *mms = current->mms;
	int access_R = access_bit % 2;
	int access_W = (access_bit % 4) / 2;
	int access_X = access_bit / 4;

	for (int i = 0; i < 3; i++)
	{
		if (buff >= mms[i].start && buff + count < mms[i].next_free)
		{
			int allowed_R = (mms[i].access_flags) % 2;
			int allowed_W = (mms[i].access_flags % 4) / 2;
			int allowed_X = (mms[i].access_flags) / 4;
			if (access_W > allowed_W)
				return -1;
			if (access_R > allowed_R)
				return -1;
			if (access_X > allowed_X)
				return -1;
			return 0;
		}
	}

	if (buff >= mms[3].start && buff + count < mms[3].end)
	{
		int allowed_R = (mms[3].access_flags) % 2;
		int allowed_W = (mms[3].access_flags % 4) / 2;
		int allowed_X = (mms[3].access_flags) / 4;
		if (access_W > allowed_W)
			return -1;
		if (access_R > allowed_R)
			return -1;
		if (access_X > allowed_X)
			return -1;
		return 0;
	}

	struct vm_area *vma = current->vm_area;
	while (vma != NULL)
	{
		if (buff >= vma->vm_start && buff + count < vma->vm_end)
		{
			int allowed_R = (vma->access_flags) % 2;
			int allowed_W = (vma->access_flags % 4) / 2;
			int allowed_X = (vma->access_flags) / 4;
			if (access_W > allowed_W)
				return -1;
			if (access_R > allowed_R)
				return -1;
			if (access_X > allowed_X)
				return -1;
			return 0;
		}
		vma = vma->vm_next;
	}
	return -1;
}

long trace_buffer_close(struct file *filep)
{
	if(!filep) return -EINVAL;
	if(!(filep->trace_buffer)) return -EINVAL;
	if(!(filep->trace_buffer->buffer)) return -EINVAL;
	if(!(filep->fops)) return -EINVAL;


	os_free(filep->fops, sizeof(struct fileops));
	os_page_free(USER_REG, filep->trace_buffer->buffer);
	os_free(filep->trace_buffer, sizeof(struct trace_buffer_info));
	os_page_free(USER_REG, filep);
	return 0;
}

int trace_buffer_read(struct file *filep, char *buff, u32 count)
{
	if (is_valid_mem_range((unsigned long)buff, count, 2) != 0)
		return -EBADMEM;

	u32 tb_writer = filep->trace_buffer->writer;
	u32 tb_reader = filep->trace_buffer->reader;
	char *tb_buff = filep->trace_buffer->buffer;
	u32 max_bytes = count;

	int diff = tb_writer - tb_reader;
	if ((diff == 0 && filep->trace_buffer->isFull == 1) || diff < 0)
		diff += TRACE_BUFFER_MAX_SIZE;
	if (max_bytes > diff)
		max_bytes = diff;
	if (filep->trace_buffer->isFull == 0 && diff == 0)
		max_bytes = 0;
	if (max_bytes == 0)
		return 0;

	for (int i = 0; i < max_bytes; i++)
	{
		buff[i] = tb_buff[tb_reader];
		tb_reader++;
		tb_reader %= TRACE_BUFFER_MAX_SIZE;
	}
	filep->trace_buffer->reader = tb_reader;
	filep->offp = tb_reader;
	filep->trace_buffer->isFull = 0;

	return max_bytes;
}

int trace_buffer_write(struct file *filep, char *buff, u32 count)
{
	if (is_valid_mem_range((unsigned long)buff, count, 1) != 0)
		return -EBADMEM;

	if (filep == NULL)
	{
		return -EINVAL;
	}

	u32 tb_writer = filep->trace_buffer->writer;
	u32 tb_reader = filep->trace_buffer->reader;
	char *tb_buff = filep->trace_buffer->buffer;
	u32 max_bytes = count;

	int diff = tb_reader - tb_writer;
	if ((diff == 0 && filep->trace_buffer->isFull == 0) || diff < 0)
		diff += TRACE_BUFFER_MAX_SIZE;
	if (max_bytes > diff)
		max_bytes = diff;
	if (filep->trace_buffer->isFull == 1)
		max_bytes = 0; // sanity check

	if (max_bytes == 0)
		return 0;

	for (int i = 0; i < max_bytes; i++)
	{
		tb_buff[tb_writer] = buff[i];
		tb_writer++;
		tb_writer %= TRACE_BUFFER_MAX_SIZE;
	}

	filep->trace_buffer->writer = tb_writer;
	filep->offp = tb_writer;
	if (tb_reader == tb_writer)
		filep->trace_buffer->isFull = 1;

	return max_bytes;
}

int sys_create_trace_buffer(struct exec_context *current, int mode)
{
	if (!current)
		return -EINVAL;

	int fd = 0;
	for (fd = 0; fd < MAX_OPEN_FILES; fd++)
		if ((current->files)[fd] == NULL)
			break;

	if (fd == MAX_OPEN_FILES)
		return -EINVAL;

	struct trace_buffer_info *TraceBuffer = (struct trace_buffer_info *)os_alloc(sizeof(struct trace_buffer_info));
	if (!TraceBuffer)
		return -ENOMEM;

	TraceBuffer->buffer = (char *)os_page_alloc(USER_REG);
	if (!(TraceBuffer->buffer))
		return -ENOMEM;

	TraceBuffer->reader = 0;
	TraceBuffer->writer = 0;
	TraceBuffer->isFull = 0;

	struct fileops *FileOps = (struct fileops *)os_alloc(sizeof(struct fileops));
	if (!FileOps)
		return -ENOMEM;

	struct file *filep = (struct file *)os_page_alloc(USER_REG);
	if (!filep)
		return -ENOMEM;

	filep->offp = 0;
	filep->ref_count = 1;
	filep->type = TRACE_BUFFER;
	filep->mode = mode;
	filep->trace_buffer = TraceBuffer;
	filep->fops = FileOps;

	filep->fops->close = trace_buffer_close;
	filep->fops->lseek = NULL;
	filep->fops->read = NULL;
	filep->fops->write = NULL;

	if (mode == O_READ)
		filep->fops->read = trace_buffer_read;
	else if (mode == O_WRITE)
		filep->fops->write = trace_buffer_write;
	else
	{
		filep->fops->write = trace_buffer_write;
		filep->fops->read = trace_buffer_read;
	}

	current->files[fd] = filep;
	return fd;
}
///////////////////////////////////////////////////////////////////////////
////		Added Functions					//////////////////////////////
//////////////////////////////////////////////////////////////////////////

int TraceBufferReader(struct file *filep, char *buff, u32 count)
{
	u32 tb_writer = filep->trace_buffer->writer;
	u32 tb_reader = filep->trace_buffer->reader;
	char *tb_buff = filep->trace_buffer->buffer;
	u32 max_bytes = count;

	int diff = tb_writer - tb_reader;
	if ((diff == 0 && filep->trace_buffer->isFull == 1) || diff < 0)
		diff += TRACE_BUFFER_MAX_SIZE;
	if (max_bytes > diff)
		max_bytes = diff;
	if (filep->trace_buffer->isFull == 0 && diff == 0)
		max_bytes = 0;
	if (max_bytes == 0)
		return 0;

	for (int i = 0; i < max_bytes; i++)
	{
		buff[i] = tb_buff[tb_reader];
		tb_reader++;
		tb_reader %= TRACE_BUFFER_MAX_SIZE;
	}
	filep->trace_buffer->reader = tb_reader;
	filep->offp = tb_reader;
	filep->trace_buffer->isFull = 0;

	return max_bytes;
}

int TraceBufferWriter(struct file *filep, char *buff, u32 count)
{
	if (filep == NULL)
	{
		return -EINVAL;
	}

	u32 tb_writer = filep->trace_buffer->writer;
	u32 tb_reader = filep->trace_buffer->reader;
	char *tb_buff = filep->trace_buffer->buffer;
	u32 max_bytes = count;

	int diff = tb_reader - tb_writer;
	if ((diff == 0 && filep->trace_buffer->isFull == 0) || diff < 0)
		diff += TRACE_BUFFER_MAX_SIZE;
	if (max_bytes > diff)
		max_bytes = diff;
	if (filep->trace_buffer->isFull == 1)
		max_bytes = 0; // sanity check

	if (max_bytes == 0)
		return 0;

	for (int i = 0; i < max_bytes; i++)
	{
		tb_buff[tb_writer] = buff[i];
		tb_writer++;
		tb_writer %= TRACE_BUFFER_MAX_SIZE;
	}

	filep->trace_buffer->writer = tb_writer;
	filep->offp = tb_writer;
	if (tb_reader == tb_writer)
		filep->trace_buffer->isFull = 1;

	return max_bytes;
}

int get_args(u64 syscall_number)
{
	int n_args[70];
	for (int i = 0; i < 70; i++)
		n_args[i] = -1;

	n_args[SYSCALL_CFORK] = 0;
	n_args[SYSCALL_CLONE] = 2;
	n_args[SYSCALL_CLOSE] = 1;
	n_args[SYSCALL_CONFIGURE] = 1;
	n_args[SYSCALL_DUMP_PTT] = 1;
	n_args[SYSCALL_DUP2] = 2;
	n_args[SYSCALL_DUP] = 1;
	n_args[SYSCALL_END_STRACE] = 0;
	n_args[SYSCALL_EXIT] = 1;
	n_args[SYSCALL_EXPAND] = 2;
	n_args[SYSCALL_FORK] = 0;
	n_args[SYSCALL_FTRACE] = 4;
	n_args[SYSCALL_GET_COW_F] = 0;
	n_args[SYSCALL_GET_USER_P] = 0;
	n_args[SYSCALL_GETPID] = 0;
	n_args[SYSCALL_LSEEK] = 3;
	n_args[SYSCALL_MMAP] = 4;
	n_args[SYSCALL_MPROTECT] = 3;
	n_args[SYSCALL_MUNMAP] = 2;
	n_args[SYSCALL_OPEN] = 2;
	n_args[SYSCALL_PHYS_INFO] = 0;
	n_args[SYSCALL_PMAP] = 1;
	n_args[SYSCALL_READ] = 3;
	n_args[SYSCALL_READ_FTRACE] = 3;
	n_args[SYSCALL_READ_STRACE] = 3;
	n_args[SYSCALL_SIGNAL] = 2;
	n_args[SYSCALL_SLEEP] = 1;
	n_args[SYSCALL_START_STRACE] = 2;
	n_args[SYSCALL_STATS] = 0;
	n_args[SYSCALL_STRACE] = 2;
	n_args[SYSCALL_TRACE_BUFFER] = 1;
	n_args[SYSCALL_VFORK] = 0;
	n_args[SYSCALL_WRITE] = 3;

	return n_args[syscall_number];
}

///////////////////////////////////////////////////////////////////////////
//// 		Start of strace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

int perform_tracing(u64 syscall_num, u64 param1, u64 param2, u64 param3, u64 param4)
{
	struct exec_context *current = get_current_ctx();
	if (current_pid != current->pid)
		return 0;

	if(current->st_md_base == NULL)
	{
		current->st_md_base = (struct strace_head*)os_alloc(sizeof(struct strace_head));
		current->st_md_base->count = 0;
		current->st_md_base->is_traced = 0;
		current->st_md_base->next = NULL;
		current->st_md_base->last = NULL;
		return 0;
	}

	struct strace_head *StraceHead = current->st_md_base;
	if (StraceHead->is_traced == 0)
		return 0;

	if (syscall_num == SYSCALL_END_STRACE || syscall_num == SYSCALL_START_STRACE)
		return 0;

	struct file *filep = current->files[StraceHead->strace_fd];
	int tracing_mode = StraceHead->tracing_mode;

	if (tracing_mode == FILTERED_TRACING)
	{
		struct strace_info *StraceInfo = StraceHead->next;
		int cnt = StraceHead->count;
		int found = 0;
		for (int i = 0; i < cnt; i++)
		{
			if (StraceInfo->syscall_num == syscall_num)
			{
				found = 1;
				break;
			}
			StraceInfo = StraceInfo->next;
		}
		if (found == 0)
			return 0;
	}

	int val = TraceBufferWriter(filep, (char *)&syscall_num, 8);

	if (get_args(syscall_num) > 0)
		TraceBufferWriter(filep, (char *)&param1, 8);
	if (get_args(syscall_num) > 1)
		TraceBufferWriter(filep, (char *)&param2, 8);
	if (get_args(syscall_num) > 2)
		TraceBufferWriter(filep, (char *)&param3, 8);
	if (get_args(syscall_num) > 3)
		TraceBufferWriter(filep, (char *)&param4, 8);

	return 0;
}

int sys_strace(struct exec_context *current, int syscall_num, int action)
{
	if(current->st_md_base == NULL)
	{
		current->st_md_base = (struct strace_head*)os_alloc(sizeof(struct strace_head));
		current->st_md_base->count = 0;
		current->st_md_base->is_traced = 0;
		current->st_md_base->next = NULL;
		current->st_md_base->last = NULL;
	}

	struct strace_head *StraceHead = current->st_md_base;

	int cnt = StraceHead->count;
	struct strace_info *StraceInfoHead = StraceHead->next;

	if (action == ADD_STRACE)
	{
		struct strace_info *StraceInfo = StraceInfoHead;
		for (int i = 0; i < cnt; i++)
		{
			if (StraceInfo->syscall_num == syscall_num)
				return -EINVAL;
			StraceInfo = StraceInfo->next;
		}
		if (cnt == STRACE_MAX)
			return -EINVAL;

		struct strace_info *newStraceInfo = (struct strace_info *)os_alloc(sizeof(struct strace_info));
		if(!newStraceInfo) return -EINVAL;

		newStraceInfo->syscall_num = syscall_num;

		if (cnt == 0)
		{
			newStraceInfo->next = NULL;
			StraceHead->next = newStraceInfo;
			StraceHead->last = newStraceInfo;
		}
		else
		{
			newStraceInfo->next = StraceHead->next;
			StraceHead->next = newStraceInfo;
		}
		StraceHead->count = cnt + 1;
		return 0;
	}

	else if (action == REMOVE_STRACE)
	{
		if(cnt <= 0) return -EINVAL; 
		struct strace_info *StraceInfo = StraceInfoHead;
		int i = 0;
		for (i = 0; i < cnt; i++)
		{
			if (StraceInfo->syscall_num == syscall_num)
				break;
			StraceInfo = StraceInfo->next;
		}

		if (i == cnt)
			return -EINVAL;
		if (cnt == 1)
		{
			os_free(StraceHead->next, sizeof(struct strace_info));
			StraceHead->next = NULL;
			StraceHead->last = NULL;
		}
		else if (i==0)
		{
			StraceInfo = StraceHead->next;
			StraceHead->next = StraceHead->next->next;
			os_free(StraceInfo, sizeof(struct strace_info));
		}
		else
		{
			StraceInfo = StraceHead->next;
			for (int j = 0; j < i - 1; j++)
				StraceInfo = StraceInfo->next;

			struct strace_info* ToDel = StraceInfo->next;
			StraceInfo->next = StraceInfo->next->next;
			if (!StraceInfo->next)
				StraceHead->last = StraceInfo;
			os_free(ToDel, sizeof(struct strace_info));

		}
		StraceHead->count = cnt - 1;
		return 0;
	}

	return -EINVAL;
}

int sys_read_strace(struct file *filep, char *buff, u64 count)
{
	int bytes_read = 0, val = 0;
	if (count < 0) return -EINVAL;
	for (int i = 0; i < count; i++)
	{
		val = TraceBufferReader(filep, buff + bytes_read, 8);
		if (val < 0){
			return -EINVAL;
		}
		if(val != 8)
		{
			return bytes_read;
		}

		u64 syscall_num = ((u64*)(buff+bytes_read))[0];

		// printk("----------------------------------\n");
		// printk("Iteration number = %d\n", i);

		// printk("----------------------------------\n");

		bytes_read += val;

		if (get_args(syscall_num) > 0)
		{
			val = TraceBufferReader(filep, buff + bytes_read, 8);
			if (val < 0){
				return -EINVAL;
			}
			if(val != 8)
			{
				return bytes_read;
			}
				// printk("Arg 1 = %d\n", ((u64 *)(buff + bytes_read))[0]);
			bytes_read += val;
		}

		if (get_args(syscall_num) > 1)
		{
			val = TraceBufferReader(filep, buff + bytes_read, 8);
			if (val < 0)
				return -EINVAL;
			if(val != 8)
			{
				return bytes_read;
			}
			// printk("Arg 2 = %d\n", ((u64 *)(buff + bytes_read))[0]);
			bytes_read += val;
		}

		if (get_args(syscall_num) > 2)
		{
			val = TraceBufferReader(filep, buff + bytes_read, 8);
			if (val < 0)
				return -EINVAL;
			if(val != 8)
			{
				return bytes_read;
			}
				// printk("Arg 3 = %d\n", ((u64 *)(buff + bytes_read))[0]);
			bytes_read += val;
		}

		if (get_args(syscall_num) > 3)
		{
			val = TraceBufferReader(filep, buff + bytes_read, 8);
			if (val < 0)
				return -EINVAL;
			if(val != 8)
			{
				return bytes_read;
			}
				// printk("Arg 4 = %d\n", ((u64 *)(buff + bytes_read))[0]);
			bytes_read += val;
		}
	}
	return bytes_read;
}

int sys_start_strace(struct exec_context *current, int fd, int tracing_mode)
{
	if(tracing_mode != FILTERED_TRACING && tracing_mode != FULL_TRACING) return -EINVAL;
	if(current->st_md_base == NULL)
	{
		current->st_md_base = (struct strace_head*)os_alloc(sizeof(struct strace_head));
		current->st_md_base->count = 0;
		current->st_md_base->is_traced = 0;
		current->st_md_base->next = NULL;
		current->st_md_base->last = NULL;
	}
	
	struct strace_head *StraceHead = current->st_md_base;
	StraceHead->tracing_mode = tracing_mode;
	StraceHead->strace_fd = fd;
	StraceHead->is_traced = 1;
	current_pid = current->pid;

	return 0;
}

int sys_end_strace(struct exec_context *current)
{
	struct strace_head *StraceHead = current->st_md_base;
	if(!StraceHead) return -EINVAL;
	StraceHead->is_traced = 0;
	// os_free(n_args, sizeof(int) * 70);
	int cnt = StraceHead->count;
	struct strace_info* StraceInfo = StraceHead->next;
	struct strace_info* nextStraceInfo = NULL;
	for(int i=0;i<cnt;i++)
	{
		nextStraceInfo = StraceInfo->next;
		os_free(StraceInfo, sizeof(struct strace_info));
		StraceInfo = nextStraceInfo;
	}
	StraceHead->count = 0;
	StraceHead->next = NULL;
	StraceHead->last = NULL;
	os_free(StraceHead, sizeof(struct strace_head));
	current->st_md_base = NULL;
	return 0;
}

///////////////////////////////////////////////////////////////////////////
//// 		Start of ftrace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

long do_ftrace(struct exec_context *ctx, unsigned long faddr, long action, long nargs, int fd_trace_buffer)
{
	if (!(ctx->ft_md_base))
	{
		ctx->ft_md_base = (struct ftrace_head *)os_alloc(sizeof(struct ftrace_head));
		ctx->ft_md_base->count = 0;
		ctx->ft_md_base->next = NULL;
		ctx->ft_md_base->last = NULL;
	}
	struct ftrace_head *FtraceHead = ctx->ft_md_base;

	if (action == ADD_FTRACE)
	{
		struct ftrace_info *FtraceInfo = FtraceHead->next;
		int cnt = FtraceHead->count;

		for (int i = 0; i < cnt; i++)
		{
			if (FtraceInfo->faddr == faddr)
				return -EINVAL;
			FtraceInfo = FtraceInfo->next;
		}
		if (cnt == FTRACE_MAX)
			return -EINVAL;

		struct ftrace_info *newFtraceInfo = (struct ftrace_info *)os_alloc(sizeof(struct ftrace_info));
		if(!newFtraceInfo) return -EINVAL;

		newFtraceInfo->faddr = faddr;
		newFtraceInfo->fd = fd_trace_buffer;
		newFtraceInfo->num_args = nargs;
		newFtraceInfo->capture_backtrace = 0;

		newFtraceInfo->next = FtraceHead->next;
		FtraceHead->next = newFtraceInfo;

		if (cnt == 0)
			FtraceHead->last = newFtraceInfo;
		FtraceHead->count = cnt + 1;

		return 0;
	}

	if (action == REMOVE_FTRACE)
	{
		struct ftrace_info *FtraceInfo = FtraceHead->next;
		int cnt = FtraceHead->count;
		if(cnt <= 0) return -EINVAL;
		int i = 0;
		for (i = 0; i < cnt; i++)
		{
			if (FtraceInfo->faddr == faddr)
				break;
			FtraceInfo = FtraceInfo->next;
		}
		if (i == cnt)
			return -EINVAL;

		if (((u8 *)faddr)[0] == INV_OPCODE && ((u8 *)faddr)[1] == INV_OPCODE && ((u8 *)faddr)[2] == INV_OPCODE && ((u8 *)faddr)[3] == INV_OPCODE)
		{
			do_ftrace(ctx, faddr, DISABLE_FTRACE, nargs, fd_trace_buffer);
		}

		if (cnt == 1)
		{
			os_free(FtraceHead->next, sizeof(struct ftrace_info));
			FtraceHead->next = NULL;
			FtraceHead->last = NULL;
		}
		else if (i==0)
		{
			FtraceInfo = FtraceHead->next;
			FtraceHead->next = FtraceHead->next->next;
			os_free(FtraceInfo, sizeof(struct strace_info));
		}
		else
		{
			FtraceInfo = FtraceHead->next;
			for (int j = 0; j < i - 1; j++)
				FtraceInfo = FtraceInfo->next;

			if (FtraceInfo->next)
			{	
				struct ftrace_info* ToDel = FtraceInfo->next;
				FtraceInfo->next = FtraceInfo->next->next;
				if (!FtraceInfo->next)
					FtraceHead->last = FtraceInfo;
				os_free(ToDel, sizeof(struct ftrace_info));
			}
		}
		FtraceHead->count = cnt - 1;
		return 0;
	}

	if (action == ENABLE_FTRACE)
	{
		struct ftrace_info *FtraceInfo = FtraceHead->next;
		int cnt = FtraceHead->count;
		int found = 0;
		for (int i = 0; i < cnt; i++)
		{
			if (FtraceInfo->faddr == faddr)
			{
				found = 1;
				break;
			}
		}
		if (found == 0)
			return -EINVAL;

		if (((u8 *)faddr)[0] == INV_OPCODE && ((u8 *)faddr)[1] == INV_OPCODE && ((u8 *)faddr)[2] == INV_OPCODE && ((u8 *)faddr)[3] == INV_OPCODE)
			return 0;

		FtraceInfo->code_backup[0] = ((u8 *)faddr)[0];
		FtraceInfo->code_backup[1] = ((u8 *)faddr)[1];
		FtraceInfo->code_backup[2] = ((u8 *)faddr)[2];
		FtraceInfo->code_backup[3] = ((u8 *)faddr)[3];
		((u8 *)faddr)[0] = INV_OPCODE;
		((u8 *)faddr)[1] = INV_OPCODE;
		((u8 *)faddr)[2] = INV_OPCODE;
		((u8 *)faddr)[3] = INV_OPCODE;

		return 0;
	}

	if (action == DISABLE_FTRACE)
	{
		struct ftrace_info *FtraceInfo = FtraceHead->next;
		int cnt = FtraceHead->count;
		int found = 0;
		for (int i = 0; i < cnt; i++)
		{
			if (FtraceInfo->faddr == faddr)
			{
				found = 1;
				break;
			}
		}
		if (found == 0)
			return -EINVAL;
		if (!(((u8 *)faddr)[0] == INV_OPCODE && ((u8 *)faddr)[1] == INV_OPCODE && ((u8 *)faddr)[2] == INV_OPCODE && ((u8 *)faddr)[3] == INV_OPCODE))
		{
			return 0;
		}

		((u8 *)faddr)[0] = FtraceInfo->code_backup[0];
		((u8 *)faddr)[1] = FtraceInfo->code_backup[1];
		((u8 *)faddr)[2] = FtraceInfo->code_backup[2];
		((u8 *)faddr)[3] = FtraceInfo->code_backup[3];

		return 0;
	}

	if (action == ENABLE_BACKTRACE)
	{
		struct ftrace_info *FtraceInfo = FtraceHead->next;
		int cnt = FtraceHead->count;
		int found = 0;
		for (int i = 0; i < cnt; i++)
		{
			if (FtraceInfo->faddr == faddr)
			{
				found = 1;
				break;
			}
		}
		if (found == 0)
			return -EINVAL;

		if (!(((u8 *)faddr)[0] == INV_OPCODE && ((u8 *)faddr)[1] == INV_OPCODE && ((u8 *)faddr)[2] == INV_OPCODE && ((u8 *)faddr)[3] == INV_OPCODE))
		{
			do_ftrace(ctx, faddr, ENABLE_FTRACE, nargs, fd_trace_buffer);
		}
		FtraceInfo->capture_backtrace = 1;

		return 0;
	}

	if (action == DISABLE_BACKTRACE)
	{
		struct ftrace_info *FtraceInfo = FtraceHead->next;
		int cnt = FtraceHead->count;
		int found = 0;
		for (int i = 0; i < cnt; i++)
		{
			if (FtraceInfo->faddr == faddr)
			{
				found = 1;
				break;
			}
		}
		if (found == 0)
			return -EINVAL;

		if (((u8 *)faddr)[0] == INV_OPCODE && ((u8 *)faddr)[1] == INV_OPCODE && ((u8 *)faddr)[2] == INV_OPCODE && ((u8 *)faddr)[3] == INV_OPCODE)
		{
			do_ftrace(ctx, faddr, DISABLE_FTRACE, nargs, fd_trace_buffer);
		}
		FtraceInfo->capture_backtrace = 0;
		return 0;
	}

	return -EINVAL;
}

// Fault handler
long handle_ftrace_fault(struct user_regs *regs)
{
	u64 DELIMITER = 1110111011;
	struct exec_context *current = get_current_ctx();
	struct ftrace_head *FtraceHead = current->ft_md_base;
	int cnt = FtraceHead->count;
	struct ftrace_info *FtraceInfo = FtraceHead->next;

	for (int i = 0; i < cnt; i++)
	{
		if (FtraceInfo->faddr == regs->entry_rip)
			break;
		FtraceInfo = FtraceInfo->next;
	}

	struct file *filep = current->files[FtraceInfo->fd];

	TraceBufferWriter(filep, (char *)&(FtraceInfo->faddr), 8);
	if (FtraceInfo->num_args > 0)
		TraceBufferWriter(filep, (char *)&regs->rdi, 8);
	if (FtraceInfo->num_args > 1)
		TraceBufferWriter(filep, (char *)&regs->rsi, 8);
	if (FtraceInfo->num_args > 2)
		TraceBufferWriter(filep, (char *)&regs->rdx, 8);
	if (FtraceInfo->num_args > 3)
		TraceBufferWriter(filep, (char *)&regs->rcx, 8);
	if (FtraceInfo->num_args > 4)
		TraceBufferWriter(filep, (char *)&regs->r8, 8);
	if (FtraceInfo->num_args > 5)
		TraceBufferWriter(filep, (char *)&regs->r9, 8);

	regs->entry_rsp -= 8;
	*((u64 *)regs->entry_rsp) = regs->rbp;
	regs->rbp = regs->entry_rsp;
	regs->entry_rip += 4;

	if (FtraceInfo->capture_backtrace)
	{
		u64 *rbp = (u64 *)regs->rbp;
		u64 return_address = FtraceInfo->faddr;
		while (return_address != END_ADDR)
		{
			TraceBufferWriter(filep, (char *)&return_address, 8);
			return_address = ((u64 *)((u64)rbp + 8))[0];
			rbp = (u64 *)(*rbp);
		}
	}
	TraceBufferWriter(filep, (char *)(&DELIMITER), 8);
	return 0;
}

int sys_read_ftrace(struct file *filep, char *buff, u64 count)
{
	if (count < 0) return -EINVAL;
	u64 DELIMITER = 1110111011;
	int bytes_read = 0, val = 0;
	for (int i = 0; i < count; i++)
	{
		while (1)
		{
			u64 TempBuff;
			val = TraceBufferReader(filep, (char *)&TempBuff, 8);
			if (val < 0)
				return -EINVAL;
			if (TempBuff == DELIMITER)
				break;
			((u64 *)(buff + bytes_read))[0] = TempBuff;
			bytes_read += val;
		}
	}
	return bytes_read;
}