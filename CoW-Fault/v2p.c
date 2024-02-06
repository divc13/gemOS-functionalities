#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */

#define PFN_MASK 0xFFF
#define OFFSET_MASK 0xFFFFFFFFFFFFF000
#define FOURTH_ZERO_MASK 0xFFFFFFFFFFFFFFF7

static inline void invlpg(u64 addr) {
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

long insert(struct exec_context *current, struct vm_area* prev_VMA, struct vm_area* curr_VMA, u64 addr, int length, int prot)
{
    if (prev_VMA->vm_end == addr && prev_VMA->access_flags == prot && prev_VMA != current->vm_area)
    {
        prev_VMA->vm_end = addr + length;
        if(curr_VMA && addr + length == curr_VMA->vm_start && curr_VMA->access_flags == prot)
        {
            prev_VMA->vm_end = curr_VMA->vm_end;
            prev_VMA->vm_next = curr_VMA->vm_next;
            stats->num_vm_area--;
            os_free(curr_VMA, sizeof(struct vm_area));
        }
        return addr;
    }

    if(curr_VMA && addr + length == curr_VMA->vm_start && curr_VMA->access_flags == prot)
    {
        curr_VMA->vm_start = addr;
        return curr_VMA->vm_start;
    }

    struct vm_area* new_vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
    new_vm_area->vm_start = addr;
    new_vm_area->vm_end = addr + length;
    new_vm_area->access_flags = prot;

    prev_VMA->vm_next = new_vm_area;
    new_vm_area->vm_next = curr_VMA;

    stats->num_vm_area++;
    return addr;
}

void merge(struct exec_context *current)
{
    struct vm_area* VMA_Head = current->vm_area;
    struct vm_area* prev_VMA = VMA_Head->vm_next;
    struct vm_area* curr_VMA = NULL;

    if (prev_VMA) curr_VMA = prev_VMA->vm_next;

    while(curr_VMA)
    {
        if(curr_VMA->vm_start == prev_VMA->vm_end && curr_VMA->access_flags == prev_VMA->access_flags)
        {
            prev_VMA->vm_end = curr_VMA->vm_end;
            prev_VMA->vm_next = curr_VMA->vm_next;
            stats->num_vm_area--;
            os_free(curr_VMA, sizeof(struct vm_area));
            curr_VMA = prev_VMA->vm_next;
        }
        else
        {
            prev_VMA = curr_VMA;
            curr_VMA = curr_VMA->vm_next;
        }
    }
}

int unmap_physical(struct exec_context *current, struct vm_area* curr_VMA, u64 addr, u64 end_addr)
{
    int length = end_addr - addr;
    if (addr >= curr_VMA->vm_end || addr < curr_VMA->vm_start) return -1;
    if (addr + length > curr_VMA->vm_end) return -1;
    if (length % 4096) return -1;

    int pg_cnt = length / 4096;

    for (int i=0; i < pg_cnt; i++, addr += 4096)
    {
        u64 pgd_offset = ((addr >> 39) % 512) * 8;
        u64 pud_offset = ((addr >> 30) % 512) * 8;
        u64 pmd_offset = ((addr >> 21) % 512) * 8;
        u64 pte_offset = ((addr >> 12) % 512) * 8;

        u64 pgd_base_address = (u64) osmap(current->pgd);
        u64* pgd_t = (u64 *)(pgd_base_address + pgd_offset);

        if (((*pgd_t) & 0x1) == 0) continue;
        if ((((*pgd_t) >> 4) & 0x1) == 0) continue;

        u64 pud_base_address = (u64)osmap((*pgd_t)>>12);
        u64* pud_t = (u64 *)(pud_base_address + pud_offset);

        if (((*pud_t) & 0x1) == 0) continue;
        if ((((*pud_t) >> 4) & 0x1) == 0) continue;

        u64 pmd_base_address = (u64)osmap((*pud_t)>>12);
        u64* pmd_t = (u64 *)(pmd_base_address + pmd_offset);

        if (((*pmd_t) & 0x1) == 0) continue;
        if ((((*pmd_t) >> 4) & 0x1) == 0) continue;

        u64 pte_base_address = (u64)osmap((*pmd_t)>>12);
        u64* pte_t = (u64 *)(pte_base_address + pte_offset);

        if (((*pte_t) & 0x1) == 0) continue;
        if ((((*pte_t) >> 4) & 0x1) == 0) continue;

        put_pfn((*pte_t) >> 12);
        if (get_pfn_refcount((*pte_t) >> 12) == 0) os_pfn_free(USER_REG, ((*pte_t) >> 12));
        (*pte_t) = 0x0;

        invlpg(addr);
    }
    return 0;
}

int protect_physical(struct exec_context *current, struct vm_area* curr_VMA, u64 addr, u64 end_addr, int prot)
{
    int length = end_addr - addr;
    if (addr >= curr_VMA->vm_end || addr < curr_VMA->vm_start) return -1;
    if (addr + length > curr_VMA->vm_end) return -1;
    if (length % 4096) return -1;

    int pg_cnt = length / 4096;

    for (int i=0; i < pg_cnt; i++, addr += 4096)
    {
        u64 pgd_offset = ((addr >> 39) % 512) * 8;
        u64 pud_offset = ((addr >> 30) % 512) * 8;
        u64 pmd_offset = ((addr >> 21) % 512) * 8;
        u64 pte_offset = ((addr >> 12) % 512) * 8;

        u64 pgd_base_address = (u64) osmap(current->pgd);
        u64* pgd_t = (u64 *)(pgd_base_address + pgd_offset);

        if (((*pgd_t) & 0x1) == 0) continue;
        if ((((*pgd_t) >> 4) & 0x1) == 0) continue;

        u64 pud_base_address = (u64)osmap((*pgd_t)>>12);
        u64* pud_t = (u64 *)(pud_base_address + pud_offset);

        if (((*pud_t) & 0x1) == 0) continue;
        if ((((*pud_t) >> 4) & 0x1) == 0) continue;

        u64 pmd_base_address = (u64)osmap((*pud_t)>>12);
        u64* pmd_t = (u64 *)(pmd_base_address + pmd_offset);

        if (((*pmd_t) & 0x1) == 0) continue;
        if ((((*pmd_t) >> 4) & 0x1) == 0) continue;

        u64 pte_base_address = (u64)osmap((*pmd_t)>>12);
        u64* pte_t = (u64 *)(pte_base_address + pte_offset);

        if (((*pte_t) & 0x1) == 0) continue;
        if ((((*pte_t) >> 4) & 0x1) == 0) continue;

        if(get_pfn_refcount((*pte_t) >> 12) != 1) continue;
        if (prot == (PROT_WRITE|PROT_READ)) *pte_t = (*pte_t | 0x8);
        else if (prot == PROT_READ) *pte_t = ((*pte_t) & FOURTH_ZERO_MASK);

        invlpg(addr);
    }
    return 0;
}

int PTE_Creater(struct exec_context *parent, struct exec_context *child, u64 addr, u64 end_addr)
{
    int length = end_addr - addr;
    if (length % 4096) return -1;
    int pg_cnt = length / 4096;

    for (int i=0; i < pg_cnt; i++, addr += 4096)
    {
        u64 pgd_offset = ((addr >> 39) % 512) * 8;
        u64 pud_offset = ((addr >> 30) % 512) * 8;
        u64 pmd_offset = ((addr >> 21) % 512) * 8;
        u64 pte_offset = ((addr >> 12) % 512) * 8;

        u64 pgd_base_address = (u64) osmap(parent->pgd);
        u64* pgd_t = (u64 *)(pgd_base_address + pgd_offset);

        if (((*pgd_t) & 0x1) == 0) continue;
        if ((((*pgd_t) >> 4) & 0x1) == 0) continue;

        u64 pud_base_address = (u64)osmap((*pgd_t)>>12);
        u64* pud_t = (u64 *)(pud_base_address + pud_offset);

        if (((*pud_t) & 0x1) == 0) continue;
        if ((((*pud_t) >> 4) & 0x1) == 0) continue;

        u64 pmd_base_address = (u64)osmap((*pud_t)>>12);
        u64* pmd_t = (u64 *)(pmd_base_address + pmd_offset);

        if (((*pmd_t) & 0x1) == 0) continue;
        if ((((*pmd_t) >> 4) & 0x1) == 0) continue;

        u64 pte_base_address = (u64)osmap((*pmd_t)>>12);
        u64* pte_t = (u64 *)(pte_base_address + pte_offset);

        if (((*pte_t) & 0x1) == 0) continue;
        if ((((*pte_t) >> 4) & 0x1) == 0) continue;
        *pte_t = ((*pte_t) & FOURTH_ZERO_MASK);
        
        u64 child_pgd_base_address = (u64) osmap(child->pgd);
        u64* child_pgd_t = (u64 *)(child_pgd_base_address + pgd_offset);

        *child_pgd_t = ((*child_pgd_t) | 0x18);

        if (((*child_pgd_t) & 0x1) == 0)
        {
            *child_pgd_t = ((*child_pgd_t) | 0x1);
            *child_pgd_t = ((*child_pgd_t) & PFN_MASK);
            u64 temp = (u64) os_pfn_alloc(OS_PT_REG);
            if (!temp) return -1;
            *child_pgd_t = ((*child_pgd_t) | (temp << 12));
        } 


        u64 child_pud_base_address = (u64)osmap((*child_pgd_t) >> 12);
        u64* child_pud_t = (u64 *)(child_pud_base_address + pud_offset);

        *child_pud_t = ((*child_pud_t)| 0x18);

        if ((*child_pud_t & 0x1) == 0)
        {
            *child_pud_t = ((*child_pud_t) | 0x1);
            *child_pud_t = ((*child_pud_t) & PFN_MASK);
            u64 temp = (u64) os_pfn_alloc(OS_PT_REG);
            if (!temp) return -1;
            *child_pud_t =(( *child_pud_t )| (temp << 12));
        } 


        u64 child_pmd_base_address = (u64) osmap((*child_pud_t) >> 12);
        u64* child_pmd_t = (u64 *)(child_pmd_base_address + pmd_offset);

        *child_pmd_t = ((*child_pmd_t )| 0x18);

        if ((*child_pmd_t & 0x1) == 0)
        {
            *child_pmd_t = ((*child_pmd_t )| 0x1);
            *child_pmd_t = ((*child_pmd_t) & PFN_MASK);
            u64 temp = (u64) os_pfn_alloc(OS_PT_REG);
            if (!temp) return -1;
            *child_pmd_t = ((*child_pmd_t )| (temp << 12));
        } 

        u64 child_pte_base_address = (u64) osmap((*child_pmd_t) >> 12);
        u64* child_pte_t = (u64 *)(child_pte_base_address + pte_offset);

        *child_pte_t = *pte_t; 
        get_pfn((*pte_t) >> 12);
    }
    return 0;
}

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (prot != PROT_READ && prot != (PROT_READ|PROT_WRITE)) return -1;
    if (length <= 0) return -1;
    if (addr % 4096) return -1;

    struct vm_area* VMA_Head = current->vm_area;

    if (!VMA_Head || VMA_Head->vm_start != MMAP_AREA_START || VMA_Head->vm_end != MMAP_AREA_START + 4096 || VMA_Head->access_flags != 0)
    {
        if (!VMA_Head)
        {
            current->vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
            VMA_Head = current->vm_area;
        }
        VMA_Head->vm_start = MMAP_AREA_START;
        VMA_Head->vm_end = MMAP_AREA_START + 4096;
        VMA_Head->vm_next = NULL;
        VMA_Head->access_flags = 0;
        stats->num_vm_area = 1;
        return 0;
    }

    if (length % 4096) length = length + 4096 - length % 4096;

    struct vm_area* curr_VMA = VMA_Head->vm_next;
    struct vm_area* prev_VMA = VMA_Head;

    while (curr_VMA)
    {
        if (prot != curr_VMA->access_flags)
        {
            if (addr <= curr_VMA->vm_start && addr + length >= curr_VMA->vm_end)
            {
                if(protect_physical(current, curr_VMA, curr_VMA->vm_start, curr_VMA->vm_end, prot) < 0) return -1;
                curr_VMA->access_flags = prot;
            }

            else if (addr <= curr_VMA->vm_start && addr + length < curr_VMA->vm_end && addr + length > curr_VMA->vm_start)
            {
                if(protect_physical(current, curr_VMA, curr_VMA->vm_start, addr + length, prot) < 0) return -1;
                struct vm_area* new_vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                new_vm_area->vm_start = curr_VMA->vm_start;
                new_vm_area->vm_end = addr + length;
                new_vm_area->access_flags = prot;
                new_vm_area->vm_next = curr_VMA;

                curr_VMA->vm_start = addr + length;
                prev_VMA->vm_next = new_vm_area;

                stats->num_vm_area++;
                break;
            }

            else if (addr > curr_VMA->vm_start && addr + length >= curr_VMA->vm_end && addr < curr_VMA->vm_end)
            {
                if(protect_physical(current, curr_VMA, addr, curr_VMA->vm_end, prot) < 0) return -1;
                struct vm_area* new_vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                new_vm_area->vm_start = addr;
                new_vm_area->vm_end = curr_VMA->vm_end;
                new_vm_area->access_flags = prot;
                new_vm_area->vm_next = curr_VMA->vm_next;

                curr_VMA->vm_end = addr;
                curr_VMA->vm_next = new_vm_area;
                stats->num_vm_area++;
            }

            else if (addr > curr_VMA->vm_start && addr + length < curr_VMA->vm_end)
            {
                if(protect_physical(current, curr_VMA, addr, addr + length, prot) < 0) return -1;
                struct vm_area* vma2 = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                vma2->vm_start = addr + length;
                vma2->vm_end = curr_VMA->vm_end;
                vma2->access_flags = curr_VMA->access_flags;
                vma2->vm_next = curr_VMA->vm_next;

                struct vm_area* vma1 = (struct vm_area*) os_alloc(sizeof(struct vm_area));
                vma1->vm_start = addr;
                vma1->vm_end = addr + length;
                vma1->access_flags = prot;
                vma1->vm_next = vma2;

                curr_VMA->vm_end = addr;
                curr_VMA->vm_next = vma1;

                stats->num_vm_area += 2;
                break;
            }

        }

        prev_VMA = curr_VMA;
        curr_VMA = curr_VMA->vm_next;
    }

    merge(current);
    return 0;
}

long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    if ((prot != PROT_READ) && (prot != (PROT_READ|PROT_WRITE))) return -1;
    if (flags != MAP_FIXED && flags != 0) return -1;
    if (length <= 0 || length >= 2*1024*1024) return -1;
    if (addr % 4096) return -1;

    struct vm_area* VMA_Head = current->vm_area;

    if (!VMA_Head || VMA_Head->vm_start != MMAP_AREA_START || VMA_Head->vm_end != MMAP_AREA_START + 4096 || VMA_Head->access_flags != 0)
    {
        if (!VMA_Head)
        {
            current->vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
            VMA_Head = current->vm_area;
        }
        VMA_Head->vm_start = MMAP_AREA_START;
        VMA_Head->vm_end = MMAP_AREA_START + 4096;
        VMA_Head->vm_next = NULL;
        VMA_Head->access_flags = 0;
        stats->num_vm_area = 1;
    }

    if (length % 4096) length = length + 4096 - length % 4096;

    if (addr)
    {
        struct vm_area* curr_VMA = VMA_Head->vm_next;
        struct vm_area* prev_VMA = VMA_Head;

        while(curr_VMA)
        {
            if ((addr < curr_VMA->vm_end && addr >= curr_VMA->vm_start) || (addr < curr_VMA->vm_start && addr + length > curr_VMA->vm_start))
            {
                if (flags == MAP_FIXED) return -1;
                break;
            }

            if (addr < curr_VMA->vm_start && addr + length <= curr_VMA->vm_start) return insert(current, prev_VMA, curr_VMA, addr, length, prot);

            prev_VMA = curr_VMA;
            curr_VMA = curr_VMA->vm_next;
        }

        if (!curr_VMA) return insert(current, prev_VMA, NULL, addr, length, prot);
    }

    if(!addr && flags == MAP_FIXED) return -1;
    struct vm_area* curr_VMA = VMA_Head->vm_next;
    struct vm_area* prev_VMA = VMA_Head;

    while(curr_VMA)
    {
        if (curr_VMA->vm_start - prev_VMA->vm_end >= length) return insert(current, prev_VMA, curr_VMA, prev_VMA->vm_end, length, prot);
        prev_VMA = curr_VMA;
        curr_VMA = curr_VMA->vm_next;
    }
    if (!curr_VMA) return insert(current, prev_VMA, NULL, prev_VMA->vm_end, length, prot);
    return -1;
}

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (addr % 4096) return -1;
    if (length <= 0) return -1;

    struct vm_area* VMA_Head = current->vm_area;
    if (!VMA_Head || VMA_Head->vm_start != MMAP_AREA_START || VMA_Head->vm_end != MMAP_AREA_START + 4096 || VMA_Head->access_flags != 0)
    {
        if (!VMA_Head)
        {
            current->vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
            VMA_Head = current->vm_area;
        }
        VMA_Head->vm_start = MMAP_AREA_START;
        VMA_Head->vm_end = MMAP_AREA_START + 4096;
        VMA_Head->vm_next = NULL;
        VMA_Head->access_flags = 0;
        stats->num_vm_area = 1;
        return 0;
    }

    if (length % 4096) length = length + 4096 - length % 4096;

    struct vm_area* curr_VMA = VMA_Head->vm_next;
    struct vm_area* prev_VMA = VMA_Head;

    while (curr_VMA)
    {

        if (addr <= curr_VMA->vm_start && addr + length >= curr_VMA->vm_end)
        {
            if (unmap_physical(current, curr_VMA, curr_VMA->vm_start, curr_VMA->vm_end) < 0) return -1;
            prev_VMA->vm_next = curr_VMA->vm_next;
            os_free(curr_VMA, sizeof(struct vm_area));
            stats->num_vm_area--;
            curr_VMA = prev_VMA->vm_next;
            continue;
        }

        else if (addr <= curr_VMA->vm_start && addr + length < curr_VMA->vm_end && addr + length > curr_VMA->vm_start)
        {
            if (unmap_physical(current, curr_VMA, curr_VMA->vm_start, addr + length) < 0) return -1;
            curr_VMA->vm_start = addr + length;
            break;
        }

        else if (addr > curr_VMA->vm_start && addr + length >= curr_VMA->vm_end && addr < curr_VMA->vm_end)
        {
            if (unmap_physical(current, curr_VMA, addr, curr_VMA->vm_end) < 0) return -1;
            curr_VMA->vm_end = addr;
        }

        else if (addr > curr_VMA->vm_start && addr + length < curr_VMA->vm_end)
        {
            if (unmap_physical(current, curr_VMA, addr, addr + length) < 0) return -1;
            struct vm_area* new_vm_area = (struct vm_area*) os_alloc(sizeof(struct vm_area));
            new_vm_area->vm_start = addr + length;
            new_vm_area->vm_end = curr_VMA->vm_end;
            new_vm_area->access_flags = curr_VMA->access_flags;
            new_vm_area->vm_next = curr_VMA->vm_next;

            curr_VMA->vm_end = addr;
            curr_VMA->vm_next = new_vm_area;

            stats->num_vm_area++;
            break;
        }

        prev_VMA = curr_VMA;
        curr_VMA = curr_VMA->vm_next;
    }

    return 0;
}

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    struct vm_area* curr_VMA = current->vm_area->vm_next;
    while(curr_VMA)
    {
        if (curr_VMA->vm_start <= addr && addr < curr_VMA->vm_end)
        {
            if (error_code == 7 && curr_VMA->access_flags == PROT_READ) return -1;
            if (error_code == 6 && curr_VMA->access_flags == PROT_READ) return -1;

            u64 pgd_offset = ((addr >> 39) % 512) * 8;
            u64 pud_offset = ((addr >> 30) % 512) * 8;
            u64 pmd_offset = ((addr >> 21) % 512) * 8;
            u64 pte_offset = ((addr >> 12) % 512) * 8;

            u64 pgd_base_address = (u64) osmap(current->pgd);
            u64* pgd_t = (u64 *)(pgd_base_address + pgd_offset);

            *pgd_t = ((*pgd_t) | 0x18);

            if (((*pgd_t) & 0x1) == 0)
            {
                *pgd_t = ((*pgd_t )| 0x1);
                *pgd_t = ((*pgd_t) & PFN_MASK);
                u64 temp = (u64) os_pfn_alloc(OS_PT_REG);
                if (!temp) return -1;
                *pgd_t =(( *pgd_t) | (temp << 12));
            } 

            u64 pud_base_address = (u64)osmap((*pgd_t)>>12);
            u64* pud_t = (u64 *)(pud_base_address + pud_offset);

            *pud_t = ((*pud_t )| 0x18);

            if (((*pud_t) & 0x1) == 0)
            {
                *pud_t = ((*pud_t )| 0x1);
                *pud_t = ((*pud_t) & PFN_MASK);
                u64 temp = (u64) os_pfn_alloc(OS_PT_REG);
                if (!temp) return -1;
                *pud_t =((*pud_t) | (temp << 12));
            } 

            u64 pmd_base_address = (u64)osmap((*pud_t)>>12);
            u64* pmd_t = (u64 *)(pmd_base_address + pmd_offset);

            *pmd_t = ((*pmd_t )| 0x18);

            if (((*pmd_t) & 0x1) == 0)
            {
                *pmd_t = ((*pmd_t )| 0x1);
                *pmd_t = ((*pmd_t) & PFN_MASK);
                u64 temp = (u64) os_pfn_alloc(OS_PT_REG);
                if (!temp) return -1;
                *pmd_t =(( *pmd_t) | (temp << 12));
            } 

            u64 pte_base_address = (u64)osmap((*pmd_t)>>12);
            u64* pte_t = (u64 *)(pte_base_address + pte_offset);

            *pte_t = ((*pte_t )| 0x10);
            *pte_t = ((*pte_t )& FOURTH_ZERO_MASK);
            if (curr_VMA->access_flags == (PROT_READ|PROT_WRITE)) *pte_t = ((*pte_t) | 0x8);
            if (((*pte_t) & 0x1) == 0)
            {
                *pte_t = ((*pte_t) | 0x1);
                *pte_t = ((*pte_t) & PFN_MASK);
                u64 temp = (u64) os_pfn_alloc(USER_REG);
                if (!temp) return -1;
                *pte_t = ((*pte_t )| (temp << 12));
            } 

            if (error_code == 7)
            {
                handle_cow_fault(current, addr, curr_VMA->access_flags);
            }
            return 1;
        }

        curr_VMA = curr_VMA->vm_next;
    }

    return -1;
}

long do_cfork(){
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    
    pid = new_ctx->pid;
    new_ctx->ppid = ctx->pid;
    new_ctx->pgd = (u64) os_pfn_alloc(OS_PT_REG);
    if (!(new_ctx->pgd)) return -1;
    new_ctx->type = ctx->type;
    new_ctx->used_mem = ctx->used_mem;
    new_ctx->regs = ctx->regs;
    new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;
    new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;
    new_ctx->alarm_config_time = ctx->alarm_config_time;
    new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;
    new_ctx->ctx_threads = ctx->ctx_threads;

    for (int i=0;i<MAX_MM_SEGS;i++) (new_ctx->mms)[i] = (ctx->mms)[i];
    for (int i=0;i<CNAME_MAX;i++) (new_ctx->name)[i] = (ctx->name)[i];
    for (int i=0;i<MAX_SIGNALS;i++) (new_ctx->sighandlers)[i] = (ctx->sighandlers)[i];
    for (int i=0;i<MAX_OPEN_FILES;i++) (new_ctx->files)[i] = (ctx->files)[i];
        
    struct vm_area* temp = ctx->vm_area;

    if (temp)
    {
        new_ctx->vm_area = (struct vm_area*)os_alloc(sizeof(struct vm_area));
        struct vm_area* vma = new_ctx->vm_area;
        vma->access_flags = temp->access_flags;
        vma->vm_start = temp->vm_start;
        vma->vm_end = temp->vm_end;

        temp = temp->vm_next;
        while(temp)
        {
            vma->vm_next = (struct vm_area*)os_alloc(sizeof(struct vm_area));
            vma = vma->vm_next;
            vma->access_flags = temp->access_flags;
            vma->vm_start = temp->vm_start;
            vma->vm_end = temp->vm_end;
            temp = temp->vm_next;
        }
        vma->vm_next = NULL;
    }
    if (PTE_Creater(ctx, new_ctx, new_ctx->mms[MM_SEG_CODE].start, new_ctx->mms[MM_SEG_CODE].next_free) < 0) return -1;
    if (PTE_Creater(ctx, new_ctx, new_ctx->mms[MM_SEG_RODATA].start, new_ctx->mms[MM_SEG_RODATA].next_free) < 0) return -1;
    if (PTE_Creater(ctx, new_ctx, new_ctx->mms[MM_SEG_DATA].start, new_ctx->mms[MM_SEG_DATA].next_free) < 0) return -1;
    if (PTE_Creater(ctx, new_ctx, new_ctx->mms[MM_SEG_STACK].start, new_ctx->mms[MM_SEG_STACK].end) < 0) return -1;

    struct vm_area* vma = new_ctx->vm_area;
    vma = vma->vm_next;

    while(vma)
    {   
        if (PTE_Creater(ctx, new_ctx, vma->vm_start, vma->vm_end) < 0) return -1;
        vma = vma->vm_next;
    }

    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    invlpg(vaddr);
    u64 pgd_offset = ((vaddr >> 39) % 512) * 8;
    u64 pud_offset = ((vaddr >> 30) % 512) * 8;
    u64 pmd_offset = ((vaddr >> 21) % 512) * 8;
    u64 pte_offset = ((vaddr >> 12) % 512) * 8;

    u64 pgd_base_address = (u64) osmap(current->pgd);
    u64* pgd_t = (u64 *)(pgd_base_address + pgd_offset);

    if (((*pgd_t) & 0x1) == 0) return -1;
    if ((((*pgd_t) >> 4) & 0x1) == 0) return -1;

    u64 pud_base_address = (u64)osmap((*pgd_t)>>12);
    u64* pud_t = (u64 *)(pud_base_address + pud_offset);

    if (((*pud_t) & 0x1) == 0) return -1;
    if ((((*pud_t) >> 4) & 0x1) == 0) return -1;

    u64 pmd_base_address = (u64)osmap((*pud_t)>>12);
    u64* pmd_t = (u64 *)(pmd_base_address + pmd_offset);

    if (((*pmd_t) & 0x1) == 0) return -1;
    if ((((*pmd_t) >> 4) & 0x1) == 0) return -1;

    u64 pte_base_address = (u64)osmap((*pmd_t)>>12);
    u64* pte_t = (u64 *)(pte_base_address + pte_offset);

    if (((*pte_t) & 0x1) == 0) return -1;
    if ((((*pte_t) >> 4) & 0x1) == 0) return -1;

    int ref_cnt = get_pfn_refcount((*pte_t) >> 12);

    if (ref_cnt < 0) return -1;
    if (ref_cnt == 0) 
    {
        os_pfn_free(USER_REG, ((*pte_t) >> 12));
        return 1;
    }
    if (ref_cnt == 1) 
    {
        *pte_t = (*pte_t | 0x8);
        return 1;
    }

    put_pfn((*pte_t) >> 12);
    u64 source_addr = (u64) osmap((*pte_t) >> 12);

    *pte_t = ((*pte_t )| 0x18);
    *pte_t = ((*pte_t )| 0x1);
    *pte_t = ((*pte_t) & PFN_MASK);
    u64 temp = (u64) os_pfn_alloc(USER_REG);
    if (!temp) return -1;
    *pte_t = ((*pte_t )| (temp << 12));

    u64 dest_addr = (u64) osmap(temp);
    memcpy((char *)dest_addr, (char *)source_addr, 4096);

    return 1;
}