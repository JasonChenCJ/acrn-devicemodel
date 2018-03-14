/*-
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#include "vmm.h"
#include "vhm_ioctl_defs.h"
#include "vmmapi.h"

#define HUGETLBFS_MAGIC       0x958458f6

/* HugePage Level 1 for 2M page, Level 2 for 1G page*/
#define PATH_HP_LV1 "/run/hugepage/acrn/huge_lv1/"
#define PATH_HP_LV2 "/run/hugepage/acrn/huge_lv2/"

static void *ptr;
static size_t total_size;
static int hp_lv_size[HP_LV_MAX];

static int open_hugetlbfs(struct vmctx *ctx, int level)
{
	char guid_str[32];
	uint8_t	 GUID[16];
	char *path;
	struct statfs fs;

	if (level >= HP_LV_MAX) {
		perror("exceed max hp level");
		return -EINVAL;
	}

	path = ctx->hp[level].path;
	if (level == HP_LV1)
		strncpy(path, PATH_HP_LV1, MAX_PATH_LEN);
	else
		strncpy(path, PATH_HP_LV2, MAX_PATH_LEN);

	if (strlen(path) + strlen(guid_str) > MAX_PATH_LEN) {
		perror("PATH overflow");
		return -ENOMEM;
	}

	uuid_copy(GUID, ctx->vm_uuid);
	sprintf(guid_str, "%01X%01X%01X%01X%01X%01X%01X%01X"
		"%01X%01X%01X%01X%01X%01X%01X%01X\n",
		GUID[0], GUID[1], GUID[2], GUID[3],
		GUID[4], GUID[5], GUID[6], GUID[7],
		GUID[8], GUID[9], GUID[10], GUID[11],
		GUID[12], GUID[13], GUID[14], GUID[15]);

	strncat(path, guid_str, strlen(guid_str));

	printf("open hugetlbfs file %s\n", path);

	ctx->hp[level].fd = open(path, O_CREAT | O_RDWR, 0755);
	if (ctx->hp[level].fd  < 0) {
		perror("Open hugtlbfs failed");
		return -EINVAL;
	}

	/* get the pagesize */
	if (fstatfs(ctx->hp[level].fd, &fs) != 0) {
		perror("Failed to get statfs fo hugetlbfs");
		return -EINVAL;
	}

	hp_lv_size[level] = 0;
	if (fs.f_type == HUGETLBFS_MAGIC)
		hp_lv_size[level] = fs.f_bsize;

	return 0;
}

static void close_hugetlbfs(struct vmctx *ctx, int level)
{
	if (level >= HP_LV_MAX) {
		perror("exceed max hp level");
		return;
	}

	if (ctx->hp[level].fd >= 0) {
		close(ctx->hp[level].fd);
		ctx->hp[level].fd = -1;
		unlink(ctx->hp[level].path);
	}
}

static bool should_enable_hp_level(struct vmctx *ctx, int level)
{
	if (level >= HP_LV_MAX) {
		perror("exceed max hp level");
		return false;
	}

	return (ctx->hp[level].lowmem > 0 || ctx->hp[level].highmem > 0);
}

/*
 * level  : hugepage level
 * len	  : region length for mmap
 * offset : region start offset from ctx->baseaddr
 * skip   : skip offset in different level hugetlbfs fd
 */
static int mmap_hugetlbfs(struct vmctx *ctx, int level, size_t len,
		size_t offset, size_t skip)
{
	char *addr;
	size_t pagesz = 0;
	int fd, i;

	if (level >= HP_LV_MAX) {
		perror("exceed max hp level");
		return -EINVAL;
	}

	fd = ctx->hp[level].fd;
	addr = mmap(ctx->baseaddr + offset, len, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED, fd, skip);
	if (addr == MAP_FAILED)
		return -ENOMEM;

	printf("mmap 0x%lx@%p\n", len, addr);

	/* pre-allocate hugepages by touch them */
	if (level == HP_LV1)
		pagesz = hp_lv_size[HP_LV1];
	if (level == HP_LV2)
		pagesz = hp_lv_size[HP_LV2];

	printf("touch %ld pages with pagesz 0x%lx\n", len/pagesz, pagesz);

	for (i = 0; i < len/pagesz; i++) {
		*(volatile char *)addr = *addr;
		addr += pagesz;
	}

	return 0;
}

static int mmap_hugetlbfs_lowmem(struct vmctx *ctx)
{
	size_t len, offset, skip;
	int ret;

	offset = skip = 0;
	len = ctx->hp[HP_LV2].lowmem;
	if (len > 0) {
		ret = mmap_hugetlbfs(ctx, HP_LV2, len, offset, skip);
		if (ret < 0) {
			perror("mmap fail for level2 lowmem");
			return ret;
		}
		offset += len;
	}
	len = ctx->hp[HP_LV1].lowmem;
	if (len  > 0) {
		ret = mmap_hugetlbfs(ctx, HP_LV1, len, offset, skip);
		if (ret < 0) {
			perror("mmap fail for level1 lowmem");
			return ret;
		}
	}

	return 0;
}

static int mmap_hugetlbfs_highmem(struct vmctx *ctx)
{
	size_t len, offset, skip;
	int ret;

	offset = 4 * GB;
	skip = ctx->hp[HP_LV2].lowmem;
	len = ctx->hp[HP_LV2].highmem;
	if (len > 0) {
		ret = mmap_hugetlbfs(ctx, HP_LV2, len, offset, skip);
		if (ret < 0) {
			perror("mmap fail for level2 highmem");
			return ret;
		}
		offset += len;
	}
	skip = ctx->hp[HP_LV1].lowmem;
	len = ctx->hp[HP_LV1].highmem;
	if (len  > 0) {
		ret = mmap_hugetlbfs(ctx, HP_LV1, len, offset, skip);
		if (ret < 0) {
			perror("mmap fail for level1 highmem");
			return ret;
		}
	}

	return 0;
}

int check_hugetlb_support(void)
{
	if ((access(PATH_HP_LV1, F_OK) == 0) ||
		(access(PATH_HP_LV2, F_OK) == 0))
		return 1;
	else
		return 0;
}

int hugetlb_setup_memory(struct vmctx *ctx)
{
	/* open hugetlbfs and get pagesize for two level */
	ctx->hp[HP_LV1].fd = ctx->hp[HP_LV2].fd = -1;
	if (open_hugetlbfs(ctx, HP_LV1) < 0)
		return -EINVAL;
	if (open_hugetlbfs(ctx, HP_LV2) < 0)
		return -EINVAL;
	if (hp_lv_size[HP_LV1] == 0)
		return -EINVAL;

	/* all memory should be at least align with hp_lv_size[HP_LV1] */
	ctx->lowmem = ALIGN_DOWN(ctx->lowmem, hp_lv_size[HP_LV1]);
	ctx->highmem = ALIGN_DOWN(ctx->highmem, hp_lv_size[HP_LV1]);

	if (ctx->highmem > 0)
		total_size = 4 * GB + ctx->highmem;
	else
		total_size = ctx->lowmem;

	if (total_size == 0) {
		perror("vm request 0 memory");
		return -EINVAL;
	}

	/* check hp level 1/2 memory size in lowmem & highmem */
	if (hp_lv_size[HP_LV2] > 0) {
		ctx->hp[HP_LV2].lowmem =
			ALIGN_DOWN(ctx->lowmem, hp_lv_size[HP_LV2]);
		ctx->hp[HP_LV2].highmem =
			ALIGN_DOWN(ctx->highmem, hp_lv_size[HP_LV2]);
	} else {
		ctx->hp[HP_LV2].lowmem = 0;
		ctx->hp[HP_LV2].highmem = 0;
	}
	ctx->hp[HP_LV1].lowmem = ctx->lowmem - ctx->hp[HP_LV2].lowmem;
	ctx->hp[HP_LV1].highmem = ctx->highmem - ctx->hp[HP_LV2].highmem;

	/* align up total size with huge page size for vma alignment */
	if (should_enable_hp_level(ctx, HP_LV2))
		total_size = ALIGN_UP(total_size+1, hp_lv_size[HP_LV2]);
	else
		total_size = ALIGN_UP(total_size+1, hp_lv_size[HP_LV1]);

	printf("\ntry to setup level 1 hugepage for:\n"
		"\tlowmem 0x%lx, highmem 0x%lx\n"
		"level 2 hugepage for:\n"
		"\tlowmem 0x%lx, highmem 0x%lx\n"
		"total_size 0x%lx\n",
		ctx->hp[HP_LV1].lowmem, ctx->hp[HP_LV1].highmem,
		ctx->hp[HP_LV2].lowmem, ctx->hp[HP_LV2].highmem,
		total_size);

	/* basic overview vma */
	ptr = mmap(NULL, total_size, PROT_NONE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ptr == MAP_FAILED) {
		perror("anony mmap fail");
		return -ENOMEM;
	}

	/* align up baseaddr according to hugepage level size */
	if (should_enable_hp_level(ctx, HP_LV1))
		ctx->baseaddr =
			(void *)ALIGN_UP((size_t)ptr, hp_lv_size[HP_LV1]);
	if (should_enable_hp_level(ctx, HP_LV2))
		ctx->baseaddr =
			(void *)ALIGN_UP((size_t)ptr, hp_lv_size[HP_LV2]);

	printf("mmap ptr 0x%p -> baseaddr 0x%p\n", ptr, ctx->baseaddr);

	/* mmap lowmem */
	if (mmap_hugetlbfs_lowmem(ctx) < 0)
		goto err;

	/* mmap highmem */
	if (mmap_hugetlbfs_highmem(ctx) < 0)
		goto err;

	return 0;
err:
	munmap(ptr, total_size);
	close_hugetlbfs(ctx, HP_LV2);
	close_hugetlbfs(ctx, HP_LV1);
	return -ENOMEM;
}

void hugetlb_unsetup_memory(struct vmctx *ctx)
{
	if (total_size > 0) {
		munmap(ptr, total_size);
		total_size = 0;
		ptr = NULL;
	}
	if (ctx->hp[HP_LV1].fd >= 0)
		close_hugetlbfs(ctx, HP_LV1);
	if (ctx->hp[HP_LV2].fd >= 0)
		close_hugetlbfs(ctx, HP_LV2);
}
