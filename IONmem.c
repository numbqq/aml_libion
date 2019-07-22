/*
 * Copyright (c) 2014 Amlogic, Inc. All rights reserved.
 *
 * This source code is subject to the terms and conditions defined in the
 * file 'LICENSE' which is part of this source code package.
 *
 * Description:
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ion/IONmem.h>
#include <ion/ion.h>
#include <linux/ion.h>
#include "ion_4.12.h"

static int cmem_fd = -2;
static int ref_count = 0;

#ifdef __DEBUG
#define __D(fmt, args...) printf("CMEM Debug: " fmt, ## args)
#else
#define __D(fmt, args...)
#endif

#define __E(fmt, args...) printf("CMEM Error: " fmt, ## args)

static int validate_init()
{
    switch (cmem_fd) {
      case -3:
        __E("CMEM_exit() already called, check stderr output for earlier "
            "CMEM failure messages (possibly version mismatch).\n");

        return 0;

      case -2:
        __E("CMEM_init() not called, you must initialize CMEM before "
            "making API calls.\n");

        return 0;

      case -1:
        __E("CMEM file descriptor -1 (failed 'open()'), ensure CMEMK "
            "kernel module cmemk.ko has been installed with 'insmod'");

        return 0;

      default:
        return 1;
    }
}

int CMEM_init(void)
{
    int flags;

    __D("init: entered - ref_count %d, cmem_fd %d\n", ref_count, cmem_fd);

    if (cmem_fd >= 0) {
        ref_count++;
        __D("init: /dev/ion already opened, incremented ref_count %d\n",
            ref_count);
        return 0;
    }

    cmem_fd = ion_open();

    if (cmem_fd < 0) {
        __E("init: Failed to open /dev/ion: '%s'\n", strerror(errno));
        return -1;
    }

    ref_count++;

    __D("init: successfully opened /dev/ion...\n");

    __D("init: fd=%d\n", cmem_fd);

    return 0;
}

int CMEM_alloc_fd(size_t size, IONMEM_AllocParams *params, unsigned int flag, unsigned int alloc_hmask)
{
    int ret = -1;
    int i = 0, num_heaps = 0;
    unsigned int heap_mask = 0;

    if (ion_query_heap_cnt(cmem_fd, &num_heaps) >= 0) {
        __D("num_heaps=%d\n", num_heaps);
        struct ion_heap_data *const heaps = (struct ion_heap_data *)malloc(num_heaps * sizeof(struct ion_heap_data));
        if (heaps != NULL && num_heaps) {
            if (ion_query_get_heaps(cmem_fd, num_heaps, heaps) >= 0) {
                for (int i = 0; i != num_heaps; ++i) {
                    __D("heaps[%d].type=%d, heap_id=%d\n", i, heaps[i].type, heaps[i].heap_id);
                    if ((1 << heaps[i].type) == alloc_hmask) {
                        heap_mask = 1 << heaps[i].heap_id;
                        __D("%d, m=%x, 1<<heap_id=%x, heap_mask=%x, name=%s, alloc_hmask=%x\n",
                            heaps[i].type, 1<<heaps[i].type, heaps[i].heap_id, heap_mask, heaps[i].name, alloc_hmask);
                        break;
                    }
                }
            }
            free(heaps);
            if (heap_mask)
                ret = ion_alloc_fd(cmem_fd, size, 0, heap_mask, flag, &params->mImageFd);
            else
                __E("don't find match heap!!\n");
        } else {
            __E("heaps is NULL or no heaps,num_heaps=%d\n", num_heaps);
        }
    } else {
        __E("query_heap_cnt fail! no ion heaps for alloc!!!\n");
    }
    if (ret < 0) {
        __E("ion_alloc failed, errno=%d\n", errno);
        return -ENOMEM;
    }
    return ret;
}

unsigned long CMEM_alloc(size_t size, IONMEM_AllocParams *params, bool cache_flag)
{
    int ret = -1;
    int legacy_ion = 0;
    unsigned flag = 0;

    legacy_ion = ion_is_legacy(cmem_fd);
    if (!validate_init()) {
        return 0;
    }
    if (cache_flag) {
        flag = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;
    }
    __D("CMEM_alloc, cache=%d, bytes=%d, legacy_ion=%d, flag=0x%x\n", cache_flag, size, legacy_ion, flag);
    if (legacy_ion == 1)
        ret = ion_alloc(cmem_fd, size, 0, ION_HEAP_TYPE_DMA_MASK, flag, &params->mIonHnd);
    else
        ret = CMEM_alloc_fd(size, params, flag, ION_HEAP_TYPE_DMA_MASK);
    if (ret < 0) {
        if (legacy_ion)
            ret = ion_alloc(cmem_fd, size, 0, ION_HEAP_CARVEOUT_MASK, flag, &params->mIonHnd);
        else
            ret = CMEM_alloc_fd(size, params, flag, ION_HEAP_CARVEOUT_MASK);
    }
    if (ret < 0) {
        if (legacy_ion)
            ret = ion_alloc(cmem_fd, size, 0, 1<< ION_HEAP_TYPE_CUSTOM, flag, &params->mIonHnd);
        else
            ret = CMEM_alloc_fd(size, params, flag, ION_HEAP_TYPE_CUSTOM);
        if (ret < 0) {
            __E("ion_alloc failed, errno=%d\n", errno);
            return -ENOMEM;
        }
    } else {
        __D("CMEM_alloc okay done!\n");
    }
    if (legacy_ion) {
        ret = ion_share(cmem_fd, params->mIonHnd, &params->mImageFd);
        if (ret < 0) {
            __E("ion_share failed, errno=%d\n", errno);
            ion_free(cmem_fd, params->mIonHnd);
            return -EINVAL;
        }
        ion_free(cmem_fd, params->mIonHnd);
    }
    return ret;
}

int CMEM_invalid_cache(int shared_fd)
{
    int legacy_ion = 0;

    legacy_ion = ion_is_legacy(cmem_fd);
    if (!legacy_ion)
        return 0;
    if (cmem_fd !=-1 && shared_fd != -1) {
        if (ion_cache_invalid(cmem_fd, shared_fd)) {
            __E("CMEM_invalid_cache err!\n");
            return -1;
        }
    } else {
        __E("CMEM_invalid_cache err!\n");
        return -1;
    }
    return 0;
}

int CMEM_free(IONMEM_AllocParams *params)
{
    int legacy_ion = 0;

    if (!validate_init()) {
        return -1;
    }
    __D("CMEM_free,mIonHnd=%x free\n", params->mIonHnd);
    legacy_ion = ion_is_legacy(cmem_fd);
    if (!legacy_ion)
        return 0;
    ion_free(cmem_fd, params->mIonHnd);

    return 0;
}


int CMEM_exit(void)
{
    int result = 0;

    __D("exit: entered - ref_count %d, cmem_fd %d\n", ref_count, cmem_fd);

    if (!validate_init()) {
        return -1;
    }

    __D("exit: decrementing ref_count\n");

    ref_count--;
    if (ref_count == 0) {
        result = ion_close(cmem_fd);

        __D("exit: ref_count == 0, closed /dev/ion (%s)\n",
            result == -1 ? strerror(errno) : "succeeded");

        /* setting -3 allows to distinguish CMEM exit from CMEM failed */
        cmem_fd = -3;
    }

    __D("exit: exiting, returning %d\n", result);

    return result;
}

