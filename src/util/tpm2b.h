/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef TPM2B_H
#define TPM2B_H

#include TPM2TYPES_HEADER

typedef struct {
    UINT16 size;
    BYTE buffer[1];
} TPM2B;

#endif /* TPM2B_H */
