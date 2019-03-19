/*
 * SPDX-License-Identifier: BSD-2
 * Copyright (c) 2019, Intel Corporation
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_sys.h"

#include "context-util.h"
#include "sapi-util.h"
#include "session-util.h"
#define LOGMODULE test
#include "util/log.h"

#define CheckPassed(rc) { \
    if (rc != TPM2_RC_SUCCESS) { \
        LOG_ERROR ("FAILURE: %s@%u with RC: 0x%" PRIx32, \
                   __FUNCTION__, __LINE__, rc); \
        return rc; \
    } else { \
        LOG_INFO ("SUCCESS: %s@%u", __FUNCTION__, __LINE__); \
    } \
}

#define NV_PS_INDEX_SIZE 34
#define INDEX_LCP_OWN 0x01400001
#define INDEX_LCP_SUP 0x01800001

#define TPM2B_SIZE_MAX(type) (sizeof (type) - 2)

const TSS2L_SYS_AUTH_COMMAND auth_cmd_null_pwd = {
    .count = 1,
    .auths = {
        {
            .sessionHandle = TPM2_RS_PW,
        },
    },
};

static TSS2_RC
create_policy_session (
    TSS2_SYS_CONTEXT *sys_ctx,
    TPMI_SH_AUTH_SESSION *handle)
{
    TPM2B_ENCRYPTED_SECRET salt = { 0 };
    TPM2B_NONCE nonce = {
        .size = GetDigestSize (TPM2_ALG_SHA1),
    };
    TPM2B_NONCE nonce_tpm = {
        .size = TPM2B_SIZE_MAX (nonce_tpm),
    };
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };

    return Tss2_Sys_StartAuthSession (sys_ctx,
                                      TPM2_RH_NULL,
                                      TPM2_RH_NULL,
                                      0,
                                      &nonce,
                                      &salt,
                                      TPM2_SE_POLICY,
                                      &symmetric,
                                      TPM2_ALG_SHA1,
                                      handle,
                                      &nonce_tpm,
                                      0);
}

static TSS2_RC
setup_nv (TSS2_SYS_CONTEXT *sys_ctx,
          TPMI_RH_NV_INDEX index)
{
    TSS2_RC rc;
    TPMI_SH_AUTH_SESSION auth_handle;
    TPM2B_DIGEST  policy_hash = {
        .size = TPM2B_SIZE_MAX (policy_hash),
    };
    TPM2B_AUTH  nv_auth = { .size = 0, };
    TSS2L_SYS_AUTH_RESPONSE auth_rsp;
    TPM2B_NV_PUBLIC public_info = {
        .size = sizeof (TPMI_RH_NV_INDEX) + sizeof (TPMI_ALG_HASH) +
            sizeof (TPMA_NV) + sizeof (UINT16) + sizeof( UINT16 ),
        .nvPublic = {
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE |
                TPMA_NV_PLATFORMCREATE | TPMA_NV_WRITEDEFINE | TPMA_NV_ORDERLY,
            .dataSize = NV_PS_INDEX_SIZE,
            .nvIndex = index,
        },
    };

    rc = create_policy_session (sys_ctx, &auth_handle);
    CheckPassed (rc);

    rc = Tss2_Sys_PolicyGetDigest (sys_ctx, auth_handle, 0, &policy_hash, 0);
    CheckPassed (rc);
    LOGBLOB_INFO (policy_hash.buffer, policy_hash.size, "policy_hash");

    rc = Tss2_Sys_NV_DefineSpace (sys_ctx,
                                  TPM2_RH_PLATFORM,
                                  &auth_cmd_null_pwd,
                                  &nv_auth,
                                  &public_info,
                                  &auth_rsp);
    CheckPassed (rc);

    rc = Tss2_Sys_FlushContext (sys_ctx, auth_handle);
    CheckPassed (rc);

    return TSS2_RC_SUCCESS;
}

static TSS2_RC
nv_write_read_test (TSS2_SYS_CONTEXT *sys_ctx,
                    TPMI_RH_NV_INDEX index)
{
    TSS2_RC rc;
    TPM2B_MAX_NV_BUFFER write_data = {
        .size = 4,
        .buffer = { 0xde, 0xad, 0xbe, 0xef },
    };
    TPM2B_MAX_NV_BUFFER nv_buf = {
        .size = TPM2B_SIZE_MAX (nv_buf),
    };
    TSS2L_SYS_AUTH_RESPONSE auth_resp = { 0, };

    rc = TSS2_RETRY_EXP (Tss2_Sys_NV_Write (sys_ctx,
                                            index,
                                            index,
                                            &auth_cmd_null_pwd,
                                            &write_data,
                                            0,
                                            &auth_resp));
    CheckPassed (rc);

    rc = Tss2_Sys_NV_Read (sys_ctx,
                           index,
                           index,
                           &auth_cmd_null_pwd,
                           4,
                           0,
                           &nv_buf,
                           &auth_resp);
    CheckPassed (rc);

    if (memcmp (nv_buf.buffer, write_data.buffer, write_data.size) != 0) {
        LOG_ERROR ("%s: data read from NV is different from data written",
                   __func__);
        LOGBLOB_DEBUG (write_data.buffer, write_data.size, "write_data");
        LOGBLOB_DEBUG (nv_buf.buffer, nv_buf.size, "nv_buf");
        return 1;
    }

    return TSS2_RC_SUCCESS;
}

static TSS2_RC
teardown_nv (TSS2_SYS_CONTEXT *sys_ctx,
             TPMI_RH_NV_INDEX index)
{
    TSS2_RC rc;
    TSS2L_SYS_AUTH_RESPONSE auth_resp = { 0, };

    rc = Tss2_Sys_NV_UndefineSpace (sys_ctx,
                                    TPM2_RH_PLATFORM,
                                    index,
                                    &auth_cmd_null_pwd,
                                    &auth_resp);
    CheckPassed (rc);

    return TSS2_RC_SUCCESS;
}
int
test_invoke (TSS2_SYS_CONTEXT *sys_ctx)
{
    TSS2_RC rc;

    rc = setup_nv (sys_ctx, INDEX_LCP_OWN);
    CheckPassed (rc);
    rc = setup_nv (sys_ctx, INDEX_LCP_SUP);
    CheckPassed (rc);
    rc = nv_write_read_test (sys_ctx, INDEX_LCP_OWN);
    CheckPassed (rc);
    rc = nv_write_read_test (sys_ctx, INDEX_LCP_SUP);
    CheckPassed (rc);
    rc = teardown_nv(sys_ctx, INDEX_LCP_OWN);
    CheckPassed (rc);
    rc = teardown_nv(sys_ctx, INDEX_LCP_SUP);
    CheckPassed (rc);

    return 0;
}
