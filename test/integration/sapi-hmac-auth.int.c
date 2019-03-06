/*
 * SPDX-License-Identifier: BSD-2
 * Copyright (c) 2019, Intel Corporation
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_sys.h"

#include "context-util.h"
#include "sapi-util.h"
#include "session-util.h"
#include "util/aux_util.h"
#define LOGMODULE test
#include "util/log.h"

#define TPM20_INDEX_PASSWORD_TEST 0x01500020
#define TPM2B_SIZE_MAX(type) (sizeof (type) - 2)

const TSS2L_SYS_AUTH_COMMAND auth_cmd_null_pwd = {
    .count = 1,
    .auths = {
        {
            .sessionHandle = TPM2_RS_PW,
        },
    },
};

#define NV_DATA_SIZE 4
#define NV_DATA { 0x00, 0xff, 0x55, 0xaa }
#define SECRET_SIZE 13
#define SECRET_DATA { 's', 'h', 'a', 'r', 'e', 'd', ' ', \
                      's', 'e', 'c', 'r', 'e', 't', }

TSS2_RC
do_test (TSS2_SYS_CONTEXT *sys_ctx,
         bool policy)
{
    TSS2_RC rc;
    TPM2B_AUTH  auth = {
        .size = SECRET_SIZE,
        .buffer = SECRET_DATA,
    };
    SESSION *session, *session_trial_policy = NULL;
    TPMA_NV attrs_nv;
    TPM2B_DIGEST digest_policy = { 0, };
    TPM2B_NONCE nonce_caller = { 0, };
    TPM2B_MAX_NV_BUFFER nv_data_write = {
        .size = NV_DATA_SIZE,
        .buffer = NV_DATA,
    };
    TPM2B_MAX_NV_BUFFER nv_data_read = {
        .size = TPM2B_SIZE_MAX (nv_data_read),
    };
    TPM2B_ENCRYPTED_SECRET encrypted_salt = { 0, };
    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_NULL, };
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2L_SYS_AUTH_RESPONSE auth_rsp = { 0, };
    TSS2L_SYS_AUTH_COMMAND auth_cmd = {
        .count = 1,
        .auths= {
            {
                .nonce = {
                    .size = 1,
                    .buffer = { 0xa5, },
                },
                .sessionAttributes = TPMA_SESSION_CONTINUESESSION,
            }
        }
    };

    if (policy) {
        attrs_nv = TPMA_NV_POLICYREAD | TPMA_NV_POLICYWRITE | TPMA_NV_PLATFORMCREATE;
    } else {
        attrs_nv = TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_PLATFORMCREATE;
    }

    rc = Tss2_Sys_GetTctiContext (sys_ctx, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS || tcti_ctx == NULL) {
        LOG_ERROR("InitSysContext failed, exiting...");
        exit (1);
    }

    if (policy) {
        rc = create_auth_session (&session_trial_policy,
                                  TPM2_RH_NULL,
                                  0,
                                  TPM2_RH_NULL,
                                  0,
                                  &nonce_caller,
                                  &encrypted_salt,
                                  TPM2_SE_TRIAL,
                                  &symmetric,
                                  TPM2_ALG_SHA256,
                                  tcti_ctx);
        return_if_error (rc, "create_auth_session");
        rc = Tss2_Sys_PolicyAuthValue (sys_ctx,
                                       session_trial_policy->sessionHandle,
                                       0,
                                       0);
        return_if_error (rc, "Tss2_Sys_PolicyAuthValue");
        rc = Tss2_Sys_PolicyGetDigest (sys_ctx,
                                       session_trial_policy->sessionHandle,
                                       0,
                                       &digest_policy,
                                       0);
        return_if_error (rc, "Tss2_Sys_PolicyGetDigest");

        rc = Tss2_Sys_FlushContext (sys_ctx,
                                    session_trial_policy->sessionHandle);
        return_if_error (rc, "Tss2_Sys_FlushContext");

        end_auth_session (session_trial_policy);
    }

    rc = DefineNvIndex (sys_ctx,
                        TPM2_RH_PLATFORM,
                        &auth,
                        &digest_policy,
                        TPM20_INDEX_PASSWORD_TEST,
                        TPM2_ALG_SHA256,
                        attrs_nv,
                        32);
    return_if_error (rc, "DefineNvIndex");

    /* Add index and associated authorization value to entity table. */
    rc = AddEntity(TPM20_INDEX_PASSWORD_TEST, &auth);
    return_if_error (rc, "AddEntity");

    /*
     * Start unbound, unsalted authorization session. Session type is
     * determined by 'policy' boolean.
     */
    rc = create_auth_session (&session,
                              TPM2_RH_NULL,
                              NULL,
                              TPM2_RH_NULL,
                              NULL,
                              &nonce_caller,
                              &encrypted_salt,
                              policy ? TPM2_SE_POLICY : TPM2_SE_HMAC,
                              &symmetric,
                              TPM2_ALG_SHA256,
                              tcti_ctx);
    return_if_error (rc, "create_auth_session");
    auth_cmd.auths[0].sessionHandle = session->sessionHandle;

    /* Store session name in session structure. */
    rc = tpm_handle_to_name (tcti_ctx,
                             session->sessionHandle,
                             &session->name);
    return_if_error (rc, "tpm_handle_to_name");

    if (policy) {
        rc = Tss2_Sys_PolicyAuthValue (sys_ctx,
                                       session->sessionHandle,
                                       NULL,
                                       NULL);
        return_if_error (rc, "Tss2_Sys_PolicyAuthValue");
    }
    /* Prepare command buffer, required for HMAC calculations */
    rc = Tss2_Sys_NV_Write_Prepare (sys_ctx,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    &nv_data_write,
                                    0);
    return_if_error (rc, "Tss2_Sys_NV_Write_Prepare");

    /* Compute HMAC, add it to auth_cmd. */
    roll_nonces (session, &auth_cmd.auths[0].nonce);
    rc = compute_command_hmac(sys_ctx,
                              TPM20_INDEX_PASSWORD_TEST,
                              TPM20_INDEX_PASSWORD_TEST,
                              TPM2_RH_NULL,
                              &auth_cmd);
    return_if_error (rc, "compute_command_hmac");

    /* Write to NV. If the command is successful, the HMAC was correct. */
    rc = TSS2_RETRY_EXP (Tss2_Sys_NV_Write (sys_ctx,
                                            TPM20_INDEX_PASSWORD_TEST,
                                            TPM20_INDEX_PASSWORD_TEST,
                                            &auth_cmd,
                                            &nv_data_write,
                                            0,
                                            &auth_rsp));
    return_if_error (rc, "Tss2_Sys_NV_Write");

    /* Calculate nonces and check response HMAC. */
    roll_nonces (session, &auth_rsp.auths[0].nonce);
    rc = check_response_hmac (sys_ctx,
                              &auth_cmd,
                              TPM20_INDEX_PASSWORD_TEST,
                              TPM20_INDEX_PASSWORD_TEST,
                              TPM2_RH_NULL,
                              &auth_rsp);
    return_if_error (rc, "check_response_hmac");

    if (policy) {
        rc = Tss2_Sys_PolicyAuthValue (sys_ctx,
                                       session->sessionHandle,
                                       NULL,
                                       NULL);
        return_if_error (rc, "Tss2_Sys_PolicyAuthValue");
    }
    /* Prepare command buffer, required for HMAC calculations */
    rc = Tss2_Sys_NV_Read_Prepare (sys_ctx,
                                   TPM20_INDEX_PASSWORD_TEST,
                                   TPM20_INDEX_PASSWORD_TEST,
                                   NV_DATA_SIZE,
                                   0);
    return_if_error (rc, "Tss2_Sys_NV_Read_Prepare");

    /* End the session after next command. */
    auth_cmd.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;

    /* Compute HMAC, add it to auth_cmd. */
    roll_nonces (session, &auth_cmd.auths[0].nonce);
    rc = compute_command_hmac (sys_ctx,
                               TPM20_INDEX_PASSWORD_TEST,
                               TPM20_INDEX_PASSWORD_TEST,
                               TPM2_RH_NULL,
                               &auth_cmd);
    return_if_error (rc, "compute_command_hmac");

    /* Read from NV. If the command is successful, the HMAC was correct. */
    rc = Tss2_Sys_NV_Read (sys_ctx,
                           TPM20_INDEX_PASSWORD_TEST,
                           TPM20_INDEX_PASSWORD_TEST,
                           &auth_cmd,
                           NV_DATA_SIZE,
                           0,
                           &nv_data_read,
                           &auth_rsp);
    return_if_error (rc, "Tss2_Sys_NV_Read");

    /* Calculate nonces and check response HMAC. */
    roll_nonces (session, &auth_rsp.auths[0].nonce);
    rc = check_response_hmac (sys_ctx,
                              &auth_cmd,
                              TPM20_INDEX_PASSWORD_TEST,
                              TPM20_INDEX_PASSWORD_TEST,
                              TPM2_RH_NULL,
                              &auth_rsp);
    return_if_error (rc, "check_response_hmac");

    /* Check that write and read data are equal. */
    if (memcmp (nv_data_read.buffer, nv_data_write.buffer, nv_data_read.size))
    {
        LOG_ERROR ("Data read not equal to data written.");
        return 1;
    }

    /* Undefine the NV index. */
    rc = Tss2_Sys_NV_UndefineSpace (sys_ctx,
                                    TPM2_RH_PLATFORM,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    &auth_cmd_null_pwd,
                                    NULL);
    return_if_error (rc, "Tss2_Sys_NV_UndefineSpace");

    /* Delete the NV index's entry in the entity table. */
    DeleteEntity (TPM20_INDEX_PASSWORD_TEST);

    /* Remove the real session from sessions table. */
    end_auth_session (session);
    return 0;
}
int
test_invoke (TSS2_SYS_CONTEXT *sys_ctx)
{
    TSS2_RC rc;

    LOG_INFO ("HMAC session test");
    rc = do_test (sys_ctx, false);
    return_if_error (rc, "do_test");

    LOG_INFO ("Policy session test");
    rc = do_test (sys_ctx, true);
    return_if_error (rc, "do_test");

    return TSS2_RC_SUCCESS;
}
