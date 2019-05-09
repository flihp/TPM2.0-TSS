/* SPDX-License-Identifier: BSD-2-Clause */

#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_tbs.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tpm2_types.h>

#include "tbs-util.h"

#define CTX_MAX 16384

TSS2_TCTI_CONTEXT*
get_tbs_ctx(void)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    size_t size = 0;

    rc = Tss2_Tcti_Tbs_Init(NULL, &size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ERROR: Tss2_Tcti_Tbs_Init failed with RC: 0x%" PRIx32 "\n", rc);
        return NULL;
    }
    tcti_ctx = malloc(size);
    if (tcti_ctx == NULL) {
        perror("ERROR: malloc failed with error: ");
        return NULL;
    }
    rc = Tss2_Tcti_Tbs_Init(tcti_ctx, &size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ERROR: Tss2_Tcti_Tbs_Init failed with RC: 0x%" PRIx32 "\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

static TSS2_SYS_CONTEXT*
get_sys_ctx_full(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    TSS2_ABI_VERSION abiv = TSS2_ABI_VERSION_CURRENT;
    TSS2_RC rc;
    TSS2_SYS_CONTEXT *sys_ctx = NULL;
    size_t size;

    size = Tss2_Sys_GetContextSize(CTX_MAX);
    sys_ctx = malloc(size);
    if (sys_ctx == NULL) {
        perror("ERROR: malloc failed with error: ");
        return NULL;
    }
    rc = Tss2_Sys_Initialize(sys_ctx, size, tcti_ctx, &abiv);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr,
            "ERROR: Tss2_Tcti_Initialize failed with RC: 0x%"
            PRIx32 "\n",
            rc);
        if (sys_ctx)
            free(sys_ctx);
        return NULL;
    }
    return sys_ctx;
}

void
free_tbs_ctx(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx != NULL) {
        Tss2_Tcti_Finalize(tcti_ctx);
        free(tcti_ctx);
    }
}

static TSS2_TCTI_CONTEXT*
free_sys_ctx_full(TSS2_SYS_CONTEXT *sys_ctx)
{
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

    rc = Tss2_Sys_GetTctiContext(sys_ctx, &tcti_ctx);
    Tss2_Sys_Finalize(sys_ctx);
    free(sys_ctx);
    if (rc == TSS2_RC_SUCCESS && tcti_ctx != NULL)
        return tcti_ctx;
    return NULL;
}

TSS2_SYS_CONTEXT*
get_sys_ctx(void)
{
    TSS2_SYS_CONTEXT *sys_ctx;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

    tcti_ctx = get_tbs_ctx();
    if (tcti_ctx == NULL) {
        return NULL;
    }
    sys_ctx = get_sys_ctx_full(tcti_ctx);
    if (sys_ctx == NULL) {
        free_tbs_ctx(tcti_ctx);
        return NULL;
    }
    return sys_ctx;
}

void
free_sys_ctx(TSS2_SYS_CONTEXT *sys_ctx)
{
    TSS2_TCTI_CONTEXT *tcti_ctx;

    tcti_ctx = free_sys_ctx_full(sys_ctx);
    if (tcti_ctx == NULL)
        return;
    free_tbs_ctx(tcti_ctx);
}

bool
is_pcr_selected(BYTE pcr_selection[],
                uint8_t pcr)
{
    return pcr_selection[pcr / 8] & (1 << (pcr % 8));
}

void
deselect_pcr(BYTE pcr_selection[],
    uint8_t pcr)
{
    pcr_selection[pcr / 8] &= ~(1 << (pcr % 8));
}

void
foreach_selection(TPML_PCR_SELECTION *pcr_selection,
    PCR_SELECTION_CALLBACK callback,
    void *data)
{
    BYTE *selection;
    TPMI_ALG_HASH hash;
    uint8_t pcr;
    size_t i;

    /* iterate over TPMS_PCR_SELECTION array from TPML_PCR_SELECTION param */
    for (i = 0; i < pcr_selection->count; ++i) {
        /* iterate over PCRs */
        for (pcr = 0; pcr < TPM2_MAX_PCRS; ++pcr) {
            selection = pcr_selection->pcrSelections[i].pcrSelect;
            /* if bit corresponding to pcr in selection is set */
            if (is_pcr_selected(selection, pcr)) {
                hash = pcr_selection->pcrSelections[i].hash;
                if (callback(hash, pcr, data) == false)
                    return;
            }
        }
    }
}

void
dump_buf (const BYTE *buf,
          size_t size)
{
    size_t i;

    for (i = 0; i < size; ++i) {
        printf("%02x", buf[i]);
        if (i % 2)
            printf(" ");
    }
    printf("\n");
}

size_t
get_alg_size(UINT16 alg_id)
{
    switch (alg_id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
    default:
        return 0;
    }
}
char*
get_alg_name(UINT16 alg_id)
{
    switch (alg_id) {
    case TPM2_ALG_SHA1:
        return "EFI_TCG2_BOOT_HASH_ALG_SHA1";
    case TPM2_ALG_SHA256:
        return "EFI_TCG2_BOOT_HASH_ALG_SHA256";
    case TPM2_ALG_SHA384:
        return "EFI_TCG2_BOOT_HASH_ALG_SHA384";
    case TPM2_ALG_SHA512:
        return "EFI_TCG2_BOOT_HASH_ALG_SHA512";
    case TPM2_ALG_SM3_256:
        return "EFI_TCG2_BOOT_HASH_ALG_SM3_256";
    default:
        return "UNKNOWN_ALGORITHM";
    }
}
