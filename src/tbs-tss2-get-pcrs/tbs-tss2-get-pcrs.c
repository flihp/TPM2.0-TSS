/* SPDX-License-Identifier: BSD-2-Clause */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include "../tbs-util/tbs-util.h"

TSS2_RC
get_pcrselection (TSS2_SYS_CONTEXT *sys_ctx,
                  TPML_PCR_SELECTION *selection)
{
    TSS2_RC rc;
    TPMI_YES_NO more = TPM2_NO;
    TPMS_CAPABILITY_DATA caps = { 0, };

    /*
     * GetCapability with TPM2_CAP_PCR returns pcr selection structure
     * populated with data describing currently active PCRs.
     */
    rc = Tss2_Sys_GetCapability(sys_ctx,
                                NULL,
                                TPM2_CAP_PCRS,
                                0,
                                1,
                                &more,
                                &caps,
                                NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr,
                "ERROR: Tss2_Sys_GetCapability failed with RC: 0x%"
                PRIx32 "\n",
                rc);
        return rc;
    }

    memcpy(selection, &caps.data.assignedPCR, sizeof(caps.data.assignedPCR));
    return rc;
}

typedef struct callback_data {
    size_t digest_i;
    TPMI_ALG_HASH last_alg;
    TPML_DIGEST tpml_digests;
    TPML_PCR_SELECTION pcr_select;
} callback_data_t;

bool
selected_digest_callback(TPMI_ALG_HASH alg,
    uint8_t pcr,
    void *data)
{
    callback_data_t *cbdata = (callback_data_t*)data;
    TPMS_PCR_SELECTION *selection;
    TPM2B_DIGEST *digest;
    size_t i;

    if (cbdata == NULL) {
        printf("ERROR: cbdata cannot be NULL.\n");
        return false;
    }
    digest = &cbdata->tpml_digests.digests[cbdata->digest_i++];
    if (get_alg_size(alg) != digest->size) {
        printf("ERROR: algorithm and digest size disagre?\n");
    }
    if (cbdata->last_alg != alg) {
        cbdata->last_alg = alg;
        printf("PCR bank: %s\n", get_alg_name(alg));
    }
    printf("  PCR[%02u]: ", pcr);
    dump_buf(digest->buffer, digest->size);

    for (i = 0; i < cbdata->pcr_select.count; ++i) {
        selection = &cbdata->pcr_select.pcrSelections[i];
        if (selection->hash == alg) {
            deselect_pcr(selection->pcrSelect, pcr);
        }
    }

    if (!(cbdata->digest_i < cbdata->tpml_digests.count))
        return false;
    else
        return true;
}

int
prettyprint_pcrs_from_selection (TSS2_SYS_CONTEXT *sys_ctx,
                                 const TPML_PCR_SELECTION *selection)
{
    TSS2_RC rc;
    UINT32 update_count = 0;
    TPML_PCR_SELECTION pcr_select_out = { 0, };
    callback_data_t cbdata = { 0, };

    memcpy(&cbdata.pcr_select, selection, sizeof(cbdata.pcr_select));
    do {
        cbdata.digest_i = 0;
        memset(&cbdata.tpml_digests, 0, sizeof(cbdata.tpml_digests));
        rc = Tss2_Sys_PCR_Read(sys_ctx,
            NULL,
            &cbdata.pcr_select,
            &update_count,
            &pcr_select_out,
            &cbdata.tpml_digests,
            NULL);
        if (rc != TSS2_RC_SUCCESS) {
            printf("ERROR: Tss2_Sys_PCR_Read failed with RC: 0x%" PRIx32 "\n",
                rc);
            return 1;
        }
        foreach_selection(&pcr_select_out,
            selected_digest_callback,
            &cbdata);
    } while (cbdata.tpml_digests.count > 0);

    return 0;
}

int
main(void)
{
    TPML_PCR_SELECTION pcr_selection = { 0 };
    TSS2_RC rc;
    TSS2_SYS_CONTEXT *sys_ctx;
    int ret = 0;

    sys_ctx = get_sys_ctx();
    if (sys_ctx == NULL) {
        ret = 1;
        goto out;
    }

    rc = get_pcrselection(sys_ctx, &pcr_selection);
    if (rc != TSS2_RC_SUCCESS) {
        ret = 1;
        goto out;
    }

    if (prettyprint_pcrs_from_selection(sys_ctx, &pcr_selection))
        ret = 1;
    
out:
    free_sys_ctx(sys_ctx);
	return ret;
}