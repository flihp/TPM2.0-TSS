/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TBS_UTIL_H
#define TBS_UTIL_H

#include <stdbool.h>
#include <stdlib.h>

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti.h>

typedef bool(*PCR_SELECTION_CALLBACK) (TPMI_ALG_HASH alg,
    uint8_t pcr,
    void *data);

TSS2_TCTI_CONTEXT*
get_tbs_ctx(void);
void
free_tbs_ctx(TSS2_TCTI_CONTEXT *tcti_ctx);
TSS2_SYS_CONTEXT*
get_sys_ctx(void);
void
free_sys_ctx(TSS2_SYS_CONTEXT *sys_ctx);
bool
is_pcr_selected(BYTE pcr_selection[],
                uint8_t pcr);
void
deselect_pcr(BYTE pcr_selection[],
             uint8_t pcr);
void
foreach_selection(TPML_PCR_SELECTION *pcr_selection,
                  PCR_SELECTION_CALLBACK callback,
                  void *data);
void
dump_buf(const BYTE *buf,
         size_t size);
size_t
get_alg_size(UINT16 alg_id);
char*
get_alg_name(UINT16 alg_id);

#endif