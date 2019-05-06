/* SPDX-License-Identifier: BSD-2 */
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <tbs.h>

#include "..\..\include\tss2\tss2_tpm2_types.h"

#include "tbs-log.h"

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
static void
prettyprint_tbs_event_alg(SpecIdEventAlgSize *event_alg)
{
	printf("    HashAlg: %s\n", get_alg_name(event_alg->HashAlg));
	printf("    DigestSize: 0x%04" PRIx16 "\n", event_alg->DigestSize);
}
static bool
prettyprint_tbs_spec_event_header(SpecIdEventHeader *event_hdr,
	                              UINT32 size)
{
	SpecIdEventAlgs *event_algs;
	SpecIdEventVendor *event_vend;
	UINT32 i;
	size_t event_algs_offset = sizeof(*event_hdr);
	size_t event_vend_offset;

	if (event_hdr == NULL)
		return false;
	if (size < sizeof(SpecIdEventHeader)) {
		printf("ERROR: size is insufficient for SpecIdEventHeader\n");
	    return false;
    }

	if (strncmp((const char*)event_hdr->Signature, TPM2_LOG_SIG, TPM2_LOG_SIG_LENGTH)) {
		printf("ERROR: Signature is not the expected value of \"%s\"\n", TPM2_LOG_SIG);
		return false;
	}
	printf("  Signature: %s\n", event_hdr->Signature);
	printf("  PlatformClass: 0x%08" PRIx32 "\n", event_hdr->PlatformClass);
	printf("  SpecVersionMinor: 0x%02" PRIx8 "\n", event_hdr->SpecVersionMinor);
	printf("  SpecVersionMajor: 0x%02" PRIx8 "\n", event_hdr->SpecVersionMajor);
	printf("  SpecErrata: 0x%02" PRIx8 "\n", event_hdr->SpecErrata);
	printf("  UintNSize: 0x%02" PRIx8 "\n", event_hdr->UintNSize);
	if (size < event_algs_offset + sizeof(SpecIdEventAlgs)) {
		printf("ERROR: size is insufficient for SpecIdEventAlgs\n");
		return false;
	}

	event_algs = (SpecIdEventAlgs*)((BYTE*)event_hdr + event_algs_offset);
	event_vend_offset = event_algs_offset + sizeof (event_algs->Count) + event_algs->Count * sizeof(SpecIdEventAlgSize);
	if (size < event_vend_offset) {
		printf("ERROR: size is insufficient for DigestSizes\n");
		return false;
	}
	printf("  NumberOfAlgorithms: 0x%" PRIx32 "\n", event_algs->Count);
	for (i = 0; i < event_algs->Count; ++i) {
		printf("  DigestSizes[%d]:\n", i);
		prettyprint_tbs_event_alg(&event_algs->DigestSizes[i]);
	}
	event_vend = (SpecIdEventVendor*)((BYTE*)event_hdr + event_vend_offset);
	if (size < event_vend_offset + event_vend->Size) {
		printf("ERROR: size is insufficient for Vendor data\n");
		return false;
	}
	printf("  VendorInfoSize: 0x%" PRIx8 "\n", event_vend->Size);
	printf("  VendorInfo[]: ");
	for (i = 0; i < event_vend->Size; ++i) {
		printf("%02x", event_vend->VendorInfo[i]);
		if (i % 2)
			printf(" ");
	}
	printf("\n");
	return true;
}
char*
eventtype_to_string(TCG_EVENTTYPE event_type)
{
	switch (event_type) {
	case EV_PREBOOT_CERT:
		return "EV_PREBOOT_CERT";
	case EV_POST_CODE:
		return "EV_POST_CODE";
	case EV_UNUSED:
		return "EV_UNUSED";
	case EV_NO_ACTION:
		return "EV_NO_ACTION";
	case EV_SEPARATOR:
		return "EV_SEPARATOR";
	case EV_ACTION:
		return "EV_ACTION";
	case EV_EVENT_TAG:
		return "EV_EVENT_TAG";
	case EV_S_CRTM_CONTENTS:
		return "EV_S_CRTM_CONTENTS";
	case EV_S_CRTM_VERSION:
		return "EV_S_CRTM_VERSION";
	case EV_CPU_MICROCODE:
		return "EV_CPU_MICROCODE";
	case EV_PLATFORM_CONFIG_FLAGS:
		return "EV_PLATFORM_CONFIG_FLAGS";
	case EV_TABLE_OF_DEVICES:
		return "EV_TABLE_OF_DEVICES";
	case EV_COMPACT_HASH:
		return "EV_COMPACT_HASH";
	case EV_IPL:
		return "EV_IPL";
	case EV_IPL_PARTITION_DATA:
		return "EV_IPL_PARTITION_DATA";
	case EV_NONHOST_CODE:
		return "EV_NONHOST_CODE";
	case EV_NONHOST_CONFIG:
		return "EV_NONHOST_CONFIG";
	case EV_NONHOST_INFO:
		return "EV_NONHOST_INFO";
	case EV_OMIT_BOOT_DEVICE_EVENTS:
		return "EV_OMIT_BOOT_DEVICE_EVENTS";
	case EV_EFI_VARIABLE_DRIVER_CONFIG:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG";
	case EV_EFI_VARIABLE_BOOT:
		return "EV_EFI_VARIABLE_BOOT";
	case EV_EFI_BOOT_SERVICES_APPLICATION:
		return "EV_EFI_BOOT_SERVICES_APPLICATION";
	case EV_EFI_BOOT_SERVICES_DRIVER:
		return "EV_EFI_BOOT_SERVICES_DRIVER";
	case EV_EFI_RUNTIME_SERVICES_DRIVER:
		return "EV_EFI_RUNTIME_SERVICES_DRIVER";
	case EV_EFI_GPT_EVENT:
		return "EV_EFI_GPT_EVENT";
	case EV_EFI_ACTION:
		return "EV_EFI_ACTION";
	case EV_EFI_PLATFORM_FIRMWARE_BLOB:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB";
	case EV_EFI_HANDOFF_TABLES:
		return "EV_EFI_HANDOFF_TABLES";
	case EV_EFI_VARIABLE_AUTHORITY:
		return "EV_EFI_VARIABLE_AUTHORITY";
	default:
		return "Unknown event type";
	}
}
static bool
prettyprint_tbs_firstevent(TCG_PCR_EVENT *event)
{
	TCG_DIGEST expected_digest = { 0, };
	size_t i;

	printf("PCR_INDEX: 0x%" PRIx32 "\n", event->PCRIndex);
	if (event->PCRIndex != 0) {
		printf("PCRIndex is %u, should be 0\n", event->PCRIndex);
		return false;
	}
	printf("EventType: %s\n", eventtype_to_string(event->EventType));
	if (event->EventType != EV_NO_ACTION) {
		printf("EventType is %u, should be EV_NO_ACTION\n", event->EventType);
		return false;
	}
	printf("Digest: ");
	for (i = 0; i < 20; ++i) {
		printf("%02x", event->Digest[i]);
		if (i < 19 && i % 2)
			printf(" ");
	}
	printf("\n");
	if (memcmp(event->Digest, &expected_digest, sizeof(expected_digest))) {
		printf("Digest is not expected 20 bytes of 0's\n");
		return false;
	}
	printf("EventSize: 0x%" PRIx32 "\n", event->EventSize);
	printf("Event:\n");
	return prettyprint_tbs_spec_event_header((SpecIdEventHeader*)event->Event,
                                             event->EventSize);
}
static size_t
prettyprint_tpm2_eventbuf(TCG_EVENT2 *event,
	                      size_t size)
{
	size_t i;

	printf("  Event: %" PRIu32 " bytes\n", event->EventSize);
	for (i = 0; i < event->EventSize; ++i) {
		printf("%02x", event->Event[i]);
		if (i % 2)
			printf(" ");
	}
	return event->Event + event->EventSize - (BYTE*)event;
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
static size_t
prettyprint_tpm2_digest(TCG_DIGEST2 *digest,
	                    size_t size)
{
	size_t digest_size, i;

	printf("    AlgorithmId: %s (0x%" PRIx16 ")\n",
           get_alg_name(digest->AlgorithmId), digest->AlgorithmId);
	/* map alg id to alg size to get buffer size */
	digest_size = get_alg_size(digest->AlgorithmId);
	printf("    Digest: ");
	for (i = 0; i < digest_size; ++i) {
		printf("%02x", digest->Digest[i]);
		if (i % 2)
			printf(" ");
	}
	return digest->Digest + digest_size - (BYTE*)digest;
}
static void
prettyprint_tpm2_event_header(TCG_EVENT_HEADER2 *event_hdr)
{
	printf("  PCRIndex: %d\n", event_hdr->PCRIndex);
	printf("  EventType: %s (0x%" PRIx32 ")\n",
		   eventtype_to_string(event_hdr->EventType),
		   event_hdr->EventType);
	printf("  DigestCount: %d\n", event_hdr->DigestCount);
}
static size_t
prettyprint_tpm2_event(TCG_PCR_EVENT2* pcr_event,
	                   size_t size)
{
	TCG_EVENT_HEADER2 *header = pcr_event;
	TCG_DIGEST2 *digest;
	TCG_EVENT2 *event;
	size_t i, digest_size;

	if (size < sizeof(*header)) {
		printf("ERROR: insufficient size for TCG_PCR_EVENT2\n");
		return 0;
	}
	prettyprint_tpm2_event_header(header);
	digest = header->Digests;
	for (i = 0, size -= sizeof (*header);
		 i < header->DigestCount && size > 0;
		++i, size -= digest_size)
	{
		printf("  TCG_DIGEST2: %zu\n", i);
		digest_size = prettyprint_tpm2_digest(digest, size);
		digest = (TCG_DIGEST2*)((BYTE*)digest + digest_size);
	}
	event = (TCG_EVENT2*)digest;
	prettyprint_tpm2_eventbuf(event, size);
	return event->Event + event->EventSize - (BYTE*)pcr_event;
}
static bool
prettyprint_tpm2_eventlog(TCG_PCR_EVENT2 *event,
	                      size_t size)
{
	size_t i = 0, event_size;

	if (event == NULL) {
		printf("TPM2 EventLog is empty.\n");
		return false;
	}
	if (size < sizeof(*event)) {
		printf("ERROR: size insufficient for TCG_PCR_EVENT2\n");
		return false;
	}

	printf("TPM2 EventLog, EFI_TCG2_EVENT_LOG_FORMAT_TCG_2 format\n");
	for (i = 0; size > 0; size -= event_size) {
		printf("TCG_PCR_EVENT2 [%zu]:\n", i++);
		event_size = prettyprint_tpm2_event(event, size);
		event = (TCG_PCR_EVENT2*)((BYTE*)event + event_size);
    }
	printf("TPM2 EventLog end\n");
	return true;
}
static bool
prettyprint_tbs_eventlog(BYTE *first,
	                     UINT32 size)
{
	TCG_PCR_EVENT *event = (TCG_PCR_EVENT*)first;
	TCG_PCR_EVENT2 *event2;

	if (event == NULL) {
		printf("TBS EventLog is empty.\n");
		return true;
	}
	if (size < sizeof(TCG_PCR_EVENT)) {
		printf("Log size insufficient for the TBS specific Event\n");
		return true;
	}

	if (!prettyprint_tbs_firstevent(event))
		return false;

	size -= sizeof(*event) + event->EventSize;
	event2 = (TCG_PCR_EVENT2*)(first + sizeof(*event) + event->EventSize);
	return prettyprint_tpm2_eventlog(event2, size);
}

BYTE*
get_log(TBS_HCONTEXT ctx, UINT32 *size)
{
	BYTE *log;
	TBS_RESULT result;

	result = Tbsi_Get_TCG_Log(ctx, NULL, size);
	if (result != TBS_SUCCESS) {
		printf("ERROR: Unable to determine size of TCG Log: 0x%x\n", result);
		return NULL;
	}

	log = malloc(*size);
	if (log == NULL) {
		printf("ERROR: Failed to allocate %u bytes for the event log: %s\n",
			   *size, strerror(errno));
		return NULL;
	}

	result = Tbsi_Get_TCG_Log(ctx, log, size);
	if (result != TBS_SUCCESS) {
		printf("ERROR: Failed to get TCG Log: 0x%x\n", result);
		free(log);
		return NULL;
	}

	return log;
}

int
main(void)
{
	BYTE *log = NULL;
	TBS_CONTEXT_PARAMS2 params = {
		.version = TPM_VERSION_20,
		.includeTpm20 = 1,
	};
	TBS_HCONTEXT context;
	TBS_RESULT result;
	UINT32 size = 0;

	result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &context);
	if (result != TBS_SUCCESS) {
		printf("Tbsi_ContextCreate failed: 0x%x\n", result);
		return 1;
	}

	log = get_log(context, &size);
	if (log == NULL) {
		return 1;
	}

	prettyprint_tbs_eventlog(log, size);
	return 0;
}