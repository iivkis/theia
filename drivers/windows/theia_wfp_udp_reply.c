/*
 * WFP transport receive injection primitive for an already corroborated
 * UDP flow. This is intentionally not an IOCTL handler or capture policy.
 * No arbitrary user-supplied tuple is accepted by the current driver.
 * The caller must own the kernel flow generation and verify IPsec/scope,
 * endpoint liveness and authorization before calling; STOP drains all NBLs.
 *
 * API contract:
 * https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsinjecttransportreceiveasync0
 * https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsconstructipheaderfortransportpacket0
 */
#include <ntifs.h>
#define NDIS_SUPPORT_NDIS6 1
#pragma warning(push)
#pragma warning(disable: 4201)
#include <ndis.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <fwpsk.h>
#pragma warning(pop)
#include "theia_wfp_udp_reply.h"

#define REPLY_TAG 'rIhT'
#define REPLY_LIMIT 64
#define REPLY_MAX 65507u
#define REPLY_HEADROOM 64u
#define UDP_HEADER 8u

typedef struct _REPLY_COMPLETION {
    KEVENT done;
    NTSTATUS status;
} REPLY_COMPLETION;

static VOID NTAPI reply_complete(VOID *context, NET_BUFFER_LIST *nbl, BOOLEAN dispatchLevel) {
    REPLY_COMPLETION *completion = (REPLY_COMPLETION *)context;
    UNREFERENCED_PARAMETER(dispatchLevel);
    completion->status = NET_BUFFER_LIST_STATUS(nbl) == NDIS_STATUS_SUCCESS
        ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    FwpsFreeNetBufferList0(nbl);
    /* Last access to the completion object before the owner can release it. */
    KeSetEvent(&completion->done, IO_NO_INCREMENT, FALSE);
}

static BOOLEAN zero_bytes(const UCHAR *p, SIZE_T length) {
    UCHAR bits = 0;
    for (SIZE_T i = 0; i < length; ++i) bits |= p[i];
    return bits == 0;
}

static BOOLEAN valid_address(ADDRESS_FAMILY family, const UCHAR *p) {
    if (family == AF_INET) {
        return !zero_bytes(p, 4) && zero_bytes(p + 4, 12) && p[0] != 127 && p[0] < 224;
    }
    if (family != AF_INET6 || zero_bytes(p, 16) || p[0] == 0xff
        || (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
        || (zero_bytes(p, 10) && p[10] == 0xff && p[11] == 0xff)) return FALSE;
    return !(zero_bytes(p, 15) && p[15] == 1);
}

static VOID write16(UCHAR *p, USHORT value) {
    p[0] = (UCHAR)(value >> 8);
    p[1] = (UCHAR)value;
}

NTSTATUS TheiaReplyInitialize(THEIA_REPLY_ENGINE *engine) {
    NET_BUFFER_LIST_POOL_PARAMETERS parameters;
    NTSTATUS status;
    RtlZeroMemory(engine, sizeof(*engine));
    ExInitializeRundownProtection(&engine->rundown);
    KeInitializeEvent(&engine->retiredEvent, NotificationEvent, FALSE);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
    RtlZeroMemory(&parameters, sizeof(parameters));
    parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    parameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    parameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    parameters.fAllocateNetBuffer = TRUE;
    parameters.PoolTag = REPLY_TAG;
    engine->pool = NdisAllocateNetBufferListPool(NULL, &parameters);
    if (engine->pool == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = FwpsInjectionHandleCreate0(AF_UNSPEC, FWPS_INJECTION_TYPE_TRANSPORT, &engine->injection);
    if (!NT_SUCCESS(status)) {
        NdisFreeNetBufferListPool(engine->pool);
        engine->pool = NULL;
        engine->injection = NULL;
    }
    return status;
}

VOID TheiaReplyRetire(THEIA_REPLY_ENGINE *engine) {
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (InterlockedCompareExchange(&engine->retired, 1, 0) == 0) {
        ExWaitForRundownProtectionRelease(&engine->rundown);
        InterlockedExchange(&engine->retired, 2);
        KeSetEvent(&engine->retiredEvent, IO_NO_INCREMENT, FALSE);
    } else {
        KeWaitForSingleObject(&engine->retiredEvent, Executive, KernelMode, FALSE, NULL);
    }
}

VOID TheiaReplyDestroy(THEIA_REPLY_ENGINE *engine) {
    TheiaReplyRetire(engine);
    if (engine->injection != NULL) {
        FwpsInjectionHandleDestroy0(engine->injection);
        engine->injection = NULL;
    }
    if (engine->pool != NULL) {
        NdisFreeNetBufferListPool(engine->pool);
        engine->pool = NULL;
    }
}

NTSTATUS TheiaReplyInject(THEIA_REPLY_ENGINE *engine, const THEIA_REPLY_FLOW *flow,
    const UCHAR *payload, ULONG length) {
    UCHAR *storage = NULL, *udp;
    PMDL mdl = NULL;
    NET_BUFFER_LIST *nbl = NULL;
    REPLY_COMPLETION *completion = NULL;
    ULONG total = 0;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || flow == NULL
        || (length != 0 && payload == NULL) || length > REPLY_MAX
        || flow->compartment <= 1 || flow->interfaceIndex == 0
        || flow->endpoint == 0 || flow->generation == 0
        || flow->localPort == 0 || flow->remotePort == 0
        || !valid_address(flow->family, flow->localAddress)
        || !valid_address(flow->family, flow->remoteAddress)
        || RtlCompareMemory(flow->localAddress, flow->remoteAddress, 16) == 16)
        return STATUS_ACCESS_DENIED;

    if (!ExAcquireRundownProtection(&engine->rundown)) return STATUS_DEVICE_NOT_READY;
    if (InterlockedIncrement(&engine->inFlight) > REPLY_LIMIT) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    if (InterlockedCompareExchange(&engine->retired, 0, 0) != 0
        || engine->pool == NULL || engine->injection == NULL) goto out;

    total = REPLY_HEADROOM + UDP_HEADER + length;
    storage = (UCHAR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, total, REPLY_TAG);
    completion = (REPLY_COMPLETION *)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*completion), REPLY_TAG);
    if (storage == NULL || completion == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    KeInitializeEvent(&completion->done, NotificationEvent, FALSE);
    completion->status = STATUS_UNSUCCESSFUL;
    udp = storage + REPLY_HEADROOM;
    write16(udp, flow->remotePort);
    write16(udp + 2, flow->localPort);
    write16(udp + 4, (USHORT)(UDP_HEADER + length));
    write16(udp + 6, 0);
    if (length != 0) RtlCopyMemory(udp + UDP_HEADER, payload, length);

    mdl = IoAllocateMdl(storage, total, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    MmBuildMdlForNonPagedPool(mdl);
    status = FwpsAllocateNetBufferAndNetBufferList0(engine->pool, 0, 0, mdl,
        REPLY_HEADROOM, UDP_HEADER + length, &nbl);
    if (!NT_SUCCESS(status)) goto out;
    /* Construct the original reverse tuple and full UDP checksum.
     * EndpointHandle is intentionally zero: this is receive, not send.
     * Flags zero maintains compatibility with the Windows 10 target. */
    status = FwpsConstructIpHeaderForTransportPacket0(nbl, 0, flow->family,
        flow->remoteAddress, flow->localAddress, IPPROTO_UDP, 0,
        NULL, 0, 0, NULL, flow->interfaceIndex, flow->subInterfaceIndex);
    if (!NT_SUCCESS(status)) goto out;
    if (InterlockedCompareExchange(&engine->retired, 0, 0) != 0) {
        status = STATUS_DEVICE_NOT_READY;
        goto out;
    }

    status = FwpsInjectTransportReceiveAsync0(engine->injection, (HANDLE)(ULONG_PTR)flow->generation, NULL, 0,
        flow->family, flow->compartment, flow->interfaceIndex, flow->subInterfaceIndex,
        nbl, reply_complete, completion);
    if (status == STATUS_SUCCESS) {
        /* Completion owns NBL after successful submission. Do not retry
         * a failed completion, and never free the MDL before callback. */
        nbl = NULL;
        KeWaitForSingleObject(&completion->done, Executive, KernelMode, FALSE, NULL);
        status = completion->status;
    }

out:
    if (nbl != NULL) FwpsFreeNetBufferList0(nbl);
    if (mdl != NULL) IoFreeMdl(mdl);
    if (storage != NULL) {
        RtlSecureZeroMemory(storage, total);
        ExFreePoolWithTag(storage, REPLY_TAG);
    }
    if (completion != NULL) ExFreePoolWithTag(completion, REPLY_TAG);
    InterlockedDecrement(&engine->inFlight);
    ExReleaseRundownProtection(&engine->rundown);
    return status;
}
