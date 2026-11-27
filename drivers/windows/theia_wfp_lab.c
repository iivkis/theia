/*
 * Theia isolated WFP lab callout, Windows 10 2004+ WDK.
 * No global filters, service installation or driver-signing changes.
 * External trusted test harness must register matching BFE callouts and
 * terminating filters only in a dedicated non-default network compartment.
 * Unsupported, unconfigured and ambiguous requests fail closed.
 */
#include <ntifs.h>
#include <wdmsec.h>
/* WFP kernel headers require NDIS 6 packet-list declarations. The
 * Microsoft headers intentionally use anonymous structures and unions. */
#define NDIS_SUPPORT_NDIS6 1
#pragma warning(push)
#pragma warning(disable: 4201)
#include <ndis.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <fwpsk.h>
#pragma warning(pop)
#include "theia_wfp_udp_reply.h"
#include "theia_wfp_udp_flow.h"

#define THEIA_TAG 'aiHT'
#define CONTEXT_SIZE 84
#define CONFIG_SIZE 40
#define ENDPOINT_SIZE 28
#define MAX_ENDPOINTS 64
#define IOCTL_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ENDPOINT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_STOP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_UDP_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_UDP_REPLY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_UDP_CLOSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)

static const GUID Provider = {0x172b0eba,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID CalloutV4 = {0x172b0ebb,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID CalloutV6 = {0x172b0ebc,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID DeviceClass = {0x172b0ebd,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\TheiaWfpLab");
static UNICODE_STRING LinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\TheiaWfpLab");
static UNICODE_STRING SystemOnly = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)");

typedef struct _ENDPOINT_PERMIT {
    UINT64 endpoint;
    UINT64 expires;
    UCHAR family;
    UCHAR protocol;
    USHORT port;
    UCHAR address[16];
} ENDPOINT_PERMIT;

typedef struct _SESSION {
    BOOLEAN configured;
    BOOLEAN active;
    ULONG compartment;
    ULONG pid;
    USHORT port;
    PFILE_OBJECT file;
    PEPROCESS process;
    UCHAR token[32];
    ENDPOINT_PERMIT permits[MAX_ENDPOINTS];
} SESSION;

static SESSION State;
static KSPIN_LOCK StateLock;
static EX_RUNDOWN_REF ClassifyRundown;
static THEIA_REPLY_ENGINE ReplyEngine;
static BOOLEAN ReplyInitialized;
static HANDLE Redirect;
static UINT32 Id4, Id6;
static PDEVICE_OBJECT Device;
static BOOLEAN ProcessNotifyRegistered;

static UINT16 read16(const UCHAR *p) {
    return ((UINT16)p[0] << 8) | p[1];
}
static UINT32 read32(const UCHAR *p) {
    return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) | ((UINT32)p[2] << 8) | p[3];
}
static UINT64 read64(const UCHAR *p) {
    return ((UINT64)read32(p) << 32) | read32(p + 4);
}
static VOID write32(UCHAR *p, UINT32 n) {
    p[0] = (UCHAR)(n >> 24); p[1] = (UCHAR)(n >> 16); p[2] = (UCHAR)(n >> 8); p[3] = (UCHAR)n;
}
static BOOLEAN zero(const UCHAR *p, SIZE_T n) {
    UCHAR bits = 0;
    for (SIZE_T i = 0; i < n; ++i) bits |= p[i];
    return bits == 0;
}
static BOOLEAN equal(const UCHAR *a, const UCHAR *b, SIZE_T n) {
    return RtlCompareMemory(a, b, n) == n;
}
static BOOLEAN valid_ip(UCHAR family, const UCHAR *p, BOOLEAN source) {
    if (family == 4) {
        return !zero(p, 4) && zero(p + 4, 12) && p[0] < 224
            && (source || p[0] != 127);
    }
    if (family != 6 || zero(p, 16) || p[0] == 0xff
        || (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
        || (zero(p, 10) && p[10] == 0xff && p[11] == 0xff)) return FALSE;
    return source || !(zero(p, 15) && p[15] == 1);
}
static VOID deactivate_locked(VOID) {
    State.active = FALSE;
    TheiaUdpStop();
    RtlSecureZeroMemory(State.token, sizeof(State.token));
    RtlSecureZeroMemory(State.permits, sizeof(State.permits));
}

static VOID NTAPI process_notify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO Info) {
    KIRQL irql;
    UNREFERENCED_PARAMETER(ProcessId);
    if (Info != NULL) return;
    KeAcquireSpinLock(&StateLock, &irql);
    if (State.process == Process) deactivate_locked();
    KeReleaseSpinLock(&StateLock, irql);
}

static NTSTATUS finish_irp(PIRP Irp, NTSTATUS status) {
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
static NTSTATUS unsupported(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    return finish_irp(irp, STATUS_INVALID_DEVICE_REQUEST);
}
static NTSTATUS open_close(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    return finish_irp(irp, STATUS_SUCCESS);
}
static NTSTATUS cleanup(PDEVICE_OBJECT dev, PIRP irp) {
    KIRQL irql;
    UNREFERENCED_PARAMETER(dev);
    KeAcquireSpinLock(&StateLock, &irql);
    if (State.file == IoGetCurrentIrpStackLocation(irp)->FileObject) {
        deactivate_locked();
        State.file = NULL;
    }
    KeReleaseSpinLock(&StateLock, irql);
    return finish_irp(irp, STATUS_SUCCESS);
}

static NTSTATUS control(PDEVICE_OBJECT dev, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    UCHAR *bytes = (UCHAR *)irp->AssociatedIrp.SystemBuffer;
    ULONG len = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    BOOLEAN waitForClassify = FALSE;
    ULONG_PTR written = 0;
    ULONG output = stack->Parameters.DeviceIoControl.OutputBufferLength;
    KIRQL irql;
    UNREFERENCED_PARAMETER(dev);
    if (bytes == NULL || irp->RequestorMode != UserMode || KeGetCurrentIrql() != PASSIVE_LEVEL
        || IoGetRequestorProcess(irp) != PsGetCurrentProcess()
        || (code != IOCTL_UDP_READ && output != 0)) {
        return finish_irp(irp, status);
    }
    KeAcquireSpinLock(&StateLock, &irql);
    if ((code==IOCTL_UDP_READ || code==IOCTL_UDP_REPLY || code==IOCTL_UDP_CLOSE)
        && State.active && State.file==stack->FileObject && State.process==PsGetCurrentProcess()
        && len>=40 && equal(bytes,State.token,32)) {
        UINT64 generation=read64(bytes+32);
        KeReleaseSpinLock(&StateLock,irql);
        if (code==IOCTL_UDP_READ && len==40 && generation==0 && output==THEIA_UDP_HEADER+THEIA_UDP_MAX)
            status=TheiaUdpRead(bytes,output,&written);
        else if (code==IOCTL_UDP_REPLY && generation && len<=40+THEIA_UDP_MAX)
            status=TheiaUdpReply(generation,bytes+40,len-40);
        else if (code==IOCTL_UDP_CLOSE && generation && len==40)
            status=TheiaUdpClose(generation);
        if (code!=IOCTL_UDP_READ || !NT_SUCCESS(status)) RtlSecureZeroMemory(bytes,len);
        irp->IoStatus.Status=status;irp->IoStatus.Information=written;
        IoCompleteRequest(irp,IO_NO_INCREMENT);
        return status;
    }
    if (code == IOCTL_CONFIG && len == CONFIG_SIZE && !State.configured
        && read32(bytes) > 1 && read16(bytes + 4) != 0 && bytes[6]<=1 && bytes[7]==0
        && !zero(bytes + 8, 32) && ReplyInitialized
        && TheiaUdpStart(read32(bytes),bytes[6]==1)) {
        State.compartment = read32(bytes);
        State.port = read16(bytes + 4);
        State.pid = HandleToULong(PsGetCurrentProcessId());
        State.process = PsGetCurrentProcess();
        ObReferenceObject(State.process);
        State.file = stack->FileObject;
        RtlCopyMemory(State.token, bytes + 8, 32);
        State.configured = State.active = TRUE;
        status = STATUS_SUCCESS;
    } else if ((code == IOCTL_STATUS || code == IOCTL_STOP) && len == CONFIG_SIZE
        && State.active && State.file == stack->FileObject && State.process == PsGetCurrentProcess()
        && read32(bytes) == State.compartment && read16(bytes + 4) == State.port
        && zero(bytes + 6, 2) && equal(bytes + 8, State.token, 32)) {
        // The same protected file, process, exact compartment, listener and
        // session token must agree. STATUS does not disclose the token.
        // STOP retires admission before userspace cancels its relay tasks.
        if (code == IOCTL_STOP) {
            deactivate_locked();
            waitForClassify = TRUE;
        }
        status = STATUS_SUCCESS;
    } else if (code == IOCTL_ENDPOINT && len == ENDPOINT_SIZE && State.active
        && State.file == stack->FileObject && State.process == PsGetCurrentProcess()
        && read64(bytes) != 0 && (bytes[9] == IPPROTO_TCP || bytes[9] == IPPROTO_UDP) && read16(bytes + 10) != 0
        && valid_ip(bytes[8], bytes + 12, FALSE)) {
        UINT64 now = KeQueryInterruptTime();
        LONG slot = -1;
        BOOLEAN duplicate = FALSE;
        for (ULONG i = 0; i < MAX_ENDPOINTS; ++i) {
            ENDPOINT_PERMIT *p = &State.permits[i];
            if (p->expires <= now) RtlZeroMemory(p, sizeof(*p));
            if (p->endpoint == read64(bytes)) duplicate = TRUE;
            if (slot < 0 && p->endpoint == 0) slot = (LONG)i;
        }
        if (!duplicate && slot >= 0) {
            ENDPOINT_PERMIT *p = &State.permits[slot];
            p->endpoint = read64(bytes);
            p->expires = now + 10ull * 10000000ull;
            p->family = bytes[8];
            p->protocol = bytes[9];
            p->port = read16(bytes + 10);
            RtlCopyMemory(p->address, bytes + 12, 16);
            status = STATUS_SUCCESS;
        } else status = STATUS_INSUFFICIENT_RESOURCES;
    }
    KeReleaseSpinLock(&StateLock, irql);
    // STOP is the only explicit drain operation for this one-shot driver
    // session. Never wait under the spin lock or at classify IRQL.
    // Once acknowledged, no in-flight callback can publish a new permit.
    if (waitForClassify) {
        ExWaitForRundownProtectionRelease(&ClassifyRundown);
        if (ReplyInitialized) TheiaReplyRetire(&ReplyEngine);
    }
    if (((code == IOCTL_CONFIG || code == IOCTL_STATUS || code == IOCTL_STOP) && len == CONFIG_SIZE)
        || (code == IOCTL_ENDPOINT && len == ENDPOINT_SIZE))
        RtlSecureZeroMemory(bytes, len);
    return finish_irp(irp, status);
}

static BOOLEAN unpack(const SOCKADDR_STORAGE *storage, UCHAR family, UCHAR ip[16], USHORT *port) {
    RtlZeroMemory(ip, 16);
    if (family == 4 && storage->ss_family == AF_INET) {
        const SOCKADDR_IN *a = (const SOCKADDR_IN *)storage;
        RtlCopyMemory(ip, &a->sin_addr, 4);
        *port = RtlUshortByteSwap(a->sin_port);
        return TRUE;
    }
    if (family == 6 && storage->ss_family == AF_INET6) {
        const SOCKADDR_IN6 *a = (const SOCKADDR_IN6 *)storage;
        if (a->sin6_scope_id != 0) return FALSE;
        RtlCopyMemory(ip, &a->sin6_addr, 16);
        *port = RtlUshortByteSwap(a->sin6_port);
        return TRUE;
    }
    return FALSE;
}

static VOID NTAPI classify(
    const FWPS_INCOMING_VALUES0 *values,
    const FWPS_INCOMING_METADATA_VALUES0 *meta,
    VOID *layerData,
    const VOID *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0 *out
) {
    UCHAR family, protocol, token[32], src[16], dst[16];
    ULONG compartment, pid;
    USHORT listenPort, srcPort, dstPort;
    UINT64 classifyHandle;
    KIRQL irql;
    FWPS_CONNECT_REQUEST0 *request = NULL;
    BOOLEAN permitted = FALSE, active;
    UCHAR *context = NULL;
    PVOID previousContext = NULL;
    FWPS_CONNECTION_REDIRECT_STATE redirectState = FWPS_CONNECTION_NOT_REDIRECTED;
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    out->actionType = FWP_ACTION_BLOCK;
    if (!ExAcquireRundownProtection(&ClassifyRundown)) {
        out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }
    if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
        family = 4;
        protocol = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
        compartment = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_COMPARTMENT_ID].value.uint32;
    } else if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) {
        family = 6;
        protocol = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL].value.uint8;
        compartment = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_COMPARTMENT_ID].value.uint32;
    } else goto done;
    if ((protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) || classifyContext == NULL
        || !(meta->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) goto done;

    KeAcquireSpinLock(&StateLock, &irql);
    active = State.active && State.compartment == compartment;
    pid = State.pid;
    listenPort = State.port;
    RtlCopyMemory(token, State.token, 32);
    KeReleaseSpinLock(&StateLock, irql);
    if (!active) goto wipe;

    if ((meta->currentMetadataValues & FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE) && meta->redirectRecords != NULL)
        redirectState = FwpsQueryConnectionRedirectState0(meta->redirectRecords, Redirect, &previousContext);
    if (redirectState != FWPS_CONNECTION_NOT_REDIRECTED) {
        // Already redirected by another driver or previously by us: refuse.
        // Our own immediate reclassification may continue only at the
        // exact local listener, with the original protected context.
        if (redirectState != FWPS_CONNECTION_REDIRECTED_BY_SELF || previousContext == NULL) goto wipe;
    }
    if (!NT_SUCCESS(FwpsAcquireClassifyHandle0((VOID *)classifyContext, 0, &classifyHandle))) goto wipe;
    if (!NT_SUCCESS(FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0, (PVOID *)&request, out))) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        goto wipe;
    }

    if (!unpack(&request->localAddressAndPort, family, src, &srcPort)
        || !unpack(&request->remoteAddressAndPort, family, dst, &dstPort)
        || dstPort == 0) goto apply;

    if (redirectState == FWPS_CONNECTION_REDIRECTED_BY_SELF) {
        if (protocol == IPPROTO_TCP && dstPort == listenPort && equal(src, dst, 16) && request->localRedirectTargetPID == pid
            && request->localRedirectHandle == Redirect) permitted = TRUE;
        goto apply;
    }

    // Only the privileged service process may use a one-shot, exact
    // kernel transport endpoint permit. A PID match alone never permits.
    if (meta->processId == pid) {
        if (!(meta->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)) goto apply;
        KeAcquireSpinLock(&StateLock, &irql);
        if (State.active && State.pid == pid && State.compartment == compartment) {
            UINT64 now = KeQueryInterruptTime();
            for (ULONG i = 0; i < MAX_ENDPOINTS; ++i) {
                ENDPOINT_PERMIT *p = &State.permits[i];
                if (p->endpoint == meta->transportEndpointHandle && p->expires > now
                    && p->family == family && p->protocol == protocol && p->port == dstPort && equal(p->address, dst, 16)) {
                    permitted = protocol!=IPPROTO_UDP || TheiaUdpAdmit(meta->transportEndpointHandle,family,dst,dstPort,TRUE);
                    RtlZeroMemory(p, sizeof(*p));
                    break;
                }
            }
        }
        KeReleaseSpinLock(&StateLock, irql);
        goto apply;
    }

    // UDP stays on its original socket/peer. The separate mandatory
    // DATAGRAM_DATA layer absorbs payload and owns reverse injection.
    if (protocol==IPPROTO_UDP) {
        if ((meta->currentMetadataValues&FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)
            && request->localRedirectHandle==NULL && valid_ip(family,dst,FALSE))
            permitted=TheiaUdpAdmit(meta->transportEndpointHandle,family,dst,dstPort,FALSE);
        goto apply;
    }
    if (protocol != IPPROTO_TCP) goto apply;

    // v1 supports only an already assigned concrete source tuple, to
    // preserve and verify the accepted peer exactly. No guessed identity.
    if (srcPort == 0 || !valid_ip(family, src, TRUE) || !valid_ip(family, dst, FALSE)
        || equal(src, dst, 16) || dstPort == listenPort || request->localRedirectHandle != NULL) goto apply;
    context = (UCHAR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, CONTEXT_SIZE, THEIA_TAG);
    if (context == NULL) goto apply;
    RtlZeroMemory(context, CONTEXT_SIZE);
    RtlCopyMemory(context, "THWFP001", 8);
    RtlCopyMemory(context + 8, token, 32);
    context[40] = family;
    context[41] = IPPROTO_TCP;
    write32(context + 44, compartment);
    context[48] = (UCHAR)(srcPort >> 8); context[49] = (UCHAR)srcPort;
    context[50] = (UCHAR)(dstPort >> 8); context[51] = (UCHAR)dstPort;
    RtlCopyMemory(context + 52, src, 16);
    RtlCopyMemory(context + 68, dst, 16);

    KeAcquireSpinLock(&StateLock, &irql);
    active = State.active && State.pid == pid && State.compartment == compartment && equal(token, State.token, 32);
    KeReleaseSpinLock(&StateLock, irql);
    if (!active) {
        RtlSecureZeroMemory(context, CONTEXT_SIZE);
        ExFreePoolWithTag(context, THEIA_TAG);
        goto apply;
    }
    // Preserve the local zone by redirecting to the already assigned
    // local interface address; the private userspace context verifies it.
    if (family == 4) {
        SOCKADDR_IN *remote = (SOCKADDR_IN *)&request->remoteAddressAndPort;
        RtlCopyMemory(&remote->sin_addr, src, 4);
        remote->sin_port = RtlUshortByteSwap(listenPort);
    } else {
        SOCKADDR_IN6 *remote = (SOCKADDR_IN6 *)&request->remoteAddressAndPort;
        RtlCopyMemory(&remote->sin6_addr, src, 16);
        remote->sin6_port = RtlUshortByteSwap(listenPort);
    }
    request->localRedirectTargetPID = pid;
    request->localRedirectHandle = Redirect;
    request->localRedirectContext = context;
    request->localRedirectContextSize = CONTEXT_SIZE;
    // Windows 8+ WFP owns context memory after application.
    permitted = TRUE;

apply:
    out->actionType = permitted ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    FwpsApplyModifiedLayerData0(classifyHandle, request, FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
    if (permitted) out->rights |= FWPS_RIGHT_ACTION_WRITE;
    FwpsReleaseClassifyHandle0(classifyHandle);
wipe:
    RtlSecureZeroMemory(token, sizeof(token));
done:
    if (!permitted) {
        out->actionType = FWP_ACTION_BLOCK;
        out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
        out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    ExReleaseRundownProtection(&ClassifyRundown);
}

static NTSTATUS NTAPI notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *key, FWPS_FILTER1 *filter) {
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}
static NTSTATUS register_callout(const GUID *key, UINT32 *id) {
    FWPS_CALLOUT1 callout;
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *key;
    callout.classifyFn = classify;
    callout.notifyFn = notify;
    return FwpsCalloutRegister1(Device, &callout, id);
}

static VOID unload(PDRIVER_OBJECT driver) {
    KIRQL irql;
    UNREFERENCED_PARAMETER(driver);
    KeAcquireSpinLock(&StateLock, &irql);
    deactivate_locked();
    KeReleaseSpinLock(&StateLock, irql);
    TheiaUdpUnregister();
    if (Id6 != 0) FwpsCalloutUnregisterById0(Id6);
    if (Id4 != 0) FwpsCalloutUnregisterById0(Id4);
    if (ProcessNotifyRegistered) PsSetCreateProcessNotifyRoutineEx(process_notify, TRUE);
    if (ReplyInitialized) {
        TheiaReplyDestroy(&ReplyEngine);
        ReplyInitialized = FALSE;
    }
    if (Redirect != NULL) FwpsRedirectHandleDestroy0(Redirect);
    if (State.process != NULL) ObDereferenceObject(State.process);
    IoDeleteSymbolicLink(&LinkName);
    if (Device != NULL) IoDeleteDevice(Device);
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registry);
    KeInitializeSpinLock(&StateLock);
    ExInitializeRundownProtection(&ClassifyRundown);
    TheiaUdpInitialize(&ReplyEngine);
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) driver->MajorFunction[i] = unsupported;
    driver->MajorFunction[IRP_MJ_CREATE] = open_close;
    driver->MajorFunction[IRP_MJ_CLOSE] = open_close;
    driver->MajorFunction[IRP_MJ_CLEANUP] = cleanup;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = control;
    driver->DriverUnload = unload;

    status = IoCreateDeviceSecure(driver, 0, &DeviceName, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, TRUE, &SystemOnly, &DeviceClass, &Device);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&LinkName, &DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(Device);
        Device = NULL;
        return status;
    }
    status = PsSetCreateProcessNotifyRoutineEx(process_notify, FALSE);
    if (!NT_SUCCESS(status)) goto fail;
    ProcessNotifyRegistered = TRUE;
    status = FwpsRedirectHandleCreate0(&Provider, 0, &Redirect);
    if (!NT_SUCCESS(status)) goto fail;
    // Prepare the transport injection resource without enabling a UDP
    // capture/IOCTL surface. A missing resource cannot grant UDP egress.
    ReplyInitialized = NT_SUCCESS(TheiaReplyInitialize(&ReplyEngine));
    if (!ReplyInitialized) { status=STATUS_DEVICE_NOT_READY;goto fail; }
    status=TheiaUdpRegister(Device);
    if (!NT_SUCCESS(status)) goto fail;
    status = register_callout(&CalloutV4, &Id4);
    if (!NT_SUCCESS(status)) goto fail;
    status = register_callout(&CalloutV6, &Id6);
    if (!NT_SUCCESS(status)) goto fail;
    Device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
fail:
    unload(driver);
    return status;
}
