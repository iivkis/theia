#pragma once
/* Private kernel-only reverse transport primitive. No IOCTL, wire struct
 * or userspace address authorizes this API. A future DATAGRAM_DATA owner
 * must supply a live kernel flow lease and keep it valid through completion.
 * Locally generated inbound NBLs can bypass IPsec verification; do not
 * enable this path outside an independently approved isolated compartment. */
typedef struct _THEIA_REPLY_ENGINE {
    HANDLE injection;
    NDIS_HANDLE pool;
    EX_RUNDOWN_REF rundown;
    KEVENT retiredEvent;
    volatile LONG retired;
    volatile LONG inFlight;
} THEIA_REPLY_ENGINE;

typedef struct _THEIA_REPLY_FLOW {
    ADDRESS_FAMILY family;
    COMPARTMENT_ID compartment;
    IF_INDEX interfaceIndex;
    IF_INDEX subInterfaceIndex;
    UINT64 endpoint;
    UINT64 generation;
    UCHAR localAddress[16];
    UCHAR remoteAddress[16];
    USHORT localPort;   /* host byte order */
    USHORT remotePort;  /* host byte order */
} THEIA_REPLY_FLOW;

NTSTATUS TheiaReplyInitialize(THEIA_REPLY_ENGINE *engine);
VOID TheiaReplyRetire(THEIA_REPLY_ENGINE *engine);
VOID TheiaReplyDestroy(THEIA_REPLY_ENGINE *engine);
NTSTATUS TheiaReplyInject(THEIA_REPLY_ENGINE *engine, const THEIA_REPLY_FLOW *flow,
    const UCHAR *payload, ULONG length);
