/*
 * Isolated WFP UDP datagram adapter. No user-provided address, endpoint,
 * interface, or compartment can authorize injection. ALE admits an exact
 * kernel endpoint/target; DATAGRAM_DATA binds the concrete source and flow.
 * The application socket retains its original peer (no UDP ALE rewrite).
 * This is not approved for IPsec-protected traffic or the default compartment.
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
#include "theia_wfp_udp_flow.h"

#define UDP_TAG 'fUhT'
#define FLOW_LIMIT 64u
#define PENDING_LIMIT 128u
#define PACKET_LIMIT 128u
#define ADMIT_TTL (10ull * 10000000ull)
static const GUID Udp4 = {0x172b0ec2,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID Udp6 = {0x172b0ec3,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID Close4 = {0x172b0ec6,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID Close6 = {0x172b0ec7,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
typedef struct _ADMISSION {
    UINT64 endpoint, expires;
    UCHAR family, address[16];
    USHORT port;
    BOOLEAN carrier;
} ADMISSION;
typedef struct _FLOW {
    THEIA_REPLY_FLOW tuple;
    UINT64 handle;
    UINT16 layer;
    UINT32 callout;
    BOOLEAN carrier, closed, published;
} FLOW;
typedef struct _PACKET {
    LIST_ENTRY link;
    UINT64 generation;
    ULONG length;
    UCHAR bytes[ANYSIZE_ARRAY];
} PACKET;
static KSPIN_LOCK Lock;
static EX_RUNDOWN_REF Classification;
static BOOLEAN Active, ApplicationUdp;
static ULONG Scope, Queued, Reserved;
static UINT64 NextGeneration;
static FLOW Flows[FLOW_LIMIT];
static ADMISSION Pending[PENDING_LIMIT];
static LIST_ENTRY Queue;
static UINT32 Id4, Id6, CloseId4, CloseId6;
static THEIA_REPLY_ENGINE *Reply;
static volatile LONG Installed4, Installed6, Closure4, Closure6;

static BOOLEAN same(const UCHAR *a, const UCHAR *b, SIZE_T n) {
    return RtlCompareMemory(a,b,n)==n;
}
static BOOLEAN zero(const UCHAR *p, SIZE_T n) {
    UCHAR v=0;
    for (SIZE_T i=0;i<n;++i) v|=p[i];
    return v==0;
}
static BOOLEAN valid_ip(ADDRESS_FAMILY family,const UCHAR *p) {
    if (family==AF_INET) return !zero(p,4)&&zero(p+4,12)&&p[0]!=127&&p[0]<224;
    return family==AF_INET6&&!zero(p,16)&&p[0]!=0xff
        && !(p[0]==0xfe&&(p[1]&0xc0)==0x80)
        && !(zero(p,10)&&p[10]==0xff&&p[11]==0xff)
        && !(zero(p,15)&&p[15]==1);
}
static VOID put16(UCHAR *p,USHORT n) { p[0]=(UCHAR)(n>>8);p[1]=(UCHAR)n; }
static VOID put32(UCHAR *p,UINT32 n) { put16(p,(USHORT)(n>>16));put16(p+2,(USHORT)n); }
static VOID put64(UCHAR *p,UINT64 n) { put32(p,(UINT32)(n>>32));put32(p+4,(UINT32)n); }
static USHORT get16(const UCHAR *p) { return (USHORT)(((USHORT)p[0]<<8)|p[1]); }
static FLOW *find(UINT64 generation) {
    if (!generation) return NULL;
    for (ULONG i=0;i<FLOW_LIMIT;++i) if (Flows[i].tuple.generation==generation) return &Flows[i];
    return NULL;
}
static BOOLEAN filters_ready(VOID) {
    return InterlockedCompareExchange(&Installed4,0,0)==1
        && InterlockedCompareExchange(&Installed6,0,0)==1
        && InterlockedCompareExchange(&Closure4,0,0)==1
        && InterlockedCompareExchange(&Closure6,0,0)==1;
}
static BOOLEAN ready_locked(VOID) {
    return Active && filters_ready();
}
static BOOLEAN same_tuple(const THEIA_REPLY_FLOW *a,const THEIA_REPLY_FLOW *b) {
    return a->family==b->family && a->compartment==b->compartment
        && a->endpoint==b->endpoint && a->localPort==b->localPort && a->remotePort==b->remotePort
        && a->interfaceIndex==b->interfaceIndex && a->subInterfaceIndex==b->subInterfaceIndex
        && same(a->localAddress,b->localAddress,16)&&same(a->remoteAddress,b->remoteAddress,16);
}
static BOOLEAN exact_live(const FLOW *f,const THEIA_REPLY_FLOW *tuple,UINT64 handle) {
    return f && !f->closed && f->published && f->handle==handle && same_tuple(&f->tuple,tuple);
}

VOID TheiaUdpInitialize(THEIA_REPLY_ENGINE *reply) {
    KeInitializeSpinLock(&Lock);
    ExInitializeRundownProtection(&Classification);
    InitializeListHead(&Queue);
    Reply=reply;
}
BOOLEAN TheiaUdpStart(ULONG scope,BOOLEAN applicationUdp) {
    KIRQL irql;
    BOOLEAN ok;
    KeAcquireSpinLock(&Lock,&irql);
    ok=!Active&&scope>1&&filters_ready();
    if (ok) { Scope=scope; ApplicationUdp=applicationUdp; Active=TRUE; }
    KeReleaseSpinLock(&Lock,irql);
    return ok;
}
BOOLEAN TheiaUdpReady(VOID) {
    KIRQL irql;
    BOOLEAN ready;
    KeAcquireSpinLock(&Lock,&irql);
    ready=ready_locked();
    KeReleaseSpinLock(&Lock,irql);
    return ready;
}
VOID TheiaUdpStop(VOID) {
    KIRQL irql;
    KeAcquireSpinLock(&Lock,&irql);
    Active=FALSE;
    ApplicationUdp=FALSE;
    RtlSecureZeroMemory(Pending,sizeof(Pending));
    for (ULONG i=0;i<FLOW_LIMIT;++i) if (Flows[i].tuple.generation) Flows[i].closed=TRUE;
    KeReleaseSpinLock(&Lock,irql);
}
VOID TheiaUdpDrain(VOID) {
    // Deactivation is immediate; potentially megabytes of payload are
    // wiped outside the spin lock and outside the ALE state lock.
    for (;;) {
        KIRQL irql;
        PACKET *p=NULL;
        KeAcquireSpinLock(&Lock,&irql);
        if (!Active&&!IsListEmpty(&Queue)) {
            p=CONTAINING_RECORD(RemoveHeadList(&Queue),PACKET,link);
            --Queued;
        }
        KeReleaseSpinLock(&Lock,irql);
        if (!p) break;
        RtlSecureZeroMemory(p->bytes,p->length);
        ExFreePoolWithTag(p,UDP_TAG);
    }
}
BOOLEAN TheiaUdpAdmit(UINT64 endpoint,UCHAR family,const UCHAR *remote,USHORT port,BOOLEAN carrier) {
    KIRQL irql;
    BOOLEAN ok=FALSE;
    ADMISSION *slot=NULL;
    UINT64 now=KeQueryInterruptTime();
    if (!endpoint||!port||!valid_ip(family==4?AF_INET:family==6?AF_INET6:AF_UNSPEC,remote)) return FALSE;
    KeAcquireSpinLock(&Lock,&irql);
    if (!ready_locked()||(!carrier&&!ApplicationUdp)) goto out;
    for (ULONG i=0;i<PENDING_LIMIT;++i) {
        ADMISSION *a=&Pending[i];
        if (a->expires<=now) RtlZeroMemory(a,sizeof(*a));
        if (a->endpoint==endpoint) goto out;
        if (!a->endpoint&&!slot) slot=a;
    }
    if (slot) {
        slot->endpoint=endpoint;slot->expires=now+ADMIT_TTL;
        slot->family=family;slot->port=port;slot->carrier=carrier;
        RtlCopyMemory(slot->address,remote,16);
        ok=TRUE;
    }
out:
    KeReleaseSpinLock(&Lock,irql);
    return ok;
}

static VOID NTAPI flow_delete(UINT16 layer,UINT32 callout,UINT64 generation) {
    KIRQL irql;
    KeAcquireSpinLock(&Lock,&irql);
    FLOW *f=find(generation);
    if (f&&f->layer==layer&&f->callout==callout) RtlZeroMemory(f,sizeof(*f));
    KeReleaseSpinLock(&Lock,irql);
}
/* Socket closure revokes even a permit that has not reached the first
 * DATAGRAM_DATA packet. Flow deletion separately revokes an attached flow. */
static VOID NTAPI classify_close(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    VOID *data,const VOID *context,const FWPS_FILTER1 *filter,UINT64 flowContext,FWPS_CLASSIFY_OUT0 *out) {
    ULONG scope;
    UCHAR protocol;
    KIRQL irql;
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    if (out->rights&FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
    if (!ExAcquireRundownProtection(&Classification)) return;
    if (v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4) {
        scope=v->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_COMPARTMENT_ID].value.uint32;
        protocol=v->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_PROTOCOL].value.uint8;
    } else if (v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6) {
        scope=v->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_COMPARTMENT_ID].value.uint32;
        protocol=v->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_PROTOCOL].value.uint8;
    } else goto done;
    if (protocol!=IPPROTO_UDP || !(m->currentMetadataValues&FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)
        || !m->transportEndpointHandle) goto done;
    KeAcquireSpinLock(&Lock,&irql);
    if (scope==Scope) {
        for (ULONG i=0;i<PENDING_LIMIT;++i)
            if (Pending[i].endpoint==m->transportEndpointHandle) RtlZeroMemory(&Pending[i],sizeof(Pending[i]));
        for (ULONG i=0;i<FLOW_LIMIT;++i)
            if (Flows[i].tuple.endpoint==m->transportEndpointHandle) Flows[i].closed=TRUE;
    }
    KeReleaseSpinLock(&Lock,irql);
done:
    ExReleaseRundownProtection(&Classification);
}
static BOOLEAN tuple_from(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    THEIA_REPLY_FLOW *t,UINT32 *direction,UINT32 *flags) {
    if (!(m->currentMetadataValues&FWPS_METADATA_FIELD_FLOW_HANDLE)
        || !(m->currentMetadataValues&FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)
        || !m->flowHandle||!m->transportEndpointHandle) return FALSE;
    RtlZeroMemory(t,sizeof(*t));
    t->endpoint=m->transportEndpointHandle;
#define FIELD(f) v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_##f].value
#define FIELD6(f) v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_##f].value
    if (v->layerId==FWPS_LAYER_DATAGRAM_DATA_V4) {
        if (FIELD(IP_PROTOCOL).uint8!=IPPROTO_UDP) return FALSE;
        t->family=AF_INET;
        put32(t->localAddress,FIELD(IP_LOCAL_ADDRESS).uint32);
        put32(t->remoteAddress,FIELD(IP_REMOTE_ADDRESS).uint32);
        t->localPort=FIELD(IP_LOCAL_PORT).uint16;t->remotePort=FIELD(IP_REMOTE_PORT).uint16;
        t->compartment=FIELD(COMPARTMENT_ID).uint32;
        t->interfaceIndex=FIELD(INTERFACE_INDEX).uint32;t->subInterfaceIndex=FIELD(SUB_INTERFACE_INDEX).uint32;
        *direction=FIELD(DIRECTION).uint32;*flags=FIELD(FLAGS).uint32;
    } else if (v->layerId==FWPS_LAYER_DATAGRAM_DATA_V6) {
        if (FIELD6(IP_PROTOCOL).uint8!=IPPROTO_UDP || !FIELD6(IP_LOCAL_ADDRESS).byteArray16 || !FIELD6(IP_REMOTE_ADDRESS).byteArray16) return FALSE;
        t->family=AF_INET6;
        RtlCopyMemory(t->localAddress,FIELD6(IP_LOCAL_ADDRESS).byteArray16->byteArray16,16);
        RtlCopyMemory(t->remoteAddress,FIELD6(IP_REMOTE_ADDRESS).byteArray16->byteArray16,16);
        t->localPort=FIELD6(IP_LOCAL_PORT).uint16;t->remotePort=FIELD6(IP_REMOTE_PORT).uint16;
        t->compartment=FIELD6(COMPARTMENT_ID).uint32;
        t->interfaceIndex=FIELD6(INTERFACE_INDEX).uint32;t->subInterfaceIndex=FIELD6(SUB_INTERFACE_INDEX).uint32;
        *direction=FIELD6(DIRECTION).uint32;*flags=FIELD6(FLAGS).uint32;
    } else return FALSE;
#undef FIELD
#undef FIELD6
    return t->compartment>1&&t->interfaceIndex&&t->localPort&&t->remotePort
        && valid_ip(t->family,t->localAddress)&&valid_ip(t->family,t->remoteAddress)
        && !same(t->localAddress,t->remoteAddress,16);
}

/* Associate an integer generation, never a pointer into a recyclable slot.
 * Flow deletion invalidates late replies even when the tuple is reused. */
static UINT64 attach(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    THEIA_REPLY_FLOW *t) {
    KIRQL irql;
    FLOW *slot=NULL;
    ADMISSION *permit=NULL;
    UINT64 generation=0,now=KeQueryInterruptTime();
    UINT32 id=v->layerId==FWPS_LAYER_DATAGRAM_DATA_V4?Id4:Id6;
    KeAcquireSpinLock(&Lock,&irql);
    if (!ready_locked()||t->compartment!=Scope||NextGeneration==~(UINT64)0) goto unlock;
    for (ULONG i=0;i<FLOW_LIMIT;++i) {
        if (Flows[i].tuple.generation&&Flows[i].handle==m->flowHandle) goto unlock;
        if (!Flows[i].tuple.generation&&!slot) slot=&Flows[i];
    }
    for (ULONG i=0;i<PENDING_LIMIT;++i) {
        ADMISSION *a=&Pending[i];
        if (a->endpoint==t->endpoint&&a->expires>now
            && a->family==(t->family==AF_INET?4:6)&&a->port==t->remotePort
            && same(a->address,t->remoteAddress,16)) { permit=a;break; }
    }
    if (!slot||!permit||(!permit->carrier&&!ApplicationUdp)) goto unlock;
    generation=++NextGeneration;
    t->generation=generation;
    slot->tuple=*t;slot->handle=m->flowHandle;slot->layer=v->layerId;
    slot->callout=id;slot->carrier=permit->carrier;slot->closed=FALSE;slot->published=FALSE;
    RtlZeroMemory(permit,sizeof(*permit));
unlock:
    KeReleaseSpinLock(&Lock,irql);
    if (!generation) return 0;
    NTSTATUS status=FwpsFlowAssociateContext0(m->flowHandle,v->layerId,id,generation);
    KeAcquireSpinLock(&Lock,&irql);
    slot=find(generation);
    if (!NT_SUCCESS(status)) {
        if (slot) RtlZeroMemory(slot,sizeof(*slot));
        generation=0;
    } else if (!slot||slot->closed||!ready_locked()) {
        generation=0; /* associated context remains for flow_delete */
    } else slot->published=TRUE;
    KeReleaseSpinLock(&Lock,irql);
    return generation;
}

static PACKET *copy_udp(NET_BUFFER_LIST *nbl,const THEIA_REPLY_FLOW *t,UINT64 generation) {
    if (!nbl||NET_BUFFER_LIST_NEXT_NBL(nbl)) return NULL;
    NET_BUFFER *nb=NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb||NET_BUFFER_NEXT_NB(nb)) return NULL;
    ULONG size=NET_BUFFER_DATA_LENGTH(nb);
    if (size<8||size>THEIA_UDP_MAX+8) return NULL;
    PACKET *p=(PACKET *)ExAllocatePool2(POOL_FLAG_NON_PAGED,FIELD_OFFSET(PACKET,bytes)+size,UDP_TAG);
    if (!p) return NULL;
    UCHAR *bytes=(UCHAR *)NdisGetDataBuffer(nb,size,p->bytes,1,0);
    if (!bytes||get16(bytes)!=t->localPort||get16(bytes+2)!=t->remotePort||get16(bytes+4)!=size) {
        ExFreePoolWithTag(p,UDP_TAG);return NULL;
    }
    if (bytes!=p->bytes) RtlCopyMemory(p->bytes,bytes,size);
    RtlMoveMemory(p->bytes,p->bytes+8,size-8);
    RtlSecureZeroMemory(p->bytes+size-8,8);
    p->length=size-8;p->generation=generation;
    return p;
}

static VOID NTAPI classify_udp(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    VOID *data,const VOID *context,const FWPS_FILTER1 *filter,UINT64 generation,FWPS_CLASSIFY_OUT0 *out) {
    THEIA_REPLY_FLOW tuple;
    UINT32 direction,flags;
    KIRQL irql;
    BOOLEAN permit=FALSE,carrier=FALSE,valid=FALSE;
    PACKET *packet=NULL;
    HANDLE injectionContext=NULL;
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(filter);
    if (!(out->rights&FWPS_RIGHT_ACTION_WRITE)) return;
    out->actionType=FWP_ACTION_BLOCK;
    out->rights&=~FWPS_RIGHT_ACTION_WRITE;
    if (!ExAcquireRundownProtection(&Classification)) return;
    if (!tuple_from(v,m,&tuple,&direction,&flags)||!data) goto done;
    // Do not process raw endpoints, loopback, IPsec, or packets with
    // uncertain transport semantics. Full IPsec policy acceptance is
    // deliberately outside this isolated, explicitly non-IPsec lab.
    if (flags&(FWP_CONDITION_FLAG_IS_IPSEC_SECURED|FWP_CONDITION_FLAG_IS_LOOPBACK|FWP_CONDITION_FLAG_IS_RAW_ENDPOINT)) goto done;
    if (direction==FWP_DIRECTION_OUTBOUND&&!generation)
        generation=attach(v,m,&tuple);
    if (!generation) goto done;
    KeAcquireSpinLock(&Lock,&irql);
    FLOW *flow=find(generation);
    valid=ready_locked()&&tuple.compartment==Scope&&exact_live(flow,&tuple,m->flowHandle);
    if (valid) carrier=flow->carrier;
    KeReleaseSpinLock(&Lock,irql);
    if (!valid) goto done;
    if (carrier) { permit=TRUE;goto done; }
    if (direction==FWP_DIRECTION_INBOUND) {
        // Injection context is assigned only by our private receive handle.
        // Match the exact live flow again on reentry, not merely the tuple.
        if (FwpsQueryPacketInjectionState0(Reply->injection,(NET_BUFFER_LIST *)data,&injectionContext)
            !=FWPS_PACKET_INJECTED_BY_SELF || (UINT64)(ULONG_PTR)injectionContext!=generation) goto done;
        KeAcquireSpinLock(&Lock,&irql);
        permit=ready_locked()&&exact_live(find(generation),&tuple,m->flowHandle);
        KeReleaseSpinLock(&Lock,irql);
        goto done;
    }
    if (direction!=FWP_DIRECTION_OUTBOUND) goto done;
    // Reserve capacity before allocating nonpaged payload storage.
    KeAcquireSpinLock(&Lock,&irql);
    valid=ready_locked()&&exact_live(find(generation),&tuple,m->flowHandle)&&Queued+Reserved<PACKET_LIMIT;
    if (valid) ++Reserved;
    KeReleaseSpinLock(&Lock,irql);
    if (!valid) goto done;
    packet=copy_udp((NET_BUFFER_LIST *)data,&tuple,generation);
    KeAcquireSpinLock(&Lock,&irql);
    --Reserved;
    if (packet&&ready_locked()&&exact_live(find(generation),&tuple,m->flowHandle)&&Queued<PACKET_LIMIT) {
        InsertTailList(&Queue,&packet->link);++Queued;packet=NULL;
        out->flags|=FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    }
    KeReleaseSpinLock(&Lock,irql);
done:
    if (packet) { RtlSecureZeroMemory(packet->bytes,packet->length);ExFreePoolWithTag(packet,UDP_TAG); }
    if (permit) {
        out->actionType=FWP_ACTION_PERMIT;
        if (!(filter->flags&FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)) out->rights|=FWPS_RIGHT_ACTION_WRITE;
    }
    ExReleaseRundownProtection(&Classification);
}

NTSTATUS TheiaUdpRead(UCHAR *buffer,ULONG capacity,ULONG_PTR *written) {
    KIRQL irql;
    NTSTATUS status=STATUS_NO_MORE_ENTRIES;
    *written=0;
    if (capacity<THEIA_UDP_HEADER+THEIA_UDP_MAX) return STATUS_BUFFER_TOO_SMALL;
    KeAcquireSpinLock(&Lock,&irql);
    if (!ready_locked()||!ApplicationUdp) { status=STATUS_ACCESS_DENIED;goto out; }
    while (!IsListEmpty(&Queue)) {
        PACKET *p=CONTAINING_RECORD(RemoveHeadList(&Queue),PACKET,link);--Queued;
        FLOW *f=find(p->generation);
        if (f&&!f->carrier&&!f->closed&&f->published) {
            RtlZeroMemory(buffer,THEIA_UDP_HEADER);
            put64(buffer,p->generation);
            buffer[8]=(UCHAR)(f->tuple.family==AF_INET?4:6);
            buffer[9]=17;
            put32(buffer+12,f->tuple.compartment);
            put16(buffer+16,f->tuple.localPort);put16(buffer+18,f->tuple.remotePort);
            RtlCopyMemory(buffer+20,f->tuple.localAddress,16);
            RtlCopyMemory(buffer+36,f->tuple.remoteAddress,16);
            put32(buffer+52,p->length);
            RtlCopyMemory(buffer+THEIA_UDP_HEADER,p->bytes,p->length);
            *written=THEIA_UDP_HEADER+p->length;status=STATUS_SUCCESS;
        }
        RtlSecureZeroMemory(p->bytes,p->length);ExFreePoolWithTag(p,UDP_TAG);
        if (status==STATUS_SUCCESS) break;
    }
out:
    KeReleaseSpinLock(&Lock,irql);
    return status==STATUS_NO_MORE_ENTRIES?STATUS_SUCCESS:status;
}
NTSTATUS TheiaUdpReply(UINT64 generation,const UCHAR *data,ULONG length) {
    THEIA_REPLY_FLOW tuple;
    KIRQL irql;
    BOOLEAN valid=FALSE;
    if (length>THEIA_UDP_MAX) return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(&Lock,&irql);
    FLOW *f=find(generation);
    if (ready_locked()&&ApplicationUdp&&f&&!f->closed&&!f->carrier&&f->published) { tuple=f->tuple;valid=TRUE; }
    KeReleaseSpinLock(&Lock,irql);
    // Receive classification checks this generation again after injection.
    return valid?TheiaReplyInject(Reply,&tuple,data,length):STATUS_ACCESS_DENIED;
}
NTSTATUS TheiaUdpClose(UINT64 generation) {
    KIRQL irql;
    NTSTATUS status=STATUS_ACCESS_DENIED;
    KeAcquireSpinLock(&Lock,&irql);
    FLOW *f=find(generation);
    if (f&&!f->carrier) { f->closed=TRUE;status=STATUS_SUCCESS; }
    KeReleaseSpinLock(&Lock,irql);
    return status;
}
// ADD_FILTER reports the filter key, not the callout key. DELETE
// reports NULL. Separate callbacks retain the address family without
// dereferencing a missing GUID. Filters must be installed after load;
// old persistent filters cannot silently authorize a new session.
static const GUID Filter4={0x172b0ec4,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID Filter6={0x172b0ec5,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID CloseFilter4={0x172b0ec8,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID CloseFilter6={0x172b0ec9,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static NTSTATUS notify_udp(FWPS_CALLOUT_NOTIFY_TYPE type,const GUID *key,const GUID *expected,volatile LONG *count) {
    if (type==FWPS_CALLOUT_NOTIFY_ADD_FILTER) {
        if (!key||!same((const UCHAR *)key,(const UCHAR *)expected,sizeof(GUID))
            || InterlockedCompareExchange(count,1,0)!=0) return STATUS_ACCESS_DENIED;
    } else if (type==FWPS_CALLOUT_NOTIFY_DELETE_FILTER) {
        InterlockedExchange(count,0);
        TheiaUdpStop();
        TheiaUdpDrain();
    }
    return STATUS_SUCCESS;
}
static NTSTATUS NTAPI notify4(FWPS_CALLOUT_NOTIFY_TYPE type,const GUID *key,FWPS_FILTER1 *filter) {
    UNREFERENCED_PARAMETER(filter);
    return notify_udp(type,key,&Filter4,&Installed4);
}
static NTSTATUS NTAPI notify6(FWPS_CALLOUT_NOTIFY_TYPE type,const GUID *key,FWPS_FILTER1 *filter) {
    UNREFERENCED_PARAMETER(filter);
    return notify_udp(type,key,&Filter6,&Installed6);
}
static NTSTATUS NTAPI notify_close4(FWPS_CALLOUT_NOTIFY_TYPE type,const GUID *key,FWPS_FILTER1 *filter) {
    UNREFERENCED_PARAMETER(filter);
    return notify_udp(type,key,&CloseFilter4,&Closure4);
}
static NTSTATUS NTAPI notify_close6(FWPS_CALLOUT_NOTIFY_TYPE type,const GUID *key,FWPS_FILTER1 *filter) {
    UNREFERENCED_PARAMETER(filter);
    return notify_udp(type,key,&CloseFilter6,&Closure6);
}
static NTSTATUS register_one(PDEVICE_OBJECT dev,const GUID *key,UINT32 *id,FWPS_CALLOUT_NOTIFY_FN1 notify,BOOLEAN closure) {
    FWPS_CALLOUT1 c;
    RtlZeroMemory(&c,sizeof(c));
    c.calloutKey=*key;c.classifyFn=closure?classify_close:classify_udp;c.notifyFn=notify;
    if (!closure) c.flowDeleteFn=flow_delete;
    return FwpsCalloutRegister1(dev,&c,id);
}
NTSTATUS TheiaUdpRegister(PDEVICE_OBJECT dev) {
    NTSTATUS status=register_one(dev,&Udp4,&Id4,notify4,FALSE);
    if (NT_SUCCESS(status)) status=register_one(dev,&Udp6,&Id6,notify6,FALSE);
    if (NT_SUCCESS(status)) status=register_one(dev,&Close4,&CloseId4,notify_close4,TRUE);
    if (NT_SUCCESS(status)) status=register_one(dev,&Close6,&CloseId6,notify_close6,TRUE);
    return status;
}
VOID TheiaUdpUnregister(VOID) {
    TheiaUdpStop();
    ExWaitForRundownProtectionRelease(&Classification);
    TheiaUdpDrain();
    // No new associations after rundown. Remove the exact live contexts.
    for (ULONG i=0;i<FLOW_LIMIT;++i) {
        KIRQL irql;
        FLOW f;
        KeAcquireSpinLock(&Lock,&irql);f=Flows[i];KeReleaseSpinLock(&Lock,irql);
        if (f.tuple.generation) (VOID)FwpsFlowRemoveContext0(f.handle,f.layer,f.callout);
    }
    // A pending deletion is completed by WFP before unregister can succeed.
    LARGE_INTEGER delay;delay.QuadPart=-100000;
    if (CloseId6) while (FwpsCalloutUnregisterById0(CloseId6)==STATUS_DEVICE_BUSY)
        KeDelayExecutionThread(KernelMode,FALSE,&delay);
    if (CloseId4) while (FwpsCalloutUnregisterById0(CloseId4)==STATUS_DEVICE_BUSY)
        KeDelayExecutionThread(KernelMode,FALSE,&delay);
    if (Id6) while (FwpsCalloutUnregisterById0(Id6)==STATUS_DEVICE_BUSY)
        KeDelayExecutionThread(KernelMode,FALSE,&delay);
    if (Id4) while (FwpsCalloutUnregisterById0(Id4)==STATUS_DEVICE_BUSY)
        KeDelayExecutionThread(KernelMode,FALSE,&delay);
}
