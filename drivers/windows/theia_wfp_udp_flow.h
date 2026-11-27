#pragma once
/* Isolated DATAGRAM_DATA adapter. All addresses are kernel-derived.
 * User mode receives an opaque generation; it cannot nominate a reply tuple. */
#define THEIA_UDP_HEADER 56u
#define THEIA_UDP_MAX 65507u
VOID TheiaUdpInitialize(THEIA_REPLY_ENGINE *reply);
NTSTATUS TheiaUdpRegister(PDEVICE_OBJECT device);
VOID TheiaUdpUnregister(VOID);
BOOLEAN TheiaUdpStart(ULONG scope, BOOLEAN applicationUdp);
VOID TheiaUdpStop(VOID);
BOOLEAN TheiaUdpAdmit(UINT64 endpoint, UCHAR family, const UCHAR *remote, USHORT port, BOOLEAN carrier);
NTSTATUS TheiaUdpRead(UCHAR *buffer, ULONG capacity, ULONG_PTR *written);
NTSTATUS TheiaUdpReply(UINT64 generation, const UCHAR *data, ULONG length);
NTSTATUS TheiaUdpClose(UINT64 generation);
