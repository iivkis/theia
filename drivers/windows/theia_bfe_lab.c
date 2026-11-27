/* Laboratory-only persistent WFP filter installer. No driver loading,
 * global filter, test-signing, or modification of foreign objects.
 * Run in an isolated non-default compartment after driver provisioning.
 * Recovery verifies the exact owned objects inside a BFE write transaction.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wchar.h>
#include <string.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

static const GUID provider = {0x172b0eba,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID callouts[4] = {
    {0x172b0ebb,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}},
    {0x172b0ebc,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}},
    {0x172b0ec2,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}},
    {0x172b0ec3,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}}
};
static const GUID sublayer = {0x172b0ebf,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}};
static const GUID filters[4] = {
    {0x172b0ec0,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}},
    {0x172b0ec1,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}},
    {0x172b0ec4,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}},
    {0x172b0ec5,0xc223,0x4ab6,{0x8c,0x52,0xa9,0x5e,0x08,0x2d,0x11,0x72}}
};
static const GUID *layers[4] = {&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
    &FWPM_LAYER_DATAGRAM_DATA_V4, &FWPM_LAYER_DATAGRAM_DATA_V6};
static wchar_t name[] = L"Theia isolated WFP lab v1";
static BOOL same(const GUID *a, const GUID *b) {
    return a && b && memcmp(a, b, sizeof(*a)) == 0;
}
static BOOL label(const FWPM_DISPLAY_DATA0 *d) {
    return d->name && wcscmp(d->name, name) == 0;
}
static void marker(UINT8 data[12], UINT32 scope) {
    memcpy(data, "THBFE001", 8);
    data[8] = (UINT8)(scope >> 24);
    data[9] = (UINT8)(scope >> 16);
    data[10] = (UINT8)(scope >> 8);
    data[11] = (UINT8)scope;
}
static BOOL marked(const FWP_BYTE_BLOB *b, const UINT8 expected[12]) {
    return b->size == 12 && b->data && memcmp(b->data, expected, 12) == 0;
}

static DWORD install(HANDLE engine, UINT32 scope, UINT8 data[12]) {
    DWORD err;
    FWP_BYTE_BLOB blob = {12, data};
    FWPM_PROVIDER0 p = {0};
    FWPM_SUBLAYER0 s = {0};
    FWPM_FILTER_CONDITION0 condition[2] = {0};
    p.providerKey = provider;
    p.displayData.name = name;
    p.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    p.providerData = blob;
    err = FwpmProviderAdd0(engine, &p, NULL);
    if (err) return err; /* existing key is NEVER overwritten */
    s.subLayerKey = sublayer;
    s.displayData.name = name;
    s.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    s.providerKey = (GUID *)&provider;
    s.providerData = blob;
    s.weight = 0x8000;
    err = FwpmSubLayerAdd0(engine, &s, NULL);
    if (err) return err;
    condition[0].fieldKey = FWPM_CONDITION_COMPARTMENT_ID;
    condition[0].matchType = FWP_MATCH_EQUAL;
    condition[0].conditionValue.type = FWP_UINT32;
    condition[0].conditionValue.uint32 = scope;
    condition[1].fieldKey=FWPM_CONDITION_IP_PROTOCOL;
    condition[1].matchType=FWP_MATCH_EQUAL;
    condition[1].conditionValue.type=FWP_UINT8;
    condition[1].conditionValue.uint8=17;
    for (unsigned i = 0; i < 4; ++i) {
        FWPM_CALLOUT0 c = {0};
        FWPM_FILTER0 f = {0};
        c.calloutKey = callouts[i];
        c.displayData.name = name;
        c.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
        c.providerKey = (GUID *)&provider;
        c.providerData = blob;
        c.applicableLayer = *layers[i];
        err = FwpmCalloutAdd0(engine, &c, NULL, NULL);
        if (err) return err;
        f.filterKey = filters[i];
        f.displayData.name = name;
        f.flags = FWPM_FILTER_FLAG_PERSISTENT; /* never permit unregistered callout */
        f.providerKey = (GUID *)&provider;
        f.providerData = blob;
        f.layerKey = *layers[i];
        f.subLayerKey = sublayer;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 8;
        f.numFilterConditions = i<2?1:2;
        f.filterCondition = condition;
        f.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        f.action.calloutKey = callouts[i];
        err = FwpmFilterAdd0(engine, &f, NULL, NULL);
        if (err) return err;
    }
    return ERROR_SUCCESS;
}

static DWORD verify(HANDLE e, UINT32 scope, const UINT8 data[12]) {
    FWPM_PROVIDER0 *p = NULL;
    FWPM_SUBLAYER0 *s = NULL;
    DWORD err = FwpmProviderGetByKey0(e, &provider, &p);
    if (err) return err;
    BOOL ok = label(&p->displayData) && p->flags == FWPM_PROVIDER_FLAG_PERSISTENT &&
        !p->serviceName && marked(&p->providerData, data);
    FwpmFreeMemory0((void **)&p);
    if (!ok) return ERROR_INVALID_DATA;
    err = FwpmSubLayerGetByKey0(e, &sublayer, &s);
    if (err) return err;
    ok = label(&s->displayData) && same(s->providerKey, &provider) &&
        s->flags == FWPM_SUBLAYER_FLAG_PERSISTENT && s->weight == 0x8000 && marked(&s->providerData, data);
    FwpmFreeMemory0((void **)&s);
    if (!ok) return ERROR_INVALID_DATA;
    for (unsigned i = 0; i < 4; ++i) {
        FWPM_CALLOUT0 *c = NULL;
        FWPM_FILTER0 *f = NULL;
        err = FwpmCalloutGetByKey0(e, &callouts[i], &c);
        if (err) return err;
        ok = label(&c->displayData) && same(c->providerKey, &provider) &&
            (c->flags & ~FWPM_CALLOUT_FLAG_REGISTERED) == FWPM_CALLOUT_FLAG_PERSISTENT &&
            same(&c->applicableLayer, layers[i]) && marked(&c->providerData, data);
        FwpmFreeMemory0((void **)&c);
        if (!ok) return ERROR_INVALID_DATA;
        err = FwpmFilterGetByKey0(e, &filters[i], &f);
        if (err) return err;
        ok = label(&f->displayData) && same(f->providerKey, &provider) && marked(&f->providerData, data) &&
            f->flags == FWPM_FILTER_FLAG_PERSISTENT && same(&f->layerKey, layers[i]) &&
            same(&f->subLayerKey, &sublayer) && f->weight.type == FWP_UINT8 && f->weight.uint8 == 8 &&
            f->action.type == FWP_ACTION_CALLOUT_TERMINATING && same(&f->action.calloutKey, &callouts[i]) &&
            f->numFilterConditions == (i<2?1:2) && f->filterCondition &&
            same(&f->filterCondition[0].fieldKey, &FWPM_CONDITION_COMPARTMENT_ID) &&
            f->filterCondition[0].matchType == FWP_MATCH_EQUAL &&
            f->filterCondition[0].conditionValue.type == FWP_UINT32 &&
            f->filterCondition[0].conditionValue.uint32 == scope &&
            (i<2 || (same(&f->filterCondition[1].fieldKey,&FWPM_CONDITION_IP_PROTOCOL) &&
                f->filterCondition[1].matchType==FWP_MATCH_EQUAL &&
                f->filterCondition[1].conditionValue.type==FWP_UINT8 &&
                f->filterCondition[1].conditionValue.uint8==17));
        FwpmFreeMemory0((void **)&f);
        if (!ok) return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

static DWORD recover(HANDLE e, UINT32 scope, const UINT8 data[12]) {
    DWORD err = verify(e, scope, data);
    if (err) return err;
    for (unsigned i = 0; i < 4; ++i) {
        err = FwpmFilterDeleteByKey0(e, &filters[i]);
        if (err) return err;
    }
    for (unsigned i = 0; i < 4; ++i) {
        err = FwpmCalloutDeleteByKey0(e, &callouts[i]);
        if (err) return err;
    }
    err = FwpmSubLayerDeleteByKey0(e, &sublayer);
    if (err) return err;
    return FwpmProviderDeleteByKey0(e, &provider);
}

/* Prove absence of every owned key, not just absence of one filter.
 * A foreign collision or partial recovery is a failure, never success. */
static DWORD verify_absent(HANDLE e) {
    FWPM_PROVIDER0 *p = NULL;
    FWPM_SUBLAYER0 *s = NULL;
    DWORD err = FwpmProviderGetByKey0(e, &provider, &p);
    if (!err) { FwpmFreeMemory0((void **)&p); return ERROR_ALREADY_EXISTS; }
    if (err != (DWORD)FWP_E_PROVIDER_NOT_FOUND) return err;
    err = FwpmSubLayerGetByKey0(e, &sublayer, &s);
    if (!err) { FwpmFreeMemory0((void **)&s); return ERROR_ALREADY_EXISTS; }
    if (err != (DWORD)FWP_E_SUBLAYER_NOT_FOUND) return err;
    for (unsigned i = 0; i < 4; ++i) {
        FWPM_CALLOUT0 *callout = NULL;
        FWPM_FILTER0 *filter = NULL;
        err = FwpmCalloutGetByKey0(e, &callouts[i], &callout);
        if (!err) { FwpmFreeMemory0((void **)&callout); return ERROR_ALREADY_EXISTS; }
        if (err != (DWORD)FWP_E_CALLOUT_NOT_FOUND) return err;
        err = FwpmFilterGetByKey0(e, &filters[i], &filter);
        if (!err) { FwpmFreeMemory0((void **)&filter); return ERROR_ALREADY_EXISTS; }
        if (err != (DWORD)FWP_E_FILTER_NOT_FOUND) return err;
    }
    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t **argv) {
    HANDLE engine = NULL;
    FWPM_SESSION0 session = {0};
    UINT8 data[12];
    wchar_t *end = NULL;
    DWORD err;
    unsigned long scope;
    BOOL is_install, is_recover, is_inspect, is_absent;
    if (argc != 4 || wcscmp(argv[3], L"--isolated-lab-confirm") != 0) return 2;
    is_install = wcscmp(argv[1], L"install") == 0;
    is_recover = wcscmp(argv[1], L"recover") == 0;
    is_inspect = wcscmp(argv[1], L"inspect") == 0;
    is_absent = wcscmp(argv[1], L"inspect-absent") == 0;
    if (!is_install && !is_recover && !is_inspect && !is_absent) return 2;
    for (const wchar_t *p = argv[2]; *p; ++p) if (*p < L'0' || *p > L'9') return 2;
    errno = 0;
    scope = wcstoul(argv[2], &end, 10);
    if (errno || end == argv[2] || *end || scope <= 1 || scope == 0xffffffffUL) return 2;
    marker(data, (UINT32)scope);
    session.displayData.name = name;
    session.txnWaitTimeoutInMSec = 3000;
    err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
    if (err) goto done;
    err = FwpmTransactionBegin0(engine, (is_inspect || is_absent) ? FWPM_TXN_READ_ONLY : 0);
    if (err) goto done;
    if (is_install) err = install(engine, (UINT32)scope, data);
    else if (is_recover) err = recover(engine, (UINT32)scope, data);
    else if (is_inspect) err = verify(engine, (UINT32)scope, data);
    else err = verify_absent(engine);
    if (!err && is_install) err = verify(engine, (UINT32)scope, data);
    if (!err && is_recover) err = verify_absent(engine);
    if (err) FwpmTransactionAbort0(engine);
    else {
        err = FwpmTransactionCommit0(engine);
        if (err) FwpmTransactionAbort0(engine);
    }
done:
    if (engine) FwpmEngineClose0(engine);
    if (err) fwprintf(stderr, L"BFE transaction refused/uncertain: 0x%08lx\n", err);
    else if (is_inspect || is_absent) wprintf(L"BFE laboratory ownership inspection passed for compartment %lu\n", scope);
    else wprintf(L"BFE laboratory transaction committed for compartment %lu\n", scope);
    return err ? 1 : 0;
}
