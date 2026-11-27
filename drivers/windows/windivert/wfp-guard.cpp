// F-15 native BFE transaction fixture. No driver, packet injection, permit,
// global firewall defaults or automatic startup. Use only a disposable
// machine and a specifically reviewed non-loopback interface.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <rpc.h>
#include <initguid.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
#include <objbase.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <array>
#include <utility>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

namespace {
constexpr wchar_t name[] = L"Theia isolated persistent interface guard v1";
constexpr UINT16 sub_weight = 0x8000;
constexpr UINT64 filter_weight = 0x8000000000000000ULL;

struct Failure { DWORD code; };
void check(DWORD code) { if (code != ERROR_SUCCESS) throw Failure{code}; }
void require(bool condition) { if (!condition) throw Failure{ERROR_INVALID_DATA}; }
bool eq(const GUID& a, const GUID& b) { return InlineIsEqualGUID(a,b) != 0; }

GUID guid(const wchar_t* text) {
    GUID value{};
    require(wcslen(text)==38 && text[0]==L'{' && text[37]==L'}');
    require(CLSIDFromString(text,&value)==S_OK && !eq(value,GUID{}));
    return value;
}
bool text_eq(const wchar_t* value,const wchar_t* expected) {
    return value && wcscmp(value,expected)==0;
}

struct Plan {
    GUID interface_key;
    GUID sub;
    std::array<GUID,2> filters;
    UINT64 luid;
    std::array<UINT8,16> marker;
};
std::array<UINT8,16> marker(const GUID& id) {
    std::array<UINT8,16> out{};
    static_assert(sizeof(id)==16);
    std::memcpy(out.data(),&id,out.size());
    return out;
}
UINT64 parse_luid(const wchar_t* text) {
    require(wcslen(text)==16);
    UINT64 value=0;
    for (const wchar_t* p=text; *p; ++p) {
        const wchar_t c=*p;
        unsigned n=0;
        if(c>=L'0' && c<=L'9') n=static_cast<unsigned>(c-L'0');
        else if(c>=L'a' && c<=L'f') n=static_cast<unsigned>(c-L'a'+10);
        else throw Failure{ERROR_INVALID_DATA};
        value=(value<<4)|n;
    }
    require(value!=0);
    return value;
}
void verify_interface(const Plan& p) {
    NET_LUID luid{};
    check(ConvertInterfaceGuidToLuid(&p.interface_key,&luid));
    require(luid.Value==p.luid);
    MIB_IF_ROW2 row{};
    row.InterfaceLuid=luid;
    check(GetIfEntry2(&row));
    require(eq(row.InterfaceGuid,p.interface_key) && row.Type!=IF_TYPE_SOFTWARE_LOOPBACK);
}
Plan parse_plan(wchar_t** argv) {
    Plan p{guid(argv[2]),guid(argv[4]),{guid(argv[5]),guid(argv[6])},
           parse_luid(argv[3]),marker(guid(argv[7]))};
    require(!eq(p.sub,p.filters[0]) && !eq(p.sub,p.filters[1]) &&
            !eq(p.filters[0],p.filters[1]));
    return p;
}

struct Engine {
    HANDLE value=nullptr;
    Engine() {
        FWPM_SESSION0 session{};
        session.txnWaitTimeoutInMSec=5000;
        // A non-dynamic session is essential for persistent objects.
        check(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&session,&value));
    }
    ~Engine() { if(value) FwpmEngineClose0(value); }
    Engine(const Engine&)=delete;
    Engine& operator=(const Engine&)=delete;
};
struct Transaction {
    HANDLE engine;
    bool active=false;
    Transaction(HANDLE e,bool read_only):engine(e) {
        check(FwpmTransactionBegin0(engine,read_only?FWPM_TXN_READ_ONLY:0));
        active=true;
    }
    ~Transaction(){ if(active) FwpmTransactionAbort0(engine); }
    void commit(){ check(FwpmTransactionCommit0(engine)); active=false; }
    Transaction(const Transaction&)=delete;
    Transaction& operator=(const Transaction&)=delete;
};
template<class T> struct BfeObject {
    T* value=nullptr;
    ~BfeObject(){ if(value) { void* mem=value; FwpmFreeMemory0(&mem); } }
    BfeObject()=default;
    BfeObject(const BfeObject&)=delete;
    BfeObject& operator=(const BfeObject&)=delete;
};
struct Security {
    PSECURITY_DESCRIPTOR value=nullptr;
    Security() {
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)",SDDL_REVISION_1,&value,nullptr))
            throw Failure{GetLastError()};
    }
    ~Security(){ if(value) LocalFree(value); }
};
FWP_BYTE_BLOB blob(Plan& p) {
    return FWP_BYTE_BLOB{static_cast<UINT32>(p.marker.size()),p.marker.data()};
}
bool same_blob(const FWP_BYTE_BLOB& value,const Plan& p) {
    return value.size==p.marker.size() && value.data &&
           std::memcmp(value.data,p.marker.data(),p.marker.size())==0;
}
const GUID& layer(size_t i) {
    return i==0?FWPM_LAYER_OUTBOUND_IPPACKET_V4:FWPM_LAYER_OUTBOUND_IPPACKET_V6;
}
bool same_sublayer(const FWPM_SUBLAYER0& s,const Plan& p) {
    return eq(s.subLayerKey,p.sub) && s.flags==FWPM_SUBLAYER_FLAG_PERSISTENT &&
        !s.providerKey && same_blob(s.providerData,p) && s.weight==sub_weight &&
        text_eq(s.displayData.name,name) && !s.displayData.description;
}
bool same_filter(const FWPM_FILTER0& f,const Plan& p,size_t i) {
    if(!eq(f.filterKey,p.filters[i]) || !eq(f.layerKey,layer(i)) ||
       !eq(f.subLayerKey,p.sub) || f.flags!=FWPM_FILTER_FLAG_PERSISTENT ||
       f.providerKey || !same_blob(f.providerData,p) ||
       f.action.type!=FWP_ACTION_BLOCK || f.rawContext!=0 || f.reserved ||
       !text_eq(f.displayData.name,name) || f.displayData.description ||
       f.weight.type!=FWP_UINT64 || !f.weight.uint64 || *f.weight.uint64!=filter_weight ||
       f.numFilterConditions!=1 || !f.filterCondition) return false;
    const auto& c=f.filterCondition[0];
    return eq(c.fieldKey,FWPM_CONDITION_IP_LOCAL_INTERFACE) && c.matchType==FWP_MATCH_EQUAL &&
        c.conditionValue.type==FWP_UINT64 && c.conditionValue.uint64 &&
        *c.conditionValue.uint64==p.luid;
}
enum class State { absent, exact, conflict };
State classify(bool sub_present,bool sub_exact,const std::array<bool,2>& present,
               const std::array<bool,2>& exact) {
    if(!sub_present && !present[0] && !present[1]) return State::absent;
    if(sub_present && sub_exact && present[0] && present[1] && exact[0] && exact[1])
        return State::exact;
    return State::conflict;
}
State inspect(HANDLE e,const Plan& p) {
    BfeObject<FWPM_SUBLAYER0> s;
    DWORD status=FwpmSubLayerGetByKey0(e,&p.sub,&s.value);
    bool sub_present=status!=static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND);
    if(sub_present) { check(status); require(s.value!=nullptr); }
    std::array<bool,2> present{},exact{};
    for(size_t i=0;i<2;++i) {
        BfeObject<FWPM_FILTER0> f;
        status=FwpmFilterGetByKey0(e,&p.filters[i],&f.value);
        if(status==static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) continue;
        check(status); require(f.value!=nullptr);
        present[i]=true;
        exact[i]=same_filter(*f.value,p,i);
    }
    return classify(sub_present,sub_present && same_sublayer(*s.value,p),present,exact);
}
void install(HANDLE e,Plan& p) {
    Security security;
    FWPM_SUBLAYER0 s{};
    s.subLayerKey=p.sub;
    s.displayData.name=const_cast<wchar_t*>(name);
    s.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;
    s.providerData=blob(p);
    s.weight=sub_weight;
    check(FwpmSubLayerAdd0(e,&s,security.value));
    UINT64 weight=filter_weight;
    FWPM_FILTER_CONDITION0 condition{};
    condition.fieldKey=FWPM_CONDITION_IP_LOCAL_INTERFACE;
    condition.matchType=FWP_MATCH_EQUAL;
    condition.conditionValue.type=FWP_UINT64;
    condition.conditionValue.uint64=&p.luid;
    for(size_t i=0;i<2;++i) {
        FWPM_FILTER0 f{};
        f.filterKey=p.filters[i];
        f.displayData.name=const_cast<wchar_t*>(name);
        f.flags=FWPM_FILTER_FLAG_PERSISTENT;
        f.providerData=blob(p);
        f.layerKey=layer(i);
        f.subLayerKey=p.sub;
        f.weight.type=FWP_UINT64;
        f.weight.uint64=&weight;
        f.numFilterConditions=1;
        f.filterCondition=&condition;
        f.action.type=FWP_ACTION_BLOCK;
        check(FwpmFilterAdd0(e,&f,security.value,nullptr));
    }
}
void remove(HANDLE e,const Plan& p) {
    for(const auto& key:p.filters) check(FwpmFilterDeleteByKey0(e,&key));
    // BFE refuses if an unexpected foreign filter references this
    // sublayer; the transaction destructor then rolls back both deletes.
    check(FwpmSubLayerDeleteByKey0(e,&p.sub));
}
const wchar_t* status_name(State s) {
    switch(s) {
        case State::absent:return L"absent";
        case State::exact:return L"exact";
        default:return L"conflict";
    }
}
void self_test() {
    require(classify(false,false,{false,false},{false,false})==State::absent);
    require(classify(true,true,{true,true},{true,true})==State::exact);
    require(classify(true,false,{true,true},{true,true})==State::conflict);
    require(classify(true,true,{true,false},{true,false})==State::conflict);
    require(classify(false,false,{true,true},{true,true})==State::conflict);
    require(classify(true,true,{true,true},{true,false})==State::conflict);
    require(parse_luid(L"0000000000000001")==1);
    require(parse_luid(L"ffffffffffffffff")==~UINT64{0});
    bool rejected=false;
    try { (void)parse_luid(L"0000000000000000"); } catch(const Failure&) { rejected=true; }
    require(rejected);
    std::wprintf(L"self-test passed (no OS mutation)\n");
}
}

int wmain(int argc,wchar_t** argv) {
    try {
        if(argc==2 && wcscmp(argv[1],L"self-test")==0) { self_test(); return 0; }
        if(argc==3 && wcscmp(argv[1],L"interface")==0) {
            NET_LUID luid{};
            auto id=guid(argv[2]);
            check(ConvertInterfaceGuidToLuid(&id,&luid));
            Plan p{}; p.interface_key=id; p.luid=luid.Value;
            verify_interface(p);
            std::wprintf(L"%016llx\n",static_cast<unsigned long long>(luid.Value));
            return 0;
        }
        // Only the protected journal wrapper should call these commands.
        require(argc==9 && wcscmp(argv[8],L"isolated-test-machine")==0);
        const std::wstring mode=argv[1];
        require(mode==L"install" || mode==L"inspect" || mode==L"recover");
        auto p=parse_plan(argv);
        // Refuse to install or claim coverage if a GUID now resolves to
        // another LUID. Explicit recovery can remove the exact OLD
        // filters even if the interface was unplugged or renumbered.
        if(mode!=L"recover") verify_interface(p);
        Engine engine;
        Transaction tx(engine.value,mode==L"inspect");
        const auto before=inspect(engine.value,p);
        if(mode==L"install") {
            require(before==State::absent);
            install(engine.value,p);
            require(inspect(engine.value,p)==State::exact);
        } else if(mode==L"recover") {
            require(before!=State::conflict);
            if(before==State::exact) remove(engine.value,p);
            require(inspect(engine.value,p)==State::absent);
        }
        tx.commit();
        // Fresh, independent read transaction. No claim about physical
        // packet enforcement or arbitration, only committed object state.
        Transaction observed(engine.value,true);
        const auto after=inspect(engine.value,p);
        observed.commit();
        if(mode==L"install") require(after==State::exact);
        if(mode==L"recover") require(after==State::absent);
        std::wprintf(L"%ls\n",status_name(after));
        return after==State::conflict?2:0;
    } catch(const Failure& error) {
        std::fwprintf(stderr,L"WFP guard refused or failed (0x%08lx); retain journal\n",
                      static_cast<unsigned long>(error.code));
        return 1;
    } catch(...) {
        std::fwprintf(stderr,L"WFP guard unexpected failure; retain journal\n");
        return 1;
    }
}
