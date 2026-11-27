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
#include <vector>
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
    std::array<GUID,4> filters;
    UINT64 luid;
    std::array<UINT8,16> marker;
    bool boot=false;
    size_t count() const { return boot?4:2; }
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
Plan parse_plan(wchar_t** fields,bool boot) {
    Plan p{guid(fields[0]),guid(fields[2]),{guid(fields[3]),guid(fields[4])},
           parse_luid(fields[1]),marker(guid(fields[5])),boot};
    if(boot) {
        p.filters[2]=guid(fields[6]);
        p.filters[3]=guid(fields[7]);
    }
    for(size_t i=0;i<p.count();++i) {
        require(!eq(p.sub,p.filters[i]));
        for(size_t j=0;j<i;++j) require(!eq(p.filters[i],p.filters[j]));
    }
    return p;
}
void validate_plans(const std::vector<Plan>& plans) {
    require(!plans.empty() && plans.size()<=8);
    std::vector<GUID> keys;
    for(size_t i=0;i<plans.size();++i) {
        const auto& p=plans[i];
        for(size_t j=0;j<i;++j) {
            require(!eq(p.interface_key,plans[j].interface_key) && p.luid!=plans[j].luid);
            require(p.marker!=plans[j].marker);
        }
        auto unique=[&keys](const GUID& key) {
            require(!eq(key,GUID{}));
            for(const auto& old:keys) require(!eq(old,key));
            keys.push_back(key);
        };
        unique(p.sub);
        for(size_t k=0;k<p.count();++k) unique(p.filters[k]);
    }
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
    void abort(){ check(FwpmTransactionAbort0(engine)); active=false; }
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
// A changed owner or access-control list is also a CAS conflict.
bool exact_security(HANDLE e,const GUID& key,bool sublayer) {
    PSID owner=nullptr,group=nullptr;
    PACL dacl=nullptr;
    BfeObject<void> descriptor;
    constexpr SECURITY_INFORMATION info=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION;
    const DWORD status=sublayer
        ? FwpmSubLayerGetSecurityInfoByKey0(e,&key,info,&owner,&group,&dacl,nullptr,&descriptor.value)
        : FwpmFilterGetSecurityInfoByKey0(e,&key,info,&owner,&group,&dacl,nullptr,&descriptor.value);
    check(status);
    if(!descriptor.value || !owner || !group || !dacl ||
        !IsWellKnownSid(owner,WinBuiltinAdministratorsSid) ||
        !IsWellKnownSid(group,WinBuiltinAdministratorsSid) || !IsValidAcl(dacl)) return false;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision=0;
    if(!GetSecurityDescriptorControl(descriptor.value,&control,&revision) ||
        (control&SE_DACL_PROTECTED)==0 || dacl->AceCount!=2) return false;
    bool system=false,admins=false;
    for(DWORD i=0;i<dacl->AceCount;++i) {
        void* raw=nullptr;
        if(!GetAce(dacl,i,&raw) || !raw) return false;
        const auto* ace=static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        if(ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags!=0 ||
            (ace->Mask!=GENERIC_ALL && ace->Mask!=FWPM_GENERIC_ALL)) return false;
        PSID sid=const_cast<DWORD*>(&ace->SidStart);
        if(IsWellKnownSid(sid,WinLocalSystemSid) && !system) system=true;
        else if(IsWellKnownSid(sid,WinBuiltinAdministratorsSid) && !admins) admins=true;
        else return false;
    }
    return system && admins;
}
FWP_BYTE_BLOB blob(Plan& p) {
    return FWP_BYTE_BLOB{static_cast<UINT32>(p.marker.size()),p.marker.data()};
}
bool same_blob(const FWP_BYTE_BLOB& value,const Plan& p) {
    return value.size==p.marker.size() && value.data &&
           std::memcmp(value.data,p.marker.data(),p.marker.size())==0;
}
const GUID& layer(size_t i) {
    return i%2==0?FWPM_LAYER_OUTBOUND_IPPACKET_V4:FWPM_LAYER_OUTBOUND_IPPACKET_V6;
}
bool same_sublayer(const FWPM_SUBLAYER0& s,const Plan& p) {
    return eq(s.subLayerKey,p.sub) && s.flags==FWPM_SUBLAYER_FLAG_PERSISTENT &&
        !s.providerKey && same_blob(s.providerData,p) && s.weight==sub_weight &&
        text_eq(s.displayData.name,name) && !s.displayData.description;
}
const GUID& filter_sublayer(const Plan& p,size_t i) {
    // Boot-time filters use a built-in sublayer, not a user-mode
    // sublayer whose initialization before BFE has not been proven.
    return i<2?p.sub:FWPM_SUBLAYER_UNIVERSAL;
}
UINT32 filter_flags(size_t i) {
    return i<2?FWPM_FILTER_FLAG_PERSISTENT:FWPM_FILTER_FLAG_BOOTTIME;
}
bool same_filter(const FWPM_FILTER0& f,const Plan& p,size_t i) {
    const UINT32 expected=filter_flags(i);
    // BFE may report a configured boot-time object as disabled once it
    // has handed off to runtime policy. This is never active-boot proof.
    const bool flags_ok=f.flags==expected ||
        (i>=2 && f.flags==(expected|FWPM_FILTER_FLAG_DISABLED));
    if(!eq(f.filterKey,p.filters[i]) || !eq(f.layerKey,layer(i)) ||
       !eq(f.subLayerKey,filter_sublayer(p,i)) || !flags_ok ||
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
State classify(bool sub_present,bool sub_exact,const std::array<bool,4>& present,
               const std::array<bool,4>& exact,size_t count=2) {
    bool any=sub_present, all=sub_present && sub_exact;
    for(size_t i=0;i<count;++i) {
        any=any || present[i];
        all=all && present[i] && exact[i];
    }
    return !any?State::absent:all?State::exact:State::conflict;
}
State inspect(HANDLE e,const Plan& p) {
    BfeObject<FWPM_SUBLAYER0> s;
    DWORD status=FwpmSubLayerGetByKey0(e,&p.sub,&s.value);
    bool sub_present=status!=static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND);
    if(sub_present) { check(status); require(s.value!=nullptr); }
    std::array<bool,4> present{},exact{};
    for(size_t i=0;i<p.count();++i) {
        BfeObject<FWPM_FILTER0> f;
        status=FwpmFilterGetByKey0(e,&p.filters[i],&f.value);
        if(status==static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) continue;
        check(status); require(f.value!=nullptr);
        present[i]=true;
        exact[i]=same_filter(*f.value,p,i) && exact_security(e,p.filters[i],false);
    }
    return classify(sub_present,sub_present && same_sublayer(*s.value,p) &&
        exact_security(e,p.sub,true),present,exact,p.count());
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
    for(size_t i=0;i<p.count();++i) {
        FWPM_FILTER0 f{};
        f.filterKey=p.filters[i];
        f.displayData.name=const_cast<wchar_t*>(name);
        f.flags=filter_flags(i);
        f.providerData=blob(p);
        f.layerKey=layer(i);
        f.subLayerKey=filter_sublayer(p,i);
        f.weight.type=FWP_UINT64;
        f.weight.uint64=&weight;
        f.numFilterConditions=1;
        f.filterCondition=&condition;
        f.action.type=FWP_ACTION_BLOCK;
        check(FwpmFilterAdd0(e,&f,security.value,nullptr));
    }
}
void remove(HANDLE e,const Plan& p) {
    for(size_t i=0;i<p.count();++i) check(FwpmFilterDeleteByKey0(e,&p.filters[i]));
    // BFE refuses if an unexpected foreign filter references this
    // sublayer; the transaction destructor then rolls back both deletes.
    check(FwpmSubLayerDeleteByKey0(e,&p.sub));
}
State inspect_all(HANDLE engine,const std::vector<Plan>& plans) {
    bool all_absent=true,all_exact=true;
    for(const auto& p:plans) {
        const auto state=inspect(engine,p);
        all_absent=all_absent && state==State::absent;
        all_exact=all_exact && state==State::exact;
    }
    return all_absent?State::absent:all_exact?State::exact:State::conflict;
}
const wchar_t* status_name(State s) {
    switch(s) {
        case State::absent:return L"absent";
        case State::exact:return L"exact";
        default:return L"conflict";
    }
}
GUID fresh_guid() {
    GUID result{};
    require(CoCreateGuid(&result)==S_OK && !eq(result,GUID{}));
    return result;
}
// Exercise actual BFE API and canonical read-back, but NEVER commit
// any of the test filters. Even a failed assertion aborts via RAII.
void transaction_self_test() {
    Plan p{GUID{},fresh_guid(),{fresh_guid(),fresh_guid()},1,marker(fresh_guid())};
    Engine engine;
    {
        Transaction tx(engine.value,false);
        require(inspect(engine.value,p)==State::absent);
        install(engine.value,p);
        require(inspect(engine.value,p)==State::exact);
        auto changed=p;
        changed.luid=2;
        require(inspect(engine.value,changed)==State::conflict);
        changed=p;
        changed.marker[0]^=1;
        require(inspect(engine.value,changed)==State::conflict);
        remove(engine.value,p);
        require(inspect(engine.value,p)==State::absent);
        install(engine.value,p);
        check(FwpmFilterDeleteByKey0(engine.value,&p.filters[0]));
        require(inspect(engine.value,p)==State::conflict);
        tx.abort();
    }
    {
        Transaction tx(engine.value,true);
        require(inspect(engine.value,p)==State::absent);
        tx.commit();
    }
    std::wprintf(L"BFE add/read/compare/delete/abort passed; no committed test filters\n");
}
void multi_transaction_self_test(bool boot) {
    std::vector<Plan> plans;
    for(UINT64 luid:{UINT64{1},UINT64{2}}) {
        Plan p{fresh_guid(),fresh_guid(),{fresh_guid(),fresh_guid(),GUID{},GUID{}},luid,marker(fresh_guid()),boot};
        if(boot) {p.filters[2]=fresh_guid();p.filters[3]=fresh_guid();}
        plans.push_back(p);
    }
    validate_plans(plans);
    Engine engine;
    {
        Transaction tx(engine.value,false);
        require(inspect_all(engine.value,plans)==State::absent);
        install(engine.value,plans[0]);
        require(inspect_all(engine.value,plans)==State::conflict);
        install(engine.value,plans[1]);
        require(inspect_all(engine.value,plans)==State::exact);
        auto changed=plans;
        changed[1].luid=3;
        require(inspect_all(engine.value,changed)==State::conflict);
        check(FwpmFilterDeleteByKey0(engine.value,&plans[1].filters[plans[1].count()-1]));
        require(inspect_all(engine.value,plans)==State::conflict);
        tx.abort();
    }
    {
        Transaction tx(engine.value,true);
        require(inspect_all(engine.value,plans)==State::absent);
        tx.commit();
    }
    std::wprintf(L"multi-interface BFE transaction abort verified; boot configuration requested=%ls; no packet enforcement asserted\n",boot?L"yes":L"no");
}
void self_test() {
    require(classify(false,false,{false,false},{false,false})==State::absent);
    require(classify(true,true,{true,true},{true,true})==State::exact);
    require(classify(true,false,{true,true},{true,true})==State::conflict);
    require(classify(true,true,{true,false},{true,false})==State::conflict);
    require(classify(false,false,{true,true},{true,true})==State::conflict);
    require(classify(true,true,{true,true},{true,false})==State::conflict);
    require(classify(true,true,{true,true,true,true},{true,true,true,true},4)==State::exact);
    require(classify(true,true,{true,true,true,false},{true,true,true,false},4)==State::conflict);
    require(filter_flags(0)==FWPM_FILTER_FLAG_PERSISTENT && filter_flags(2)==FWPM_FILTER_FLAG_BOOTTIME);
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
        if(argc==3 && wcscmp(argv[1],L"transaction-self-test")==0 &&
            wcscmp(argv[2],L"abort-only")==0) { transaction_self_test(); return 0; }
        if(argc==3 && wcscmp(argv[1],L"multi-transaction-self-test")==0 &&
            wcscmp(argv[2],L"abort-only")==0) { multi_transaction_self_test(false); return 0; }
        if(argc==3 && wcscmp(argv[1],L"boot-transaction-self-test")==0 &&
            wcscmp(argv[2],L"abort-only")==0) { multi_transaction_self_test(true); return 0; }
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
        require(argc>=9 && wcscmp(argv[argc-1],L"isolated-test-machine")==0);
        std::wstring mode=argv[1];
        std::vector<Plan> plans;
        if(mode==L"install-many" || mode==L"inspect-many" || mode==L"recover-many") {
            mode.resize(mode.size()-5);
            const bool boot=wcscmp(argv[2],L"boot")==0;
            require(boot || wcscmp(argv[2],L"persistent")==0);
            const int width=boot?8:6;
            require((argc-4)%width==0 && (argc-4)/width>=1 && (argc-4)/width<=8);
            for(int offset=3;offset<argc-1;offset+=width) plans.push_back(parse_plan(argv+offset,boot));
        } else {
            require(argc==9);
            plans.push_back(parse_plan(argv+2,false));
        }
        require(mode==L"install" || mode==L"inspect" || mode==L"recover");
        validate_plans(plans);
        auto verify_all=[&plans]() {for(const auto& p:plans) verify_interface(p);};
        // Explicit recovery can remove exact OLD objects even after an
        // interface change, but cannot delete a partial or foreign set.
        if(mode!=L"recover") verify_all();
        Engine engine;
        Transaction tx(engine.value,mode==L"inspect");
        const auto before=inspect_all(engine.value,plans);
        if(mode==L"install") {
            require(before==State::absent);
            for(auto& p:plans) install(engine.value,p);
            require(inspect_all(engine.value,plans)==State::exact);
            verify_all();
        } else if(mode==L"recover") {
            require(before!=State::conflict);
            if(before==State::exact) for(const auto& p:plans) remove(engine.value,p);
            require(inspect_all(engine.value,plans)==State::absent);
        }
        tx.commit();
        // Fresh independent read transaction. No claim about enforcement
        // or boot handoff, only the complete configured object set.
        Transaction observed(engine.value,true);
        const auto after=inspect_all(engine.value,plans);
        observed.commit();
        if(mode==L"install") require(after==State::exact);
        if(mode==L"recover") require(after==State::absent);
        else verify_all();
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
