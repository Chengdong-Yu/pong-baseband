/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * IPA QMI extended-rule reception. Wire facts: NothingOSS 22G100 board
 * reference ipa_qmi_service_v01.c and rmnet_ipa.c, c402fcdb3a15.
 * The native request handler first stores rules and returns their actual
 * IDs. Hardware installation and FILTER_INSTALLED are separate operations.
 * Pong's QMAP DMA path does not advertise AP classifier/NAT offloads.
 */
struct PongModemRules {
    static constexpr unsigned MaxRules=64,RuleBytes=173,Capacity=16384;
    struct Rule {uint32_t id,mux,route,action,ip;bool xlat,firewall;};
    struct Set {uint8_t wire[Capacity];unsigned bytes=0,count=0;Rule rules[MaxRules]{};} sets[2]{};
    unsigned active=0,generation=0;bool valid=false;
    unsigned failure=0,detail=0,detail2=0;
    uint32_t reject(unsigned stage,unsigned a=0,unsigned b=0) {
        failure=stage;detail=a;detail2=b;return 1;
    }
    void snapshot()const {
        IOLog("Pong WAN rules: generation=%u active=%u count=%u failure=%u detail=%u detail2=%u; no subscriber or packet contents\n",generation,valid,count(),failure,detail,detail2);
    }
    unsigned count()const {return valid?sets[active].count:0;}
    uint32_t id(unsigned index)const {return sets[active].rules[index].id;}
    void revoke(){valid=false;}
    uint32_t receive(const uint8_t *sdu,unsigned bytes) {
        failure=detail=detail2=0;
        if(!cbd_sdu_ok(sdu,bytes))return reject(1);
        const unsigned end=7u+cbd_rd16(sdu+5);
        if(end>Capacity)return 2;
        auto &next=sets[active^1u];next.bytes=next.count=0;
        uint32_t fields=0,listBytes=0;const uint8_t *list=nullptr;
        for(unsigned at=7;at<end;at+=3+cbd_rd16(sdu+at+1)) {
            const unsigned type=sdu[at],size=cbd_rd16(sdu+at+1);
            if(type<0x10||type>0x17)return 94;
            const unsigned bit=1u<<(type-0x10);if(fields&bit)return reject(2,type);fields|=bit;
            if(type==0x10||type==0x16)return 94; // different native rule formats
            if(type==0x15){list=sdu+at+3;listBytes=size;}
            else if(type>=0x11&&type<=0x13&&size!=4)return reject(3,type,size);
        }
        if(!list||!listBytes||list[0]>MaxRules||listBytes!=1u+unsigned(list[0])*RuleBytes)return reject(4,listBytes,list&&listBytes?list[0]:0);
        next.count=list[0];unsigned ipv4=0,ipv6=0;
        for(unsigned i=0;i<next.count;i++) {
            const auto *p=list+1+i*RuleBytes;
            const uint32_t ip=cbd_rd32(p),action=cbd_rd32(p+154);
            // Match the original reception stage: preserve equations and
            // inactive fields as opaque metadata, rather than imposing
            // execution-time classifier restrictions here. This cache is
            // never interpreted as an installed AP hardware rule table.
            const uint32_t route=cbd_rd32(p+159),mux=cbd_rd32(p+164),id=cbd_rd32(p+168);
            // Preserve the modem's IDs verbatim, including repeated IDs
            // across IP tables; the native receiver does not renumber or
            // impose an additional global uniqueness requirement.
            next.rules[i]={id,p[163]?mux:~0u,p[158]?route:~0u,action,ip,false,false};
            ipv4+=ip==1||ip==3;ipv6+=ip==2||ip==3;
        }
        const unsigned types[]={0x11,0x12,0x13,0x14,0x17};
        for(unsigned type:types) {
            uint32_t size=0;const auto *p=cbd_find(sdu,bytes,type,&size);if(!p)continue;
            if(type==0x11){if(cbd_rd32(p)>=32)return reject(8,type,cbd_rd32(p));continue;}
            if(type==0x12||type==0x13){if(cbd_rd32(p)!=(type==0x12?ipv4:ipv6))return reject(9,type,cbd_rd32(p));continue;}
            if(!size||p[0]>next.count||size!=1u+4u*p[0])return reject(10,size,p[0]);
            for(unsigned i=0;i<p[0];i++) {
                const unsigned index=cbd_rd32(p+1+i*4);if(index>=next.count)return reject(11,type,index);
                if(type==0x14)next.rules[index].xlat=true;else next.rules[index].firewall=true;
            }
        }
        memcpy(next.wire,sdu,end);next.bytes=end;
        active^=1u;valid=true;++generation;
        IOLog("Pong WAN: retained actual extended filter request generation=%u rules=%u bytes=%u; IDs acknowledged, AP hardware install not reported\n",generation,count(),end);
        return 0;
    }
} modemRules;
