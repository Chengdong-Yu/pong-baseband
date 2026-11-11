/* SPDX-License-Identifier: GPL-2.0-only
 * IPA5.1 equation/table serialization adapted from NothingOSS SM8475
 * ipahal_fltrt.c / ipahal_fltrt_i.h, c402fcdb3a1523d10b15ef1123bced45456f7592.
 * Copyright (c) 2012-2021, The Linux Foundation. All rights reserved.
 * Native wire fields are decoded explicitly; never log match payloads.
 */
struct PongIpaFilters {
    unsigned generation=0,building=0,completion=0,counts[2]{},lengths[2]{},ids[64]{},idCount=0;
    unsigned failure=0,detail=0;
    bool pending=false;
    unsigned reject(unsigned code,unsigned value=0){failure=code;detail=value;return 0;}
    static bool flag(const uint8_t *eq,unsigned at){return eq[at]==1;}
    unsigned rule(const uint8_t *wire,uint8_t *out,unsigned room,unsigned priority) {
        if(room<256)return reject(1,room);
        const auto *eq=wire+4;
        const unsigned ranges=eq[6],meq=eq[17],ihl=eq[53],wide=eq[72];
        const unsigned flags[]={2,4,36,38,43,47,139,149};
        for(unsigned at:flags)if(eq[at]>1)return reject(2,at);
        if(ranges>2||meq>2||ihl>2||wide>2)return reject(3);
        const unsigned extra=eq[2]+eq[4]+eq[36]+eq[43]+eq[47]+ranges+meq+ihl+wide;
        if(extra>13)return reject(4,extra);
        const unsigned route=wire[158]?cbd_rd32(wire+159):0,action=cbd_rd32(wire+154),id=cbd_rd32(wire+168);
        // Original rmnet copies native IPA enum values directly. AP NAT
        // is not implemented by this owner; refuse it rather than execute
        // an uninitialized NAT table or silently change a carrier rule.
        if(action!=0&&action!=3)return reject(5,action);
        if(route>255||id>=1023||priority>255)return reject(6,id);
        uint16_t expected=0;
        if(eq[2])expected|=1u;
        if(eq[4])expected|=1u<<1;
        if(eq[36])expected|=1u<<2;
        for(unsigned i=0;i<wide;i++)expected|=1u<<(3+i);
        for(unsigned i=0;i<meq;i++)expected|=1u<<(5+i);
        for(unsigned i=0;i<ihl;i++)expected|=1u<<(7+i);
        if(eq[139])expected|=1u<<9;
        for(unsigned i=0;i<ranges;i++)expected|=1u<<(10+i);
        if(eq[47])expected|=1u<<12;
        if(eq[43])expected|=1u<<13;
        if(eq[38])expected|=1u<<14;
        if(eq[149])expected|=1u<<15;
        if(cbd_rd16(eq)!=expected)return reject(7,cbd_rd16(eq));
        bzero(out,256);
        const uint64_t header=expected|(uint64_t(route)<<16)|(uint64_t(priority)<<32)|
            (uint64_t(id)<<42)|(uint64_t(action)<<52)|(1ull<<62);
        IpaCommandDma::le64(out,header);
        unsigned ex=8,rest=8+((extra+7)&~7u);
        if(eq[2])out[ex++]=0; // IPA>=4.5 pure-ACK, not an IPv4 TOS byte
        if(eq[4])out[ex++]=eq[5];
        if(eq[36])out[ex++]=eq[37];
        for(unsigned i=0;i<wide;i++) {
            const auto *p=eq+73+33*i;out[ex++]=p[0];
            memcpy(out+rest,p+1,8);rest+=8;memcpy(out+rest,p+17,8);rest+=8;
            memcpy(out+rest,p+9,8);rest+=8;memcpy(out+rest,p+25,8);rest+=8;
        }
        for(unsigned kind=0;kind<2;kind++)for(unsigned i=0;i<(kind?ihl:meq);i++) {
            const auto *p=eq+(kind?54:18)+9*i;out[ex++]=p[0];
            memcpy(out+rest,p+1,8);rest+=8;
        }
        if(eq[139]){memcpy(out+rest,eq+141,8);rest+=8;}
        for(unsigned i=0;i<ranges;i++) {
            const auto *p=eq+7+5*i;out[ex++]=p[0];
            // QMI order low/high; hardware body order high/low.
            memcpy(out+rest,p+3,2);rest+=2;memcpy(out+rest,p+1,2);rest+=2;
        }
        if(eq[47]){out[ex++]=eq[48];memcpy(out+rest,eq+49,4);rest+=4;}
        if(eq[43]){out[ex++]=eq[44];memcpy(out+rest,eq+45,2);rest+=4;}
        if(eq[38]){IpaCommandDma::le32(out+rest,cbd_rd32(eq+39)&0xfffffu);rest+=4;}
        if(ex!=8+extra||rest>248)return reject(8,rest);
        return (rest+7)&~7u;
    }
    bool prepare() {
        failure=detail=0;
        auto &d=ipaDma;const auto &set=modemRules.sets[modemRules.active];
        unsigned bytes=0;const auto *list=cbd_find(set.wire,set.bytes,0x15,&bytes);
        if(!list||!bytes||bytes!=1u+list[0]*PongModemRules::RuleBytes||list[0]>64){reject(9);return false;}
        counts[0]=counts[1]=lengths[0]=lengths[1]=0;idCount=list[0];
        // Exclusive, otherwise-unused owned DMA arena. Keep each family
        // terminated and leave space for all64 bounded native equations.
        bzero(d.cpu+0x41000,0xc000);
        for(unsigned i=0;i<idCount;i++) {
            const auto *wire=list+1+i*PongModemRules::RuleBytes;
            const unsigned family=cbd_rd32(wire);
            if(i<12)IOLog("Pong WAN filter metadata: index=%u native_ip=%u action=%u route=%u rule_id=%u bitmap=%x; match bytes omitted\n",
                i,family,cbd_rd32(wire+154),cbd_rd32(wire+159),cbd_rd32(wire+168),cbd_rd16(wire+4));
            if(family>1){reject(10,family);return false;}
            const unsigned offset=family?0x47000:0x41000,used=lengths[family];
            if(used+256+8>0x6000){reject(11,used);return false;}
            const unsigned amount=rule(wire,d.cpu+offset+used,0x6000-used,counts[family]);
            if(!amount)return false;
            ids[i]=cbd_rd32(wire+168);lengths[family]+=amount;++counts[family];
        }
        d.clean(d.cpu+0x41000,0xc000);
        // Pipe2 is the second set production bit in original0x94e6:
        // bitmap word followed by pipe1/pipe2/etc pointers. Update ONLY
        // the AP non-hash entry; keep all modem-owned entries untouched.
        IpaCommandDma::le64(d.cpu+0x40800,d.Iova+0x41000);
        IpaCommandDma::le64(d.cpu+0x40808,d.Iova+0x47000);d.clean(d.cpu+0x40800,64);
        IpaCommandDma::Immediate commands[3]={};
        for(unsigned i=0;i<2;i++) {
            commands[i].opcode=19;commands[i].bytes=16;
            d.le16(commands[i].payload+2,8);
            d.le16(commands[i].payload+4,d.restricted+(i?0x1418:0x1318));
            d.le64(commands[i].payload+8,d.Iova+0x40800+i*8);
        }
        // Native IPA5 filter commit invalidates the filter cache after
        // publishing table headers. Clear only its documented filter
        // strobe, retaining routing-cache/other bits and real HPS clear.
        commands[2].opcode=12;commands[2].bytes=16;
        d.le16(commands[2].payload+2,0x404);
        d.le32(commands[2].payload+4,1u<<4);d.le32(commands[2].payload+8,1u<<4);
        completion=d.completedCommands+1;
        if(!d.submit(commands,3))return false;
        building=modemRules.generation;pending=true;
        IOLog("Pong WAN filters: submitted actual AP2 equation tables generation=%u v4=%u/%u v6=%u/%u; installation not acknowledged yet\n",
            building,counts[0],lengths[0],counts[1],lengths[1]);
        return true;
    }
    void poll(bool txIdle) {
        auto &d=ipaDma;if(d.error||d.stage!=10||!modemRules.valid)return;
        if(pending) {
            if(d.pending||d.completedCommands<completion)return;
            pending=false;generation=building;
            IOLog("Pong WAN filters: real command completion installed generation=%u AP2 only; modem notification still required\n",generation);
        }
        if(generation==modemRules.generation||pending||!txIdle||d.pending||failure)return;
        if(!prepare()&&failure)IOLog("Pong WAN filters: actual native rule unsupported/invalid phase=%u detail=%u; TX remains blocked, no installed success sent\n",failure,detail);
    }
    unsigned notification(uint8_t *out,unsigned room,uint16_t transaction) const {
        if(!generation||pending||room<512)return 0;
        uint8_t pipe[4]={2,0,0,0},status[2]={},empty[1]={},list[257]={};
        list[0]=uint8_t(idCount);for(unsigned i=0;i<idCount;i++)cbd_wr32(list+1+i*4,ids[i]);
        unsigned used=7;
        used+=cbd_tlv(out+used,room-used,1,pipe,4);
        used+=cbd_tlv(out+used,room-used,2,status,2);
        used+=cbd_tlv(out+used,room-used,3,empty,1);
        used+=cbd_tlv(out+used,room-used,0x17,list,1+4*idCount);
        return cbd_request(out,transaction,0x24,used-7);
    }
} ipaFilters;
