/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Pong's actual heap-mem QMI v1 service (0x34, instance1). Protocol fields
 * and cape client sizes follow NothingOSS's published memshare driver/DT.
 * Runs only on the MPSS owner worker, outside GLINK receive callbacks.
 * No fixed Linux CMA address, invented DMA extent or implicit SCM success.
 */
constexpr uint32_t MemsharePort=0x101,MemshareMaximum=0x500000;
struct MemshareOwner {
    IOBufferMemoryDescriptor *memory=nullptr;
    uint64_t physical=0;
    uint32_t bytes=0,node=0,port=0;
    bool modem=false,quarantined=false;
} memshare;
uint16_t ms16(const uint8_t *p){return uint16_t(p[0])|uint16_t(p[1])<<8;}
uint32_t ms32(const uint8_t *p){return uint32_t(ms16(p))|uint32_t(ms16(p+2))<<16;}
uint64_t ms64(const uint8_t *p){return uint64_t(ms32(p))|uint64_t(ms32(p+4))<<32;}
void msPut(uint8_t *p,uint64_t value,unsigned n){for(unsigned i=0;i<n;i++)p[i]=uint8_t(value>>(i*8));}
bool msValue(const QcomQmiMessage &m,uint8_t tag,uint32_t &value,bool optional=false) {
    uint32_t length=0;auto p=qcom_qmi_tlv(&m,tag,&length);
    if(!p)return optional;
    if(length!=4)return false;
    value=ms32(p);return true;
}
// Ownership bits:1 HLOS,2 MSS_MSA. Also used by the distinct RMTFS buffer,
// which must remain CPU-accessible while the modem accesses the same pages.
bool modemAssignPages(uint64_t physical,uint32_t bytes,unsigned from,unsigned to) {
    // PAS authentication is complete before this service can receive a
    // request. Its boot-owned64KiB scratch is reused under the SCM gate.
    uint64_t scratch=0;Window work;
    if(!PongLowDma::modemMetadataAddress(scratch)||!work.open(scratch,4096,kIOMapWriteCombineCache))return false;
    auto *p=const_cast<uint8_t *>(work.va);bzero(p,4096);
    msPut(p,physical,8);msPut(p+8,(bytes+4095u)&~4095u,8);
    unsigned sources=0,destinations=0;
    for(unsigned bit=1;bit<=2;bit<<=1) {
        const uint32_t vmid=bit==1?3:15;
        if(from&bit)msPut(p+64+4*sources++,vmid,4);
        if(to&bit) {
            msPut(p+128+24*destinations,vmid,4);
            msPut(p+132+24*destinations,bit==1&&to!=3?7:6,4);++destinations;
        }
    }
    // SCM64 extended arguments3..9, separate64-byte aligned DMA records.
    msPut(p+192,sources*4,8);msPut(p+200,scratch+128,8);msPut(p+208,destinations*24,8);
    __asm__ volatile("dsb sy":::"memory");
    const uint32_t types=7u|(QCOM_SCM_RO<<4)|(QCOM_SCM_RO<<8)|(QCOM_SCM_RO<<12);
    const Result result=scmCall(0x0c,0x16,types,scratch,16,scratch+64,scratch+192);
    work.close();
    IOLog("PongModem: actual memory ownership %u->%u bytes=%u SCM=%lld/%llx\n",from,to,bytes,result.status,result.result);
    return ok(result);
}
bool memshareTransfer(bool toModem) {
    const bool result=modemAssignPages(memshare.physical,memshare.bytes,toModem?1:2,toModem?2:1);
    if(!result){memshare.quarantined=true;return false;}
    memshare.modem=toModem;return true;
}
bool memshareAllocate(uint32_t bytes,uint32_t node,uint32_t port) {
    if(memshare.quarantined||!bytes||bytes>MemshareMaximum)return false;
    if(memshare.memory)return memshare.modem&&bytes==memshare.bytes&&node==memshare.node&&port==memshare.port;
    const uint32_t rounded=(bytes+4095u)&~4095u;
    auto *memory=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
        IOOptionBits(kIODirectionInOut)|IOOptionBits(kIOMemoryHostPhysicallyContiguous),rounded,4096);
    if(!memory)return false;
    if(memory->prepare()!=kIOReturnSuccess){memory->release();return false;}
    IOByteCount span=0;const uint64_t physical=memory->getPhysicalSegment(0,&span,kIOMemoryMapperNone);
    if(!physical||(physical&4095)||span<rounded||physical+rounded>(1ULL<<36)) {
        memory->complete();memory->release();return false;
    }
    auto *address=static_cast<uint8_t *>(memory->getBytesNoCopy());bzero(address,rounded);
    // Cached AP writes must reach PoC before ownership leaves HLOS. Never
    // touch or release these pages again until secure reassignment succeeds.
    for(uint32_t offset=0;offset<rounded;offset+=64)
        __asm__ volatile("dc cvac,%0"::"r"(address+offset):"memory");
    __asm__ volatile("dsb sy":::"memory");
    memshare.memory=memory;memshare.physical=physical;memshare.bytes=bytes;memshare.node=node;memshare.port=port;
    return memshareTransfer(true);
}
uint32_t memshareAnswer(uint32_t node,uint32_t port,const uint8_t *request,uint32_t bytes,uint8_t *out,uint32_t capacity) {
    QcomQmiMessage m{};
    if(qcom_qmi_parse(request,bytes,&m)||m.type!=QCOM_QMI_REQUEST||capacity<64)return 0;
    uint16_t error=0;uint32_t client=~0u,processor=0,sequence=0,wanted=0;
    bool allocated=false,query=false;
    if(m.message==0x24) {
        query=true;
        if(!msValue(m,1,client)||!msValue(m,0x10,processor,true)||client>2||processor)error=48;
    } else if(m.message==0x22) {
        uint32_t alignment=0;
        if(!msValue(m,1,wanted)||!msValue(m,2,client)||!msValue(m,3,processor)||
           !msValue(m,4,sequence)||!msValue(m,0x11,alignment,true)||alignment>11||client!=1||processor)error=48;
        else if(!memshareAllocate(wanted,node,port))error=2;
        else allocated=true;
    } else if(m.message==0x23) {
        uint32_t length=0;const auto *extent=qcom_qmi_tlv(&m,1,&length);
        if(!msValue(m,0x10,client,true)||!msValue(m,0x11,processor,true)||processor||
           (client!=~0u&&client!=1)||!extent||length!=13||extent[0]!=1||
           !memshare.memory||!memshare.modem||memshare.quarantined||
           memshare.node!=node||memshare.port!=port||ms64(extent+1)!=memshare.physical||ms32(extent+9)!=memshare.bytes)error=48;
        else if(!memshareTransfer(false))error=3;
        else {
            memshare.memory->complete();memshare.memory->release();memshare={};
        }
    } else error=71;
    out[0]=QCOM_QMI_RESPONSE;msPut(out+1,m.transaction,2);msPut(out+3,m.message,2);
    out[7]=2;msPut(out+8,4,2);msPut(out+10,error?1:0,2);msPut(out+12,error,2);uint32_t used=14;
    if(!error&&query){out[used++]=0x10;msPut(out+used,4,2);used+=2;msPut(out+used,client==1?MemshareMaximum:0,4);used+=4;}
    if(allocated) {
        out[used++]=0x10;msPut(out+used,4,2);used+=2;msPut(out+used,sequence,4);used+=4;
        out[used++]=0x11;msPut(out+used,13,2);used+=2;out[used++]=1;
        msPut(out+used,memshare.physical,8);used+=8;msPut(out+used,memshare.bytes,4);used+=4;
    }
    msPut(out+5,used-7,2);
    IOLog("PongModem: memshare request=%x client=%u bytes=%u result=%u\n",m.message,client,wanted,error);
    return used;
}
