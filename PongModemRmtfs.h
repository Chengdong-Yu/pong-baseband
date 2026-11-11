/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * RMTFS QMI v1, standard service14/instance0. Same request layout as
 * linux-msm/rmtfs. Native UFS reads the current original NV partitions;
 * writes are retained in a bounded boot-session shadow, never issued
 * to Android's factory NV partitions. No NV or device identities in Git.
 */
constexpr uint32_t RmtfsPort=0x102,RmtfsBytes=0x280000;
extern "C" int pong_ufs_factory_nv(unsigned,uint64_t,void *,uint32_t,uint64_t *) __attribute__((weak_import));
struct RmtfsStorage {const char *path,*file;uint8_t *shadow=nullptr;uint32_t bytes=0,node=0;bool open=false;};
RmtfsStorage rmtfsStorage[]={
    {"/boot/modem_fs1","/pong/firmware/efs/modemst1.bin"},
    {"/boot/modem_fs2","/pong/firmware/efs/modemst2.bin"},
    {"/boot/modem_fsg","/pong/firmware/efs/fsg.bin"},
    {"/boot/modem_fsc","/pong/firmware/efs/fsc.bin"},
};
IOMemoryMap *rmtfsMapping;
uint8_t *rmtfsAddress;
uint64_t rmtfsPhysical;
uint32_t rmtfsNode,rmtfsRequests;
bool rmtfsShared,rmtfsQuarantined;
bool rmtfsDma(uint32_t node,uint32_t bytes) {
    if(!bytes||bytes>RmtfsBytes||rmtfsQuarantined)return false;
    if(rmtfsMapping)return rmtfsShared&&rmtfsNode==node;
    // IOVEC is32-bit. The active XNU allocator has no suitable low-memory
    // 640-page run (213 scanned only1-2 pages). Reserve it in UEFI before
    // XNU starts; never report a guessed CMA extent or truncate a high PA.
    uint64_t pa=0;
    if(!PongLowDma::rmtfsAddress(pa)){IOLog("PongModem: no real UEFI RMTFS low32 lease\n");return false;}
    auto *memory=IODeviceMemory::withRange(pa,RmtfsBytes);
    auto *mapping=memory?memory->map(kIOMapAnywhere|kIOMapWriteCombineCache):nullptr;
    if(memory)memory->release();
    if(!mapping)return false;
    auto *address=reinterpret_cast<uint8_t *>(mapping->getVirtualAddress());bzero(address,RmtfsBytes);
    for(uint32_t i=0;i<RmtfsBytes;i+=64)__asm__ volatile("dc civac,%0"::"r"(address+i):"memory");
    __asm__ volatile("dsb sy":::"memory");
    rmtfsMapping=mapping;rmtfsAddress=address;rmtfsPhysical=pa;rmtfsNode=node;
    rmtfsShared=modemAssignPages(pa,RmtfsBytes,1,3);
    if(!rmtfsShared)rmtfsQuarantined=true; // no release after uncertain secure ownership
    return rmtfsShared;
}
bool rmtfsLoad(RmtfsStorage &storage) {
    if(storage.shadow)return true;
    if(pong_ufs_factory_nv) {
        const unsigned slot=unsigned(&storage-rmtfsStorage);uint64_t bytes=0;
        int error=pong_ufs_factory_nv(slot,0,nullptr,0,&bytes);
        if(error||!bytes||bytes>4*1024*1024||bytes%512) {
            IOLog("PongModem: actual factory NV source unavailable slot=%u errno=%d; stale snapshot not substituted\n",slot,error);
            return false;
        }
        auto *shadow=static_cast<uint8_t *>(IOMallocData(bytes));if(!shadow)return false;
        for(uint64_t done=0;done<bytes;) {
            const uint32_t count=uint32_t(bytes-done>128*1024?128*1024:bytes-done);
            uint64_t observed=0;error=pong_ufs_factory_nv(slot,done,shadow+done,count,&observed);
            if(!error&&observed!=bytes)error=EIO;
            if(error)break;
            done+=count;
        }
        if(error){IOFreeData(shadow,bytes);return false;}
        storage.shadow=shadow;storage.bytes=uint32_t(bytes);
        IOLog("PongModem: RMTFS loaded current original UFS NV slot=%u bytes=%u; modem writes stay in RAM\n",slot,storage.bytes);
        return true;
    }
    // Compatibility for builds without the native UFS aggregate only.
    // An available physical backend's failure never falls back to a stale
    // host export, so its missing dependency stays a real modem error.
    void *file=nullptr;uint64_t bytes=0;
    const int opened=sheng_fw_open(storage.file,&file,&bytes);
    if(opened){IOLog("PongModem: RMTFS actual NV snapshot open failed errno=%d\n",opened);return false;}
    if(!bytes||bytes>4*1024*1024||bytes%512){sheng_fw_close(file);return false;}
    auto *shadow=static_cast<uint8_t *>(IOMallocData(bytes));
    bool loaded=shadow!=nullptr;
    // The firmware reader deliberately bounds each request to1MiB. NV
    // snapshots may be several MiB; respect the same bound as MPSS loading.
    for(uint64_t done=0;loaded&&done<bytes;) {
        const size_t count=size_t(bytes-done>1024*1024?1024*1024:bytes-done);
        const int error=sheng_fw_read(file,done,shadow+done,count);
        if(error){IOLog("PongModem: RMTFS actual NV snapshot read failed errno=%d\n",error);loaded=false;}
        done+=count;
    }
    sheng_fw_close(file);
    if(!loaded){if(shadow)IOFreeData(shadow,bytes);return false;}
    storage.shadow=shadow;storage.bytes=uint32_t(bytes);return true;
}
uint32_t rmtfsAnswer(uint32_t node,const uint8_t *request,uint32_t bytes,uint8_t *out,uint32_t capacity) {
    QcomQmiMessage m{};
    if(qcom_qmi_parse(request,bytes,&m)||m.type!=QCOM_QMI_REQUEST||capacity<32)return 0;
    uint16_t error=0;uint32_t id=0,value=0,fieldBytes=0;unsigned responseBytes=0;
    const uint8_t *field=nullptr;RmtfsStorage *storage=nullptr;
    if(m.message==1) {
        field=qcom_qmi_tlv(&m,1,&fieldBytes);
        if(!field||!fieldBytes||fieldBytes>256)error=2;
        else {
            if(field[fieldBytes-1]==0)--fieldBytes;
            for(unsigned i=0;i<sizeof rmtfsStorage/sizeof *rmtfsStorage;i++)
                if(strlen(rmtfsStorage[i].path)==fieldBytes&&!memcmp(field,rmtfsStorage[i].path,fieldBytes)) {
                    id=i+1;storage=&rmtfsStorage[i];break;
                }
            if(!storage||(storage->open&&storage->node!=node)||!rmtfsLoad(*storage))error=1;
            else {storage->open=true;storage->node=node;value=id;responseBytes=4;}
        }
    } else {
        if(!msValue(m,1,id)||!id||id>sizeof rmtfsStorage/sizeof *rmtfsStorage)error=2;
        else {
            storage=&rmtfsStorage[id-1];
            if(!storage->open||storage->node!=node)error=1;
        }
        if(!error&&m.message==2)storage->open=false;
        else if(!error&&m.message==4) {
            if(!msValue(m,2,value))error=2;
            else if(!rmtfsDma(node,value))error=1;
            else responseBytes=8;
        } else if(!error&&m.message==5){responseBytes=1;value=0;}
        else if(!error&&m.message==3) {
            uint32_t directionBytes=0,forceBytes=0;
            const auto *direction=qcom_qmi_tlv(&m,2,&directionBytes);
            const auto *force=qcom_qmi_tlv(&m,4,&forceBytes);
            field=qcom_qmi_tlv(&m,3,&fieldBytes);
            if(!direction||directionBytes!=1||*direction>1||!force||forceBytes!=1||*force>1||
               !field||!fieldBytes||fieldBytes!=1u+12u*field[0])error=2;
            else if(!rmtfsShared||rmtfsQuarantined||rmtfsNode!=node)error=1;
            // Validate the complete scatter list before any shadow writes.
            for(unsigned i=0;!error&&i<field[0];i++) {
                const auto *v=field+1+12*i;const uint64_t offset=uint64_t(ms32(v))*512,
                    physical=ms32(v+4),length=uint64_t(ms32(v+8))*512;
                if(offset>storage->bytes||length>storage->bytes-offset||physical<rmtfsPhysical||
                   physical-rmtfsPhysical>RmtfsBytes||length>RmtfsBytes-(physical-rmtfsPhysical))error=2;
            }
            for(unsigned i=0;!error&&i<field[0];i++) {
                const auto *v=field+1+12*i;const uint32_t offset=ms32(v)*512,length=ms32(v+8)*512;
                auto *shared=rmtfsAddress+(uint64_t(ms32(v+4))-rmtfsPhysical);
                if(*direction) {
                    // A completed modem request transfers this range to AP.
                    for(uint32_t n=0;n<length;n+=64)__asm__ volatile("dc civac,%0"::"r"(shared+n):"memory");
                    __asm__ volatile("dsb sy":::"memory");memcpy(storage->shadow+offset,shared,length);
                } else {
                    memcpy(shared,storage->shadow+offset,length);
                    for(uint32_t n=0;n<length;n+=64)__asm__ volatile("dc cvac,%0"::"r"(shared+n):"memory");
                    __asm__ volatile("dsb sy":::"memory");
                }
            }
        } else if(!error&&m.message!=2&&m.message!=4&&m.message!=5)error=1;
    }
    out[0]=QCOM_QMI_RESPONSE;msPut(out+1,m.transaction,2);msPut(out+3,m.message,2);
    out[7]=2;msPut(out+8,4,2);msPut(out+10,error?1:0,2);msPut(out+12,error,2);uint32_t used=14;
    if(!error&&responseBytes) {
        out[used++]=0x10;msPut(out+used,responseBytes,2);used+=2;
        msPut(out+used,responseBytes==8?rmtfsPhysical:value,responseBytes);used+=responseBytes;
    }
    msPut(out+5,used-7,2);
    if(++rmtfsRequests<=16||error)IOLog("PongModem: actual RMTFS request=%u caller=%u result=%u; NV writes remain in boot-session shadow\n",m.message,id,error);
    return used;
}
