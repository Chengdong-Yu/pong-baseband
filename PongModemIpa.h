/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Cape IPA5.1 prerequisites. IP0 is a BCM frequency resource, not an ARC
 * level: its native eight-byte aux record supplies kHz per vote unit.
 * NothingOSS clk-rpmh.c and ipa_v3/ipa.c use this clock and a separate
 * SMP2P clock-query response. This does not assert GSI/INIT_COMPLETE.
 */
struct IpaClockOwner {
    uint32_t address=0,unitKhz=0,vote=0;
    bool held=false;
    bool firmware=false;
    int firmware_error=0;
    uint32_t gsi_status=0;
    bool resources=false;
} ipaClock;
bool ipaResourcesPrepare() {
    if(ipaClock.resources)return true;
    if(!ipaClock.held||!ipaClock.firmware)return false;
    Window regs;if(!regs.open(0x03f40000,0x20000))return false;
    auto read=[&](unsigned offset){const uint32_t v=*reinterpret_cast<volatile uint32_t *>(regs.va+offset);__asm__ volatile("dmb oshld":::"memory");return v;};
    auto write=[&](unsigned offset,uint32_t value){
        uint32_t reg;const auto address=reinterpret_cast<uintptr_t>(regs.va+offset);
        __asm__ volatile("mov %w0,%w1\n\tstr %w0,[%2]\n\tdsb sy":"=&r"(reg):"r"(value),"r"(address):"memory");
    };
    if(!read(0x28)||read(0x28)==UINT32_MAX){regs.close();return false;}
    // Native ipa3_init_hw applies these on real IPA5.1 too (unlike the
    // secure firmware-owned global GSI mapping/configuration). Keep the
    // actual reset/readback values outside each documented field.
    const uint32_t comp=read(0x2c)|0x180u;
    write(0x2c,comp);
    // The actual original IPA_5_1 QMB records are zero initialized;
    // ipa3_cfg_qsb writes those field encodings (not IPA4.2's12/8).
    const uint32_t qsbWrites=read(0x54)&~0xffu;
    const uint32_t qsbReads=read(0x58)&~0xffff00ffu;
    write(0x54,qsbWrites);write(0x58,qsbReads);
    const uint32_t timestamp=(read(0x4ac)&~0x1f1f9fu)|14u|0x80u|(14u<<8)|(24u<<16);
    write(0x4ac,timestamp);
    const uint32_t gran=(read(0x4b4)&~0xfffu)|3u|(4u<<3)|(5u<<6)|(5u<<9);
    write(0x4b4,gran);
    const uint32_t divider=read(0x4b0);
    if(divider&(1u<<31))write(0x4b0,divider&~(1u<<31));
    write(0x4b0,divider|(1u<<31));
    if(read(0x2c)!=comp||read(0x54)!=qsbWrites||read(0x58)!=qsbReads||
       read(0x4ac)!=timestamp||read(0x4b4)!=gran||!(read(0x4b0)&(1u<<31))) {
        regs.close();IOLog("PongModem IPA5.1: native QMB/timer prerequisite readback failed\n");return false;
    }
    // This runs before PAS4 starts MPSS and before any AP channel is
    // allocated. Actual NothingOSS IPA_5_1 tables, never Coachz4.2.
    // Preserve reserved register bits; supply the resource budgets without
    // which GSI may fetch a command but IPA cannot allocate its context.
    static const uint8_t src[5][6][2]={
        {{7,12},{0,0},{0,0},{0,0},{1,63},{0,63}},
        {{21,21},{0,0},{0,0},{0,0},{10,10},{0,0}},
        {{33,33},{0,0},{0,0},{0,0},{20,20},{0,0}},
        {{0,63},{0,0},{0,63},{0,63},{1,63},{0,63}},
        {{38,38},{0,0},{0,0},{0,0},{16,16},{0,0}}};
    static const uint8_t dst[3][8][2]={
        {{6,6},{5,5},{0,0},{0,0},{0,0},{0,0},{39,39},{0,0}},
        {{0,3},{0,3},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}},
        {{0,63},{0,63},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}}};
    bool ready=true;
    for(unsigned direction=0;direction<2&&ready;direction++) {
        const unsigned types=direction?3:5,pairs=direction?4:3;
        for(unsigned t=0;t<types&&ready;t++)for(unsigned pair=0;pair<pairs;pair++) {
            const auto *x=direction?dst[t][pair*2]:src[t][pair*2];
            const auto *y=direction?dst[t][pair*2+1]:src[t][pair*2+1];
            const unsigned offset=(direction?0x600:0x500)+t*0x20+pair*4;
            const uint32_t fields=x[0]|(uint32_t(x[1])<<8)|(uint32_t(y[0])<<16)|(uint32_t(y[1])<<24);
            const uint32_t value=(read(offset)&~0x3f3f3f3fu)|fields;
            write(offset,value);
            if(read(offset)!=value){ready=false;break;}
        }
    }
    if(ready) {
        // Native IPA_5_1 resource policy: special source group4,
        // destination specials disabled, second-priority source group1.
        // The original HAL's EXT valid mask is zero; preserve that bit
        // rather than invent an enable encoding absent from the source.
        const uint32_t config=(read(0x6a0)&~0x3f1ff171u)|0x41u;
        write(0x6a0,config);ready=read(0x6a0)==config;
        if(ready) {
            const uint32_t ext=(read(0x6a4)&~0x70u)|0x10u;
            write(0x6a4,ext);ready=read(0x6a4)==ext;
        }
    }
    const uint32_t contexts=read(0x500),descriptors=read(0x520),buffers=read(0x540);
    regs.close();ipaClock.resources=ready;
    IOLog("PongModem IPA5.1: actual pre-MPSS resource tables ready=%u contexts=%x descriptors=%x buffers=%x\n",ready,contexts,descriptors,buffers);
    return ready;
}
bool ipaClockPrepare() {
    if(ipaClock.held)return true;
    Window window;if(!window.open(0x80860000,0x20000))return false;
    auto *db=static_cast<uint8_t *>(IOMallocData(0x20000));
    if(!db){window.close();return false;}
    for(unsigned n=0;n<0x20000;n+=4) {
        const uint32_t word=*reinterpret_cast<volatile uint32_t *>(window.va+n);memcpy(db+n,&word,4);
    }
    window.close();
    bool found=false;
    if(ms32(db+4)==QCOM_CMD_DB_MAGIC)for(unsigned s=0;s<8&&!found;s++) {
        const auto *slave=db+8+16*s;
        if(!ms16(slave))break;
        const uint32_t head=144+ms16(slave+2),data=144+ms16(slave+4),count=ms16(slave+6);
        if(head>0x20000||count>(0x20000-head)/24)break;
        for(unsigned n=0;n<count;n++) {
            const auto *entry=db+head+24*n;
            if(memcmp(entry,"IP0\0\0\0\0\0",8))continue;
            const uint32_t bytes=ms16(entry+20),aux=data+ms16(entry+22);
            if(bytes!=8||aux>0x20000||bytes>0x20000-aux)break;
            ipaClock.address=ms32(entry+16);ipaClock.unitKhz=ms32(db+aux);
            found=ipaClock.address&&ipaClock.unitKhz&&ipaClock.unitKhz<=120000;break;
        }
    }
    IOFreeData(db,0x20000);
    if(!found){IOLog("PongModem IPA5.1: native IP0 BCM record unavailable; clock not enabled\n");return false;}
    // Native IPA5.x boot SVS2=120MHz. BCM commit/valid bits30/29;
    // x=0, y=frequency/aux_unit, capped by the actual14-bit vote ABI.
    const uint32_t units=(120000+ipaClock.unitKhz-1)/ipaClock.unitKhz;
    if(!units||units>0x3fff)return false;
    ipaClock.vote=(1u<<30)|(1u<<29)|units;
    ipaClock.held=pong_rpmh_vote(ipaClock.address,ipaClock.vote);
    IOLog("PongModem IPA5.1: actual IP0 address=%x unit_khz=%u vote=%x ACK=%u; GSI not started\n",
        ipaClock.address,ipaClock.unitKhz,ipaClock.vote,ipaClock.held);
    return ipaClock.held;
}
bool ipaClockQuery(void *) {
    // A retained, acknowledged real RPMh vote is the answer. Do not infer
    // clock or datapath state from modem ready, a static DT or an elapsed timer.
    return ipaClock.held;
}
int ipaRead(void *file,uint64_t offset,void *to,size_t bytes) {
    return sheng_fw_read(file,offset,to,bytes);
}
bool ipaFirmwareStart(uint64_t metadataPa,size_t modemMetadataBytes) {
    if(ipaClock.firmware)return true;
    if(!ipaClock.held||modemMetadataBytes>0xe000){ipaClock.firmware_error=EBUSY;return false;}
    constexpr uint64_t base=0x8b900000,bytes=0x10000;
    if(gPhysBase<base+bytes&&base<gPhysBase+gPhysSize){ipaClock.firmware_error=EBUSY;return false;}
    // IPA5.1 uses GSI3.0, not the Coachz1.x or IPA5.0/GSI2.9 layout.
    // Refuse an already enabled foreign manager before touching its firmware.
    Window gsi;if(!gsi.open(0x03e04000,0xfc000)){ipaClock.firmware_error=ENOMEM;return false;}
    ipaClock.gsi_status=*reinterpret_cast<volatile uint32_t *>(gsi.va+0x25000);gsi.close();
    if(ipaClock.gsi_status==UINT32_MAX||(ipaClock.gsi_status&1)) {
        ipaClock.firmware_error=EBUSY;
        IOLog("PongModem IPA5.1: GSI3.0 foreign enabled/status=%x; no firmware overwrite\n",ipaClock.gsi_status);return false;
    }
    // NothingOSS ipa.c9438: IPA3.1+ hardware delegates global GSI
    // configuration to TZ. gsi_configure_regs is only for IPA3.0 or
    // emulation; gsi_enable_fw belongs to the manual/emulation loader.
    // Pong uses signed PAS15/MDT, so never read/write those global banks.
    void *file=nullptr;uint64_t size=0;
    int error=sheng_fw_open("/pong/firmware/ipa_fws.mbn",&file,&size);
    if(error){ipaClock.firmware_error=error;return false;}
    auto *image=static_cast<QcomMdtImage *>(IOMallocData(sizeof(QcomMdtImage)));
    Window metadata,firmware;
    if(!image)error=ENOMEM;
    if(!error)error=qcom_mdt_parse(image,size,ipaRead,file);
    if(!error&&(image->elf64||!image->relocatable||image->min_address||qcom_mdt_span(image)>bytes||
       qcom_mdt_metadata_size(image)>0x2000))error=EINVAL;
    // Last8KiB of the existing boot-owned metadata lease: disjoint from
    // this actual MPSS image's metadata, never a guessed CMA address.
    if(!error&&!metadata.open(metadataPa+0xe000,0x2000,kIOMapWriteCombineCache))error=ENOMEM;
    if(!error)error=qcom_mdt_metadata(image,ipaRead,file,const_cast<uint8_t *>(metadata.va),0x2000);
    if(!error) {
        __asm__ volatile("dsb sy":::"memory");
        if(!ok(scm(QCOM_SCM_PAS_INIT_IMAGE,qcom_scm_args(2,QCOM_SCM_VAL,QCOM_SCM_RW,0),15,metadataPa+0xe000)))error=EIO;
    }
    if(!error&&!ok(scm(QCOM_SCM_PAS_MEM_SETUP,qcom_scm_args(3,0,0,0),15,base,qcom_mdt_span(image))))error=EIO;
    if(!error&&!firmware.open(base,bytes,kIOMapWriteCombineCache))error=ENOMEM;
    if(!error) {
        auto *data=const_cast<uint8_t *>(firmware.va);bzero(data,bytes);
        for(unsigned n=0;n<image->count&&!error;n++) {
            const auto &segment=image->segment[n];if(!segment.load)continue;
            uint64_t offset=0;error=qcom_mdt_place(image,n,base,bytes,&offset);
            if(!error&&segment.file_size)error=ipaRead(file,segment.file_offset,data+offset,size_t(segment.file_size));
        }
        __asm__ volatile("dsb sy":::"memory");
        if(!error&&!ok(scm(QCOM_SCM_PAS_AUTH_AND_RESET,qcom_scm_args(1,0,0,0),15)))error=EIO;
    }
    firmware.close();metadata.close();if(image)IOFreeData(image,sizeof(QcomMdtImage));sheng_fw_close(file);
    ipaClock.firmware_error=error;ipaClock.firmware=!error;
    Window observed;
    if(!error&&observed.open(0x03e04000+0x25000,0x1000)) {
        ipaClock.gsi_status=*reinterpret_cast<volatile uint32_t *>(observed.va);
        __asm__ volatile("dmb oshld":::"memory");observed.close();
    }
    IOLog("PongModem IPA5.1: TZ-owned GSI3.0 global configuration retained; actual EE0 status=%x; DMA channels/QMI initialization pending\n",ipaClock.gsi_status);
    IOLog("PongModem IPA5.1: actual Pong PAS15 signed firmware authenticated=%u error=%d; GSI channels/QMI INIT_COMPLETE not inferred\n",
        ipaClock.firmware,error);
    return ipaClock.firmware;
}
