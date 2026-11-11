/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Pong IPA5.1 AP command DMA owner; GSI3.0 EE0, command endpoint14/channel12.
 * Facts: NothingOSS ipa-utils.c/gsi.c/gsihal-reg.c, matching SM8475 DT.
 * The global GSI registers remain TZ-owned. No identity mappings of all
 * DRAM, foreign stream reset, invented completion or packet success.
 * Retain descriptor/table/ring ownership after every uncertain command.
 */
#include "../PongAdreno/ArmSmmu4K/ArmSmmu4KProgram.h"
#include "../NativeUfs/SmmuTakeover.h"
struct IpaCommandDma {
    Window gsi,smmu,registers;
    IOBufferMemoryDescriptor *memory=nullptr,*tables=nullptr;
    uint8_t *cpu=nullptr;uint64_t physical=0,tablePhysical=0;
    uint32_t stage=0,bank=~0u,channelState=0;int error=0;
    bool attempted=false;
    bool pending=false;
    uint32_t producer=0,eventRead=0,lastTre=0,completedCommands=0,lastEvent=0;
    uint32_t restricted=0,sramBytes=0;
    uint32_t failureRegs[16]{};
    uint64_t deadline=0;
    static constexpr uint64_t Iova=0x20000000;
    static constexpr unsigned Bytes=0x100000,TableBytes=0x8000;
    uint32_t read(const Window &window,unsigned offset)const {
        uint32_t value=*reinterpret_cast<volatile uint32_t *>(window.va+offset);
        __asm__ volatile("dmb oshld":::"memory");return value;
    }
    void write(Window &window,unsigned offset,uint32_t value) {
        uint32_t reg;const auto address=reinterpret_cast<uintptr_t>(window.va+offset);
        __asm__ volatile("mov %w0,%w1\n\tstr %w0,[%2]\n\tdsb sy":"=&r"(reg):"r"(value),"r"(address):"memory");
    }
    static void clean(const void *cpu,size_t bytes) {
        const auto end=reinterpret_cast<uintptr_t>(cpu)+bytes;
        for(auto p=reinterpret_cast<uintptr_t>(cpu)&~uintptr_t(63);p<end;p+=64)
            __asm__ volatile("dc civac,%0"::"r"(p):"memory");
        __asm__ volatile("dsb sy":::"memory");
    }
    static IOBufferMemoryDescriptor *allocate(unsigned bytes,uint64_t &physical) {
        auto *memory=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
            IOOptionBits(kIODirectionInOut)|IOOptionBits(kIOMemoryPhysicallyContiguous)|IOOptionBits(kIOMemoryMapperNone),bytes,4096);
        if(!memory)return nullptr;
        IOByteCount span=0;physical=memory->getPhysicalSegment(0,&span,kIOMemoryMapperNone);
        if(!physical||(physical&4095)||span<bytes||physical>=(1ull<<36)||bytes>(1ull<<36)-physical){memory->release();return nullptr;}
        bzero(memory->getBytesNoCopy(),bytes);clean(memory->getBytesNoCopy(),bytes);return memory;
    }
    bool fail(int value,const char *phase) {
        error=value;IOLog("PongModem IPA DMA: phase=%s stage=%u error=%d; actual resources retained, normal boot continues\n",phase,stage,error);return false;
    }
    bool ownedEvents(uint32_t events) {
        // Native gsi_register_device enables the EE-local interrupt types
        // before ALLOCATE. A polled owner still must arm/ack its actual
        // sources; disabling the physical GIC line is not a substitute for
        // configuring the GSI completion engine. Never clear foreign rings.
        write(gsi,0x25220,1);
        write(gsi,0x25088,read(gsi,0x25088)|0x4cu);
        write(gsi,0x25204,read(gsi,0x25204)|1u);
        // Native policy excludes the debug breakpoint source (bit0).
        write(gsi,0x25210,read(gsi,0x25210)|0xeu);
        write(gsi,0x250ac,read(gsi,0x250ac)|events);
        if(read(gsi,0x25220)!=1||(read(gsi,0x25088)&0x4cu)!=0x4cu||
           !(read(gsi,0x25204)&1u)||(read(gsi,0x25210)&0xeu)!=0xeu||
           (read(gsi,0x250ac)&events)!=events)
            return fail(EIO,"owned EE interrupt source readback");
        IOLog("PongModem IPA DMA: actual EE0 event sources armed type=%x EOB_mask=%x global=%x general=%x; completion still requires real DMA event\n",
            read(gsi,0x25088),read(gsi,0x250ac),read(gsi,0x25204),read(gsi,0x25210));
        return true;
    }
    bool pollOwnedEvents(uint32_t events) {
        const uint32_t global=read(gsi,0x25200),general=read(gsi,0x2520c);
        if((global&1u)||(general&0xeu)) {
            IOLog("PongModem IPA DMA: actual EE-local error global=%x general=%x log=%x; no completion substituted\n",global,general,read(gsi,0x25240));
            return fail(EIO,"real GSI error source");
        }
        const uint32_t pending=read(gsi,0x250a8)&events;
        if(pending)write(gsi,0x250b0,pending);
        return true;
    }
    bool setupSmmu() {
        if(!smmu.open(0x15000000,0x100000))return fail(ENOMEM,"SMMU map");
        if(!pong_smmu_lease_lock())return fail(EBUSY,"SMMU lease");
        struct Lease {~Lease(){pong_smmu_lease_unlock();}} lease;
        auto read=[&](unsigned offset){return this->read(smmu,offset);};
        const auto plan=planUfsSmmu(0x5c0,Iova,Bytes,read,78,120);
        if(plan.error)return fail(EBUSY,plan.error);
        bank=plan.bank;
        uint32_t smemOffset=0,smemLength=0;
        if(qcom_smem_find(&smem,&part,497,&smemOffset,&smemLength)||smemLength<0x9000||
            smemOffset>SmemBytes||0x9000>SmemBytes-smemOffset)
            return fail(ENOENT,"native IPA filter SMEM497 ownership");
        const uint64_t smemAddress=SmemBase+smemOffset,smemStart=smemAddress&~uint64_t(4095);
        const uint64_t smemEnd=(smemAddress+0x9000+4095)&~uint64_t(4095),smemSize=smemEnd-smemStart;
        // Exact original DT additional-mapping, not a broad bypass.274's
        // real TF at0x146a9080 falls inside this required two-page region.
        // Native IOMMU_MMIO means Device-nGnRE; SMEM is normal NC.
        const ArmSmmu4KRange ranges[]={
            {0x146a8000,0x146a8000,0x2000,3,2,2},
            {Iova,physical,Bytes,3,1,3},
            {smemStart,smemStart,smemSize,3,0,2}};
        ArmSmmu4KConfig config={32,36,tablePhysical,size_t((Bytes+0x2000+smemSize)/4096)};
        ArmSmmu4KResult built={};
        if(ArmSmmu4KBuild(&config,ranges,3,static_cast<uint64_t *>(tables->getBytesNoCopy()),TableBytes/4096,&built)!=ArmSmmu4KSuccess)
            return fail(EINVAL,"native4K table");
        clean(tables->getBytesNoCopy(),built.table_pages*4096);
        ArmSmmu4KContextConfig context={};context.lower=&config;context.lower_tables=&built;
        context.id0=read(0x20);context.id2=read(0x28);context.asid=0x5c0;context.coherent_walk=1;
        context.polled_faults=1;context.ignore_top_byte=1;context.shared_asid=1;
        ArmSmmu4KIo io={this,0x100000,
            [](void *p,size_t offset,uint32_t *value){auto *s=static_cast<IpaCommandDma *>(p);*value=s->read(s->smmu,unsigned(offset));return 0;},
            [](void *p,size_t offset,uint64_t *value){auto *s=static_cast<IpaCommandDma *>(p);*value=*reinterpret_cast<volatile uint64_t *>(s->smmu.va+offset);return 0;},
            [](void *p,size_t offset,uint32_t value){auto *s=static_cast<IpaCommandDma *>(p);s->write(s->smmu,unsigned(offset),value);return 0;},
            [](void *p,size_t offset,uint64_t value){auto *s=static_cast<IpaCommandDma *>(p);*reinterpret_cast<volatile uint64_t *>(s->smmu.va+offset)=value;__asm__ volatile("dsb sy":::"memory");return 0;},
            [](void *){__asm__ volatile("dsb sy":::"memory");return 0;},1};
        ArmSmmu4KProgramResult programmed={};
        const auto result=ArmSmmu4KProgramDisabledContext(&io,bank,&context,20000,&programmed);
        if(result!=ArmSmmu4KSuccess) {
            IOLog("PongModem IPA DMA: actual SMMU result=%u phase=%u FSR=%x TCR=%x TCR2=%x SCTLR=%x\n",unsigned(result),programmed.phase,programmed.fault_status,programmed.readback.tcr,programmed.readback.tcr2,programmed.readback.sctlr);
            return fail(EIO,"SMMU program");
        }
        write(smmu,0xc00+4*plan.slot,bank);
        if(!plan.migrate&&!plan.reuse)write(smmu,0x800+4*plan.slot,0x800005c0);
        if(read(0xc00+4*plan.slot)!=bank||read(0x800+4*plan.slot)!=0x800005c0)return fail(EIO,"SID5c0 readback");
        IOLog("PongModem IPA DMA: actual DT additional MMIO146a8000/2000 and SMEM497=%llx/%x mapped with bounded native4K leaves=%lu; no global bypass\n",
            smemAddress,0x9000,(unsigned long)built.leaf_pages);
        stage=2;return true;
    }
    bool command(bool event,unsigned id,unsigned opcode,unsigned expected) {
        const unsigned offset=event?0x1c000+id*0x80:0x14000+id*0x80;
        if(opcode==0&&((read(gsi,offset)>>20)&15))return fail(EBUSY,"foreign GSI resource");
        // Mirror native GSI command-control acknowledgement even though
        // this owner polls. Clear/mask only this allocated resource; stale
        // completion mailbox bits must not survive ALLOCATE -> START.
        const unsigned source=event?0x2509c:0x25090,mask=event?0x250a0:0x25094,clear=event?0x250a4:0x25098;
        const uint32_t bit=1u<<id,oldMask=read(gsi,mask),oldType=read(gsi,0x25088),type=event?2u:1u;
        write(gsi,clear,bit);write(gsi,mask,oldMask|bit);write(gsi,0x25088,oldType|type);
        write(gsi,event?0x25010:0x25008,id|(opcode<<24));
        const auto end=nowMs()+50;
        bool done=false;unsigned actual=0;
        do {
            actual=(read(gsi,offset)>>20)&15;
            if(actual==expected){if(!event)channelState=actual;done=true;break;}
            if(actual==15)break;
            IODelay(10);
        }while(nowMs()<end);
        if(read(gsi,source)&bit)write(gsi,clear,bit);
        write(gsi,mask,oldMask);write(gsi,0x25088,oldType);
        return done||fail(actual==15?EIO:ETIMEDOUT,event?"event command":"channel command");
    }
    struct Immediate {uint16_t opcode;uint8_t bytes;uint8_t payload[24];};
    static void le16(uint8_t *p,uint16_t v){p[0]=v;p[1]=v>>8;}
    static void le32(uint8_t *p,uint32_t v){le16(p,v);le16(p+2,v>>16);}
    static void le64(uint8_t *p,uint64_t v){le32(p,uint32_t(v));le32(p+4,uint32_t(v>>32));}
    static uint32_t from32(const uint8_t *p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
    static uint64_t from64(const uint8_t *p){return from32(p)|(uint64_t(from32(p+4))<<32);}
    bool submit(const Immediate *commands,unsigned count) {
        // Bounded batches fit the owned256-TRE ring/payload slots and
        // remain below the native command endpoint's20 interface TLVs.
        if(pending||!count||count>8||stage<4||error)return false;
        // Each ring index owns a separate payload slot until its actual
        // completion. One bounded outstanding batch, never timer credits.
        for(unsigned i=0;i<count;i++) {
            const unsigned index=(producer+i)&255;
            auto *payload=cpu+0x20000+index*32;
            auto *tre=cpu+index*16;
            if(!commands[i].bytes||commands[i].bytes>24)return fail(EINVAL,"immediate payload extent");
            bzero(payload,32);memcpy(payload,commands[i].payload,commands[i].bytes);
            bzero(tre,16);le64(tre,Iova+0x20000+index*32);le16(tre+8,commands[i].opcode);
            le32(tre+12,(3u<<16)|(i+1==count?0x600u:1u));
            clean(payload,32);clean(tre,16);
        }
        lastTre=(producer+count-1)&255;producer=(producer+count)&255;
        pending=true;deadline=nowMs()+1000;
        write(gsi,0x24000+12*8+4,0);
        write(gsi,0x24000+12*8,uint32_t(Iova+producer*16));
        return true;
    }
    bool completion() {
        if(!pollOwnedEvents(1))return false;
        // Pong's real DT selects ipa-gpi-event-rp-ddr. The firmware writes
        // this owned shadow on event generation; do not rely solely on
        // MMIO context snapshots for the GSI3.0 producer pointer.
        clean(cpu+0x18000,64);
        const auto ptr=from64(cpu+0x18000);
        const uint64_t base=Iova+0x10000;
        if(ptr<base||ptr>=base+4096||((ptr-base)&15))return fail(EIO,"event producer extent");
        const unsigned index=unsigned(ptr-base)/16;
        unsigned visited=0;bool done=false;
        while(eventRead!=index&&visited++<256) {
            const auto *event=cpu+0x10000+eventRead*16;
            // Event pages were cleaned before handing ownership to GSI;
            // the CPU never writes them after that handoff.
            clean(event,16);
            const uint64_t tre=from64(event);lastEvent=event[11];
            if(event[15]!=12||tre<Iova||tre>=Iova+4096||((tre-Iova)&15))
                return fail(EIO,"foreign/malformed command event");
            if(lastEvent!=1&&lastEvent!=2)return fail(EIO,"command completion error");
            if(unsigned(tre-Iova)/16==lastTre)done=true;
            eventRead=(eventRead+1)&255;
        }
        if(visited) {
            write(gsi,0x24804,0);
            write(gsi,0x24800,uint32_t(base+((eventRead+255)&255)*16));
        }
        if(done){pending=false;++completedCommands;return true;}
        if(nowMs()>=deadline) {
            IOLog("PongModem IPA DMA: command pending TRE=%u event_index=%u RP=%llx CH=%x SMMU_FSR=%x; DMA retained\n",
                lastTre,eventRead,ptr,read(gsi,0x14000+12*0x80),read(smmu,0x80000+bank*0x1000+0x58));
            const unsigned ch=0x14000+12*0x80;
            failureRegs[0]=read(gsi,ch+16);failureRegs[1]=read(gsi,ch+24);
            failureRegs[2]=read(gsi,ch+0x40);failureRegs[3]=read(gsi,ch+0x44);
            failureRegs[4]=read(gsi,ch+0x48);failureRegs[5]=read(gsi,0x25240);
            failureRegs[6]=read(gsi,0x25200);failureRegs[7]=read(gsi,0x1c000+16);
            failureRegs[8]=read(smmu,0x80000+bank*0x1000+0x58);
            failureRegs[9]=read(smmu,0x80000+bank*0x1000+0x60);
            failureRegs[10]=read(registers,0x8800+14*4);
            failureRegs[11]=read(registers,0x9000+14*4);
            failureRegs[12]=read(registers,0x9400+14*4);
            failureRegs[13]=read(gsi,0x25080);
            failureRegs[14]=read(gsi,0x25090);
            failureRegs[15]=read(gsi,0x250a8);
            IOLog("PongModem IPA DMA: real command RP=%x WP=%x fetchRP=%x fetchWP=%x QOS=%x ERR=%x GLOBAL=%x\n",
                read(gsi,ch+16),read(gsi,ch+24),read(gsi,ch+0x40),read(gsi,ch+0x44),
                read(gsi,ch+0x48),read(gsi,0x25240),read(gsi,0x25200));
            fail(ETIMEDOUT,"immediate completion");
        }
        return false;
    }
    bool initHeaders() {
        const uint32_t geometry=read(registers,0x40);
        restricted=(geometry>>16)*8;sramBytes=(geometry&0xffff)*8;
        // Cold boot, before INIT_DRIVER transfers SRAM ownership to MPSS.
        // Native ipa_setup_apps_pipes starts with HDR_INIT_LOCAL, not an
        // invented HPS pipeline-clear wait before the tables exist.
        if(sramBytes<0x5000||restricted>0xffff-0x5000)return fail(ENODEV,"IPA5.1 SRAM geometry");
        // Match _ipa_init_sram_v3 on actual IPA5.1: two4-byte canaries
        // immediately before each shared table/header/context, modem
        // memory and PDN region. Do not write the uC shared area0x1000.
        const unsigned guarded[]={0x1288,0x1308,0x1388,0x1408,0x1488,0x1528,
            0x15c8,0x1668,0x1708,0x1b40,0x3898,0x4ee8};
        for(unsigned offset:guarded)for(unsigned back=4;back<=8;back+=4) {
            const unsigned address=0x10000+restricted+offset-back;
            write(registers,address,0xdeadbeefu);
            if(read(registers,address)!=0xdeadbeefu)return fail(EIO,"native SRAM canary readback");
        }
        bzero(cpu+0x30000,0x10000);clean(cpu+0x30000,0x10000);
        Immediate header={9,16,{}};
        le64(header.payload,Iova+0x30000);
        le32(header.payload+8,0x420u|((restricted+0x1708u)<<12));
        if(!submit(&header,1))return false;
        stage=5;return true;
    }
    bool initContexts() {
        // The native HAL points empty headers at its existing local
        // offset0x1000. It does not zero that uC-owned shared area.
        const unsigned offsets[]={0x1b40,0x3898,0x2868,0x4ee8},sizes[]={0xd20,0xd48,0xa48,0x118};
        Immediate commands[4]={};
        for(unsigned i=0;i<4;i++) {
            commands[i].opcode=0x13;commands[i].bytes=16;
            le16(commands[i].payload+2,sizes[i]);
            le16(commands[i].payload+4,restricted+offsets[i]);
            le64(commands[i].payload+8,Iova+0x30000);
        }
        if(!submit(commands,4))return false;
        stage=7;return true;
    }
    bool initTables() {
        // NothingOSS ipahal_{rt,flt}_generate_empty_img uses local SRAM
        // on IPA5.1 (only IPA4.0 uses a system-memory empty table). Local
        // encoding is (byte_offset/8)*128 +1, per create_tbl_addr(false).
        // This also avoids making common Q6 table headers reference an
        // address that is valid only in the AP SID5c0 DMA context.
        constexpr uint64_t emptyTable=(0x1000u/8u)*128u+1u;
        auto *filter=cpu+0x40100,*route=cpu+0x40200;
        bzero(cpu+0x40000,0x1000);
        const uint64_t bitmap=(1ull<<1)|(1ull<<2)|(1ull<<5)|(1ull<<6)|(1ull<<7)|(1ull<<10)|(1ull<<12)|(1ull<<15);
        le64(filter,bitmap);
        for(unsigned i=0;i<8;i++)le64(filter+8+i*8,emptyTable);
        for(unsigned i=0;i<19;i++)le64(route+i*8,emptyTable);
        clean(cpu+0x40000,0x1000);
        const unsigned op[]={3,4,7,8},hash[]={0x1288,0x1388,0x1488,0x15c8},plain[]={0x1308,0x1408,0x1528,0x1668};
        Immediate commands[4]={};
        for(unsigned i=0;i<4;i++) {
            commands[i].opcode=op[i];commands[i].bytes=24;
            const uint32_t size=i<2?72:152;
            const uint64_t address=Iova+(i<2?0x40100:0x40200);
            le64(commands[i].payload,address);
            const uint64_t fields=uint64_t(size)|(uint64_t(restricted+hash[i])<<12)|
                (uint64_t(size)<<28)|(uint64_t(restricted+plain[i])<<40);
            le64(commands[i].payload+8,fields);le64(commands[i].payload+16,address);
        }
        if(!submit(commands,4))return false;
        stage=9;return true;
    }
    void poll() {
        if(error||stage<4)return;
        if(pending) {
            if(!completion())return;
            if(stage==5) {
                stage=6;
                IOLog("PongModem IPA DMA: real native HDR_INIT_LOCAL completed; continuing full IPA5.1 setup\n");
                (void)initContexts();
            } else if(stage==7) {
                stage=8;
                write(registers,0x478,restricted+0x1b40);
                if(read(registers,0x478)!=restricted+0x1b40){fail(EIO,"local processing context readback");return;}
                (void)initTables();
            } else if(stage==9) {
                stage=10;
                IOLog("PongModem IPA DMA: native header/context/filter/route initialization completed restricted=%u SRAM=%u; physical QMI/WAN gate remains\n",restricted,sramBytes);
            }
        }
    }
    bool start() {
        stage=1;
        if(!gsi.open(0x03e04000,0xfc000)||!registers.open(0x03f40000,0x20000))return fail(ENOMEM,"owned register mapping");
        if(!(read(gsi,0x25000)&1))return fail(ENODEV,"GSI EE0 not enabled by TZ");
        const uint32_t flavor=read(registers,0),version=read(registers,0x28);
        const unsigned channels=read(gsi,0x25040)&255,events=read(gsi,0x25050)&255;
        IOLog("PongModem IPA DMA: real IPA version=%x flavor=%x GSI channels=%u events=%u\n",version,flavor,channels,events);
        if(!version||version==UINT32_MAX||channels<=12||!events)return fail(ENODEV,"IPA/GSI capability");
        if(((read(gsi,0x14000+12*0x80)>>20)&15)||((read(gsi,0x1c000)>>20)&15))return fail(EBUSY,"command channel/event already owned");
        memory=allocate(Bytes,physical);tables=allocate(TableBytes,tablePhysical);
        if(!memory||!tables)return fail(ENOMEM,"owned DMA allocation");
        cpu=static_cast<uint8_t *>(memory->getBytesNoCopy());
        if(!setupSmmu())return false;
        if(!ownedEvents(1))return false;
        // Event0 and command12 are real EE0 allocations; context fields
        // follow GSI3.0, with ERINDEX in CNTXT1 rather than older CNTXT0.
        if(!command(true,0,0,1))return false;
        const unsigned ev=0x1c000;const uint64_t eventIova=Iova+0x10000;
        write(gsi,ev,(16u<<24)|(1u<<7)|2);write(gsi,ev+4,4096);
        write(gsi,ev+8,uint32_t(eventIova));write(gsi,ev+12,0);
        for(unsigned offset=32;offset<=52;offset+=4)write(gsi,ev+offset,0);
        // Original ipa_dp.c: non-NAPI command ring count1, 16 cycles of
        // the32kHz moderation clock. A zero/zero moderation setup is not
        // the Pong command-completion policy.
        write(gsi,ev+32,(1u<<16)|16u);
        le64(cpu+0x18000,eventIova);clean(cpu+0x18000,64);
        write(gsi,ev+48,uint32_t(Iova+0x18000));write(gsi,ev+52,0);
        if(read(gsi,ev+4)!=4096||read(gsi,ev+8)!=eventIova)return fail(EIO,"event-ring context readback");
        write(gsi,0x24804,0);write(gsi,0x24800,uint32_t(eventIova+4096-16));
        if(!command(false,12,0,1))return false;
        const unsigned ch=0x14000+12*0x80;
        write(gsi,ch,(16u<<24)|(1u<<7)|2);write(gsi,ch+4,4096);
        write(gsi,ch+8,uint32_t(Iova));write(gsi,ch+12,0);
        // GSI3.0 moved QOS from the older +0x5c to +0x48.
        // +0x5c is scratch4: writing a QoS value there corrupts firmware
        // scratch while leaving the fetch policy unconfigured.
        // NothingOSS ipa_dp.c sets DB_IN_BYTES=1 for the address-valued
        // doorbell and command-channel low_weight=15. Without bit24 the
        // byte pointer below is interpreted using a different unit.
        const uint32_t qos=(1u<<24)|(1u<<10)|(24u<<16)|15u;
        write(gsi,ch+0x48,qos);
        for(unsigned offset=0x4c;offset<=0x70;offset+=4)write(gsi,ch+offset,0);
        if(read(gsi,ch+0x48)!=qos)return fail(EIO,"GSI3.0 command QoS readback");
        if(read(gsi,ch+4)!=4096||read(gsi,ch+8)!=Iova)return fail(EIO,"command-ring context readback");
        stage=3;
        // Prepare the actual IPA command endpoint14 in DMA-only mode to
        // LAN consumer16; no WAN/RX channel is started or published here.
        const unsigned endpoint=0x1000+14*0x80;
        write(registers,endpoint+8,0);write(registers,endpoint+12,0);
        write(registers,endpoint+16,0);write(registers,endpoint+20,0);
        write(registers,endpoint+32,3u|(16u<<4));write(registers,endpoint+36,0);
        write(registers,endpoint+52,0);write(registers,endpoint+56,0);write(registers,endpoint+60,0);write(registers,endpoint+64,0);
        if(read(registers,endpoint+32)!=(3u|(16u<<4)))return fail(EIO,"command endpoint mode");
        write(gsi,0x25220,1); // EE0 IRQ mode; actual completion is polled below
        if(!command(false,12,1,2))return false;
        stage=4;
        IOLog("PongModem IPA DMA: actual SID5c0 native4K lease bank=%u; EE0 event0 and command channel12 started; no packet/IPA-init success inferred\n",bank);
        return initHeaders();
    }
} ipaDma;
void ipaDmaPoll() {
    // Both secure firmware authentication and real remote readiness are
    // required; the optional owner cannot block normal XNU startup.
    if(ipaDma.attempted){if(pong_modem_is_ready())ipaDma.poll();return;}
    if(!ipaClock.firmware||!ipaClock.resources||!pong_modem_is_ready())return;
    ipaDma.attempted=true;(void)ipaDma.start();
}
