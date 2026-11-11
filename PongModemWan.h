/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Cape IPA5.1/GSI3.0 owner. QMI handshake structure follows UniXNU/
 * QcomBaseband (HoshinoYumeka/chiba233); memory/register/endpoint facts
 * are this Pong's NothingOSS tables. No Coachz4.2 addresses or DMA bypass.
 */
constexpr uint32_t IpaHostPort=0x122,IpaClientPort=0x123;
struct PongWan {
    PongQrtrServer remote{};bool present=false,registered=false;
    bool setup=false,initialSent=false,driverReady=false,ucReady=false;
    bool subscribed=false,indicated=false,backend=false,failed=false,onlineRetried=false;
    uint32_t subscriberNode=0,subscriberPort=0,error=0,attempts=0;
    uint16_t transaction=0;uint64_t deadline=0;
    uint16_t filterTransaction=0;bool filterPending=false;
    unsigned notifiedFilters=0,filterAttempts=0,filterGeneration=0;uint64_t filterDeadline=0;
    uint8_t config[128]{};unsigned configBytes=0,notifications=0,requestLogs=0;
    uint32_t configFields=0,lastNotificationPipe=~0u,lastNotificationStatus=~0u;
    struct RequestRecord {uint16_t message,transaction;uint32_t bytes,result,fields;} history[16]{};
    unsigned historyCount=0;
    void snapshot()const {
        const unsigned begin=historyCount>16?historyCount-16:0;
        for(unsigned i=begin;i<historyCount;i++) {
            const auto &r=history[i%16];
            IOLog("Pong WAN history: request=%x txn=%u bytes=%u result=%u fields=%x\n",r.message,r.transaction,r.bytes,r.result,r.fields);
        }
    }
    void snapshotFault() const {
        // Only AP-owned registers are readable here. In particular, do
        // not access Q6's EE1 interrupt page, even for a read-only snapshot.
        auto &d=ipaDma;
        if(d.stage<10)return;
        IOLog("Pong WAN fault: IRQ_AP=%x LAN_TX=%x WAN_TX=%x route=%x LAN_packets=%llu bytes=%llu; AP ownership only, no IRQ acknowledgement\n",
            d.read(d.registers,0xc008),
            d.read(d.registers,0x1000+16*0x80+0x68),d.read(d.registers,0x1000+23*0x80+0x68),
            d.read(d.registers,0x38),lanPackets,lanBytes);
        IOLog("Pong WAN AP fault: SNOC_FEC=%x address=%x:%x attributes=%x SMMU_FSR=%x FAR=%x:%x; only AP EE0 and owned bank\n",
            d.read(d.registers,0xc018),d.read(d.registers,0xc024),d.read(d.registers,0xc020),d.read(d.registers,0xc028),
            d.read(d.smmu,0x80000+d.bank*0x1000+0x58),d.read(d.smmu,0x80000+d.bank*0x1000+0x64),d.read(d.smmu,0x80000+d.bank*0x1000+0x60));
    }
    struct Reply {uint32_t node,port;uint16_t txn,msg;uint32_t error;
        unsigned ruleCount;uint32_t ruleIds[64];} replies[8];
    unsigned head=0,count=0;
    uint32_t txProducer=0,txRetired=0,txEvent=0,rxProducer=0,rxEvent=0;
    uint32_t lanProducer=0,lanEvent=0;bool lanReady=false;
    bool txOwned[256]{},rxOwned[256]{},lanOwned[256]{};
    uint64_t txPackets=0,rxPackets=0,dropped=0;
    uint64_t lanPackets=0,lanBytes=0;
    static constexpr unsigned RxCount=16,RxBytes=32768,TxCount=32,TxBytes=2048;
    static constexpr unsigned LanCount=8,LanBytes=8192;
    bool fail(uint32_t e,const char *where) {
        failed=true;error=e;
        IOLog("Pong WAN: %s actual error=%u; DMA retained, network link revoked\n",where,e);return false;
    }
    bool ready()const {
        return !failed&&setup&&lanReady&&backend&&present&&driverReady&&ucReady&&subscribed&&indicated&&
            !ipaDma.error&&ipaDma.stage==10&&pong_modem_is_ready()&&
            __atomic_load_n(&modemDataState,__ATOMIC_ACQUIRE)==0&&
            modemData.llp==2&&modemData.ul==5&&modemData.dl==5&&
            modemRules.valid&&ipaFilters.generation==modemRules.generation&&
            !ipaFilters.pending&&notifiedFilters==ipaFilters.generation;
    }
    void server(const PongQrtrServer *s,bool added) {
        if(s->service!=49||s->instance!=0x201)return;
        if(added){remote=*s;present=true;}
        else if(present&&s->node==remote.node&&s->port==remote.port) {
            modemRules.revoke();
            present=driverReady=ucReady=subscribed=indicated=false;filterPending=false;notifiedFilters=0;
            if(setup)fail(ENETDOWN,"modem service removed");
        }
    }
    uint32_t u32(uint8_t *out,unsigned cap,unsigned kind,uint32_t value) {
        uint8_t b[4];cbd_wr32(b,value);return cbd_tlv(out,cap,kind,b,4);
    }
    uint32_t pair(uint8_t *out,unsigned cap,unsigned kind,uint32_t a,uint32_t b) {
        uint8_t v[8];cbd_wr32(v,a);cbd_wr32(v+4,b);return cbd_tlv(out,cap,kind,v,8);
    }
    unsigned initRequest(uint8_t *out,unsigned cap) {
        if(cap<256)return 0;
        unsigned n=7;const uint32_t r=ipaDma.restricted;
        n+=u32(out+n,cap-n,0x10,3); // MSM Android platform, real Qualcomm backend
        n+=pair(out+n,cap-n,0x11,r+0x1708,r+0x1947);
        n+=pair(out+n,cap-n,0x12,r+0x1528,10);
        n+=pair(out+n,cap-n,0x13,r+0x1668,10);
        n+=u32(out+n,cap-n,0x14,r+0x1308);
        n+=u32(out+n,cap-n,0x15,r+0x1408);
        n+=pair(out+n,cap-n,0x16,r+0x3898,0xd48);
        n+=u32(out+n,cap-n,0x17,23);
        n+=pair(out+n,cap-n,0x19,r+0x1b40,r+0x265f);
        n+=pair(out+n,cap-n,0x1b,r+0x1488,10);
        n+=pair(out+n,cap-n,0x1c,r+0x15c8,10);
        n+=u32(out+n,cap-n,0x1d,r+0x1288);
        n+=u32(out+n,cap-n,0x1e,r+0x1388);
        n+=u32(out+n,cap-n,0x1f,r+0x2868);
        n+=u32(out+n,cap-n,0x20,0x60);
        n+=u32(out+n,cap-n,0x21,r+0x4fe8);
        n+=u32(out+n,cap-n,0x22,0x18);
        return cbd_request(out,transaction,0x21,n-7);
    }
    uint32_t configuration(const uint8_t *sdu,unsigned bytes) {
        // NothingOSS ipa_mhi_client.c's native CONFIG callback accepts
        // this metadata independently of starting an MHI channel. Preserve
        // a real bounded copy; no MHI/DMA/offload success is inferred.
        const unsigned end=7u+cbd_rd16(sdu+5);
        if(end>sizeof config||end>bytes)return 1;
        uint32_t fields=0;
        for(unsigned at=7;at<end;at+=3+cbd_rd16(sdu+at+1)) {
            const unsigned type=sdu[at],n=cbd_rd16(sdu+at+1);
            // The native schema continues through0x1e: UL/DL MSI
            // thresholds, UL/DL FIFO sizes and downlink buffer size.
            if(type<0x10||type>0x1e||n!=(type==0x11?1u:4u))return 1;
            const uint32_t bit=1u<<(type-0x10);if(fields&bit)return 1;fields|=bit;
            const uint32_t value=n==1?sdu[at+3]:cbd_rd32(sdu+at+3);
            // Zero enum/size values are an unspecified/default metadata
            // value. Retaining them does not configure a physical path.
            if((type==0x10&&value>3)||(type==0x11&&value>1)||
               (type==0x12&&value&&(value<128||value>32768))||
               (type==0x13&&value>2)||(type==0x14&&value>4)||
               ((type==0x15||type==0x18)&&value>255)||(type==0x16&&value>1023)||
               ((type==0x1a||type==0x1b)&&value>65535))return 1;
        }
        memcpy(config,sdu,end);configBytes=end;configFields=fields;
        return 0;
    }
    uint32_t filterNotification(const uint8_t *sdu,unsigned bytes) {
        // This is an acknowledgement of the modem's notification, not a
        // claim that AP filtering rules have been installed. Native
        // ipa3_handle_filter_installed_notify_req also acknowledges receipt.
        uint32_t n=0;const auto *pipe=cbd_find(sdu,bytes,1,&n);
        if(!pipe||n!=4)return 1;
        const uint32_t source=cbd_rd32(pipe);
        const auto *status=cbd_find(sdu,bytes,2,&n);
        if(!status||n!=2||source>=32||cbd_rd16(status)>1)return 1;
        const uint32_t result=cbd_rd16(status);
        const auto *indices=cbd_find(sdu,bytes,3,&n);
        if(!indices||n<1||indices[0]>64||n!=1u+8u*indices[0])return 1;
        lastNotificationPipe=source;lastNotificationStatus=result;++notifications;
        return 0;
    }
    bool receive(uint32_t local,uint32_t node,uint32_t port,const uint8_t *sdu,unsigned bytes) {
        if(local!=IpaHostPort&&local!=IpaClientPort)return false;
        if(!cbd_sdu_ok(sdu,bytes))return true;
        const uint16_t txn=cbd_rd16(sdu+1),msg=cbd_rd16(sdu+3);
        if(local==IpaClientPort) {
            if(present&&filterPending&&node==remote.node&&port==remote.port&&sdu[0]==2&&txn==filterTransaction&&msg==0x24) {
                filterPending=false;const unsigned result=cbd_error(sdu,bytes);
                if(result)fail(result,"physical filter-install notification refused");
                else {notifiedFilters=filterGeneration;filterAttempts=0;
                    IOLog("Pong WAN filters: physical modem acknowledged installed AP2 generation=%u; data readiness still requires current WDS/link\n",notifiedFilters);}
                return true;
            }
            if(present&&initialSent&&node==remote.node&&port==remote.port&&sdu[0]==2&&txn==transaction&&msg==0x21) {
                initialSent=false;error=cbd_error(sdu,bytes);
                if(error)fail(error,"physical INIT_DRIVER refused");
                else {driverReady=true;IOLog("Pong WAN: actual modem INIT_DRIVER accepted, wait for physical uC completion\n");}
            }
            return true;
        }
        if(sdu[0]!=0||!pong_modem_is_ready()||count==8)return true;
        uint32_t result=94;
        if(msg==0x20)result=0;
        else if(msg==0x35) {
            uint32_t n=0;const auto *status=cbd_find(sdu,bytes,1,&n);
            // Native NothingOSS acknowledges the actual completion
            // notification; this one-byte status is not a QMI result TLV.
            result=status&&n==1?0:1;
        } else if(msg==0x27)result=configuration(sdu,bytes);
        else if(msg==0x24)result=filterNotification(sdu,bytes);
        else if(msg==0x23)result=modemRules.receive(sdu,bytes);
        uint32_t fields=0;
        for(unsigned at=7,end=7u+cbd_rd16(sdu+5);at<end;at+=3+cbd_rd16(sdu+at+1))
            if(sdu[at]>=0x10&&sdu[at]<0x30)fields|=1u<<(sdu[at]-0x10);
        history[historyCount++%16]={msg,txn,bytes,result,fields};
        if(requestLogs++<32)
            IOLog("Pong WAN: actual host QMI request=%x txn=%u bytes=%u result=%u config_fields=%x notifications=%u; no packet or filter-install success inferred\n",
                msg,txn,bytes,result,configFields,notifications);
        auto &reply=replies[(head+count)%8];reply={node,port,txn,msg,result,0,{}};
        if(msg==0x23&&!result) {
            reply.ruleCount=modemRules.count();
            for(unsigned i=0;i<reply.ruleCount;i++)reply.ruleIds[i]=modemRules.id(i);
        }
        ++count;
        return true;
    }
    bool ring(unsigned channel,unsigned event,unsigned ringOffset,unsigned eventOffset,unsigned shadowOffset,bool rx) {
        auto &d=ipaDma;
        const unsigned ev=0x1c000+event*0x80,ch=0x14000+channel*0x80;
        if(((d.read(d.gsi,ev)>>20)&15)||((d.read(d.gsi,ch)>>20)&15))return fail(EBUSY,"foreign WAN GSI resources");
        if(!d.ownedEvents(1u<<event))return fail(d.error,"WAN event source setup");
        if(!d.command(true,event,0,1))return fail(d.error,"WAN event allocation");
        d.write(d.gsi,ev,(16u<<24)|(1u<<7)|2u);d.write(d.gsi,ev+4,4096);
        d.write(d.gsi,ev+8,uint32_t(d.Iova+eventOffset));d.write(d.gsi,ev+12,0);
        for(unsigned off=32;off<=52;off+=4)d.write(d.gsi,ev+off,0);
        d.write(d.gsi,ev+32,(1u<<16)|16u);
        d.le64(d.cpu+shadowOffset,d.Iova+eventOffset);d.clean(d.cpu+shadowOffset,64);
        d.write(d.gsi,ev+48,uint32_t(d.Iova+shadowOffset));
        d.write(d.gsi,0x24804+event*8,0);d.write(d.gsi,0x24800+event*8,uint32_t(d.Iova+eventOffset+4080));
        if(!d.command(false,channel,0,1))return fail(d.error,"WAN channel allocation");
        d.write(d.gsi,ch,(16u<<24)|(!rx?1u<<7:0)|2u);
        d.write(d.gsi,ch+4,4096|(event<<24));
        d.write(d.gsi,ch+8,uint32_t(d.Iova+ringOffset));d.write(d.gsi,ch+12,0);
        // NothingOSS IPA_5_1: LAN13 uses escape-only, threshold0;
        // WAN1/11 use smart prefetch, threshold3. The9 in the LAN
        // mapping is its interface TLV/AOS budget, not this threshold.
        const uint32_t qos=(1u<<24)|((channel==13?1u:2u)<<10)|((channel==13?0u:3u)<<16)|1u;
        d.write(d.gsi,ch+0x48,qos);
        for(unsigned off=0x4c;off<=0x70;off+=4)d.write(d.gsi,ch+off,0);
        if(d.read(d.gsi,ch+0x48)!=qos)return fail(EIO,"native GSI fetch policy readback");
        return d.command(false,channel,1,2)||fail(d.error,"WAN START");
    }
    bool consumer(unsigned pipe,unsigned txInstance) {
        // IPA5.1 has distinct UL/DL TX engines. ipa3_cfg_ep_cfg programs
        // INIT_PROD_CFG even for a consumer (the name is misleading):
        // LAN16 belongs to UL0, WAN23 to DL1. Leaving WAN at reset UL0
        // crosses the modem's DL routing/TX ownership and can raise TX_ERR.
        auto &d=ipaDma;const unsigned ep=0x1000+pipe*0x80;
        d.write(d.registers,ep+0x38,0); // actual IPA_v5_0_GROUP_UL for both
        d.write(d.registers,ep+0x68,txInstance);
        if(d.read(d.registers,ep+0x38)!=0||d.read(d.registers,ep+0x68)!=txInstance)
            return fail(EIO,"native consumer resource/TX instance readback");
        return true;
    }
    void rxTre(unsigned ringIndex,unsigned slot) {
        auto &d=ipaDma;auto *tre=d.cpu+0x2000+ringIndex*16;
        bzero(tre,16);d.le64(tre,d.Iova+0x50000+slot*RxBytes);
        // Native replenish paths request both EOT and EOB, with BEI for
        // polling. A consumed block must return ownership even without
        // an EOT (for example when an aggregate fills that whole block).
        d.le16(tre+8,RxBytes);d.le32(tre+12,(2u<<16)|0x700u);
        d.clean(tre,16);
    }
    void lanTre(unsigned ringIndex,unsigned slot) {
        auto &d=ipaDma;auto *tre=d.cpu+0x3000+ringIndex*16;
        bzero(tre,16);d.le64(tre,d.Iova+0xe0000+slot*LanBytes);
        d.le16(tre+8,LanBytes);d.le32(tre+12,(2u<<16)|0x700u);d.clean(tre,16);
    }
    bool exceptionPath() {
        // The actual IPA5.1 AP LAN consumer16/GSI13 is required even with
        // no WAN session: command/default/exception traffic may use it.
        // Formerly only WAN23 existed and the global exception route was
        // left at reset. Never direct a packet to an unowned consumer.
        auto &d=ipaDma;const unsigned ep=0x1000+16*0x80;
        if((d.read(d.gsi,0x25040)&255)<=13||(d.read(d.gsi,0x25050)&255)<=3)
            return fail(ENODEV,"LAN GSI channel/event capability");
        const unsigned zero[]={8,12,24,28,32,36,44,52,56,60,64};
        for(unsigned offset:zero)d.write(d.registers,ep+offset,0);
        d.write(d.registers,ep+16,2); // original IPA_LAN_RX_HEADER_LENGTH
        // Native HAL inverts hdr_little_endian: register bit0=1 is BE.
        // Writing0 here selected LE despite the old comment saying BE.
        d.write(d.registers,ep+20,1u|2u|(2u<<10)); // BE,padding field0,4B alignment
        if(!consumer(16,0))return false;
        if(!ring(13,3,0x3000,0x13000,0x180c0,true))return false;
        for(unsigned i=0;i<LanCount;i++){lanTre(i,i);lanOwned[i]=true;}
        lanProducer=LanCount;d.clean(d.cpu+0x3000,4096);
        d.write(d.gsi,0x24004+13*8,0);
        d.write(d.gsi,0x24000+13*8,uint32_t(d.Iova+0x3000+lanProducer*16));
        // Native setup_exception_path routes normal and fragment misses to
        // LAN16, local zero header0, retaining the actual original header.
        const uint32_t route=(d.read(d.registers,0x38)&0xe0000000u)|16u|(16u<<8)|(1u<<27);
        d.write(d.registers,0x38,route);
        if(d.read(d.registers,0x38)!=route)return fail(EIO,"LAN exception-route readback");
        lanReady=true;
        IOLog("Pong WAN: actual AP LAN16/GSI13/event3 RX buffers armed; exception route=%x before INIT_DRIVER\n",route);
        return true;
    }
    bool start() {
        auto &d=ipaDma;
        if(setup||failed)return setup;
        if(!exceptionPath())return false;
        const unsigned tx=0x1000+2*0x80,rx=0x1000+23*0x80;
        // MAP without checksum offloads, matching actual WDA QMAP5. QMAP
        // metadata/payload-length fields follow IPA5.1 register layouts.
        const unsigned endpoints[]={tx,rx};
        for(unsigned ep:endpoints) {
            d.write(d.registers,ep+8,0);d.write(d.registers,ep+12,0);
            d.write(d.registers,ep+32,0);d.write(d.registers,ep+52,0);
            d.write(d.registers,ep+56,0);d.write(d.registers,ep+64,0);
        }
        // Original IPA5.1 rmnet WAN producer: BASIC, four-byte MAP
        // header, metadata extracted at offset0 (the modem requires0),
        // packet-processing sequencer4. DMA-only/header0 discarded the
        // mux metadata; the first real packets crashed MPSS ipa_ul at0xb8.
        // Real modem-provided equation tables now perform classification
        // and select its actual routing table. No per-packet software
        // bypass is used for ordinary WAN data.
        d.write(d.registers,tx+16,4u|0x40u);d.write(d.registers,tx+20,1);
        d.write(d.registers,tx+32,2u<<4);d.write(d.registers,tx+36,0);
        d.write(d.registers,tx+60,4);
        if(d.read(d.registers,tx+16)!=(4u|0x40u)||d.read(d.registers,tx+32)!=(2u<<4)||d.read(d.registers,tx+60)!=4)
            return fail(EIO,"native WAN parser/sequencer readback");
        d.write(d.registers,rx+16,4u|0x40u|(1u<<7)|(1u<<19)|(2u<<20));
        // QMAP is BE(bit0=1); pad byte offset0, payload includes padding.
        // Mask belongs at+0x18, not metadata value+0x1c.
        d.write(d.registers,rx+20,1u|2u|8u|(2u<<10));
        d.write(d.registers,rx+24,0xff000000u);d.write(d.registers,rx+28,0);
        // Original generic RX aggregation uses500us (5x100us pulse0),
        // with no packet limit.16KiB byte limit fits the owned32KiB buffer.
        d.write(d.registers,rx+36,1u|(4u<<2)|(16u<<5)|(5u<<12));
        d.write(d.registers,rx+60,0);d.write(d.registers,rx+0x2c,0);
        if(!consumer(23,1))return false;
        if(d.read(d.registers,tx+20)!=1||d.read(d.registers,rx+20)!=(1u|2u|8u|(2u<<10)))
            return fail(EIO,"native QMAP big-endian header readback");
        if(!ring(11,1,0x1000,0x11000,0x18040,false)||!ring(1,2,0x2000,0x12000,0x18080,true))return false;
        setup=true;
        for(unsigned i=0;i<RxCount;i++){rxTre(i,i);rxOwned[i]=true;}
        rxProducer=RxCount;d.clean(d.cpu+0x2000,4096);
        d.write(d.gsi,0x24008+4,0);d.write(d.gsi,0x24008,uint32_t(d.Iova+0x2000+rxProducer*16));
        // Actual sender/receiver hooks exist now, but ready() still waits
        // for real modem QMI completion and WDA agreement.
        backend=pong_baseband_wan_backend(sendHook,readyHook);
        pong_modem_request_data_port();
        IOLog("Pong WAN: actual GSI11/TX ep2 and GSI1/RX ep23 initialized; backend=%u, physical QMI gate remains\n",backend);
        return backend;
    }
    int send(uint32_t mux,const uint8_t *ip,uint32_t bytes) {
        if(!ready())return ENETDOWN;
        if(!ip||!bytes||bytes>1492||mux<1||mux>4)return EINVAL;
        if(txProducer-txRetired>=TxCount)return EBUSY;
        auto &d=ipaDma;const unsigned slot=txProducer%TxCount,index=txProducer&255;
        auto *packet=d.cpu+0xd0000+slot*TxBytes,*data=d.cpu+0x1000+index*16;
        const unsigned padding=(4-(bytes&3))&3,payloadBytes=bytes+padding;
        packet[0]=padding;packet[1]=mux;packet[2]=payloadBytes>>8;packet[3]=payloadBytes;
        memcpy(packet+4,ip,bytes);bzero(packet+4+bytes,padding);
        bzero(data,16);d.le64(data,d.Iova+0xd0000+slot*TxBytes);
        d.le16(data+8,payloadBytes+4);d.le32(data+12,(2u<<16)|0x600u);
        d.clean(packet,payloadBytes+4);d.clean(data,16);
        txOwned[index]=true;++txProducer;
        d.write(d.gsi,0x24000+11*8,uint32_t(d.Iova+0x1000+(txProducer&255)*16));
        return 0;
    }
    void payload(const uint8_t *p,unsigned bytes) {
        unsigned at=0;
        while(bytes-at>=4) {
            const unsigned size=(unsigned(p[at+2])<<8)|p[at+3],pad=p[at]&63;
            if(!size||size>bytes-at-4||pad>size){++dropped;return;}
            const unsigned length=size-pad,mux=p[at+1];
            if(!(p[at]&0x80)&&mux>=1&&mux<=4&&length&&
               (p[at+4]>>4==4||p[at+4]>>4==6)) {
                pong_baseband_wan_receive(mux,p+at+4,length,p[at+4]>>4);++rxPackets;
            }else ++dropped;
            at+=4+size;
        }
        if(at!=bytes)++dropped;
    }
    void events(bool rx,bool lan=false) {
        auto &d=ipaDma;unsigned &cursor=lan?lanEvent:rx?rxEvent:txEvent;
        const unsigned event=lan?3:rx?2:1,offset=lan?0x13000:rx?0x12000:0x11000,shadow=lan?0x180c0:rx?0x18080:0x18040;
        if(!d.pollOwnedEvents(1u<<event)){fail(d.error,"WAN real event error");return;}
        const unsigned channel=lan?13:rx?1:11,ringOffset=lan?0x3000:rx?0x2000:0x1000;
        d.clean(d.cpu+shadow,64);const auto ptr=d.from64(d.cpu+shadow),base=d.Iova+offset;
        if(ptr<base||ptr>=base+4096||((ptr-base)&15)){fail(EIO,"WAN event pointer extent");return;}
        const unsigned index=unsigned(ptr-base)/16;unsigned processed=0;
        while(cursor!=index&&processed++<256&&!failed) {
            auto *record=d.cpu+offset+cursor*16;d.clean(record,16);
            const auto tre=d.from64(record);const auto ringBase=d.Iova+ringOffset;
            if(record[15]!=channel||tre<ringBase||tre>=ringBase+4096||((tre-ringBase)&15)||
               (record[11]!=1&&record[11]!=2)){fail(EIO,"WAN event identity/result");return;}
            const unsigned slot=unsigned(tre-ringBase)/16;
            if(rx) {
                bool &owned=lan?lanOwned[slot]:rxOwned[slot];
                if(!owned){fail(EIO,"RX ownership");return;}
                owned=false;const unsigned bufferSlot=slot%(lan?LanCount:RxCount),bytes=record[8]|(unsigned(record[9])<<8);
                if(bytes>(lan?LanBytes:RxBytes)){fail(EIO,"RX length");return;}
                const unsigned buffer=lan?0xe0000+bufferSlot*LanBytes:0x50000+bufferSlot*RxBytes;
                d.clean(d.cpu+buffer,bytes);
                if(lan){++lanPackets;lanBytes+=bytes;} // exception/status sink, not PDP RX
                else if(ready())payload(d.cpu+buffer,bytes);
                else ++dropped;
                unsigned &producer=lan?lanProducer:rxProducer;const unsigned next=producer&255;
                if(lan){lanTre(next,bufferSlot);lanOwned[next]=true;}
                else {rxTre(next,bufferSlot);rxOwned[next]=true;}
                ++producer;
            }else {
                if(!txOwned[slot]||slot!=(txRetired&255)){fail(EIO,"TX ownership/FIFO");return;}
                txOwned[slot]=false;++txRetired;++txPackets;
            }
            cursor=(cursor+1)&255;
        }
        if(processed) {
            d.write(d.gsi,0x24800+event*8,uint32_t(base+((cursor+255)&255)*16));
            if(rx)d.write(d.gsi,0x24000+channel*8,uint32_t(d.Iova+ringOffset+((lan?lanProducer:rxProducer)&255)*16));
        }
    }
    void poll() {
        if(failed||ipaDma.error||!pong_modem_is_ready())return;
        if(ipaDma.stage<10)return;
        if(!setup&&!start())return;
        ipaFilters.poll(txProducer==txRetired);
        if(ipaFilters.failure){fail(EOPNOTSUPP,"actual AP filter rule compilation");return;}
        if(!registered)registered=!pong_modem_qrtr_register(&control.qrtr,49,0x101,IpaHostPort);
        if(!registered)return;
        if(count) {
            const auto &r=replies[head];uint8_t response[274]={2};unsigned bytes=14;
            cbd_wr16(response+1,r.txn);cbd_wr16(response+3,r.msg);cbd_wr16(response+5,7);
            response[7]=2;cbd_wr16(response+8,4);cbd_wr16(response+10,r.error?1:0);cbd_wr16(response+12,r.error);
            if(r.msg==0x23&&!r.error) {
                response[bytes++]=0x11;cbd_wr16(response+bytes,1+4*r.ruleCount);bytes+=2;
                response[bytes++]=r.ruleCount;
                for(unsigned i=0;i<r.ruleCount;i++){cbd_wr32(response+bytes,r.ruleIds[i]);bytes+=4;}
                cbd_wr16(response+5,bytes-7);
            }
            if(!pong_modem_qrtr_send(&control.qrtr,IpaHostPort,r.node,r.port,response,bytes)) {
                if(!r.error&&r.msg==0x20){subscribed=true;subscriberNode=r.node;subscriberPort=r.port;}
                if(!r.error&&r.msg==0x35)ucReady=true;
                head=(head+1)%8;--count;
            }
        }
        if(initialSent&&nowMs()>=deadline){initialSent=false;if(attempts>=3)fail(ETIMEDOUT,"INIT_DRIVER response");}
        if(present&&!driverReady&&!initialSent&&!failed) {
            uint8_t request[256];++transaction;if(!transaction)++transaction;
            const unsigned bytes=initRequest(request,sizeof request);
            if(bytes&&!pong_modem_qrtr_send(&control.qrtr,IpaClientPort,remote.node,remote.port,request,bytes)) {
                initialSent=true;deadline=nowMs()+60000;++attempts;
                IOLog("Pong WAN: sent real IPA5.1 INIT_DRIVER with actual SRAM/ep23, attempt=%u\n",attempts);
            }
        }
        if(driverReady&&ucReady&&subscribed&&!indicated&&!failed) {
            const uint8_t indication[]={4,0,0,0x22,0,7,0,2,4,0,0,0,0,0};
            if(!pong_modem_qrtr_send(&control.qrtr,IpaHostPort,subscriberNode,subscriberPort,indication,sizeof indication)) {
                indicated=true;IOLog("Pong WAN: actual modem/uC handshake complete; physical data path armed\n");
            }
        }
        if(filterPending&&nowMs()>=filterDeadline) {
            filterPending=false;
            if(filterAttempts>=3){fail(ETIMEDOUT,"physical filter-install notification response");return;}
        }
        if(present&&driverReady&&ipaFilters.generation&&!ipaFilters.pending&&
            ipaFilters.generation==modemRules.generation&&notifiedFilters!=ipaFilters.generation&&!filterPending) {
            uint8_t request[512];uint16_t next=transaction+1;if(!next)next=1;
            const unsigned bytes=ipaFilters.notification(request,sizeof request,next);
            if(bytes&&!pong_modem_qrtr_send(&control.qrtr,IpaClientPort,remote.node,remote.port,request,bytes)) {
                transaction=filterTransaction=next;filterGeneration=ipaFilters.generation;
                filterPending=true;filterDeadline=nowMs()+5000;++filterAttempts;
            }
        }
        if(indicated&&!onlineRetried&&pong_modem_native_online_requested()) {
            // Native iOS already asked for ONLINE while IPA was missing.
            // Retry once after the actual handshake; never override a
            // subsequent non-ONLINE/airplane-mode intent.
            onlineRetried=pong_modem_request_online();
        }
        events(false);events(true);events(true,true);
    }
    static int sendHook(uint32_t mux,const uint8_t *ip,uint32_t bytes);
    static bool readyHook();
} wan;
int PongWan::sendHook(uint32_t mux,const uint8_t *ip,uint32_t bytes){return wan.send(mux,ip,bytes);}
bool PongWan::readyHook(){return wan.ready();}
