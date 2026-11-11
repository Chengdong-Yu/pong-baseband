/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Actual Qualcomm IMS/IMSA state for native VoLTE integration. QMI
 * service18 is IMS settings and33 is IMSA (libqmi public schemas).
 * Read configuration, subscribe to physical registration/service events,
 * and publish only matched modem results. Never fabricate IMS attachment,
 * SIP authentication, voice availability or a successful call.
 */
constexpr uint32_t ModemImsPort=0x150;
struct PongModemIms {
    struct Query {
        unsigned endpoint;uint16_t message,transaction=0;
        bool pending=false,done=false;unsigned attempts=0,error=0;
        uint64_t deadline=0,refresh=0;
    } queries[7]={{0,0x98},{1,0x33},{0,0x90},{1,0x22},{1,0x20},{1,0x21},{0,0x8f}};
    PongQrtrServer endpoints[2]{};bool present[2]{},bound[2]{};
    uint16_t next=0;
    uint32_t registration=~0u,technology=~0u,voice=~0u,sms=~0u;
    uint32_t registrationError=~0u;
    uint32_t voiceTechnology=~0u,voiceEnabled=~0u,registrationEnabled=~0u;
    unsigned replies=0,indications=0,failures=0,lastError=0;
    bool registrationPolicyRead=false,registrationRequested=false;
    void publish() {
        pong_baseband_transport_ims(registration,technology,voice,sms,voiceTechnology,voiceEnabled,registrationEnabled);
    }
    void server(const PongQrtrServer *s,bool added) {
        const unsigned index=s->service==18?0:s->service==33?1:2;
        if(index==2)return;
        if(added&&(!present[index]||(s->instance>>8)<(endpoints[index].instance>>8))) {
            endpoints[index]=*s;present[index]=true;
        }else if(!added&&present[index]&&endpoints[index].node==s->node&&endpoints[index].port==s->port) {
            present[index]=false;
            if(index){registration=technology=voice=sms=voiceTechnology=~0u;}
            else voiceEnabled=registrationEnabled=~0u;
            publish();
        }else return;
        bound[index]=false;
        for(auto &q:queries)if(q.endpoint==index){q.pending=q.done=false;q.attempts=q.error=0;q.refresh=0;}
    }
    void poll() {
        const uint64_t now=nowMs();
        if(!registrationPolicyRead) {
            unsigned request=0;registrationRequested=PE_parse_boot_argn("pong_ims",&request,sizeof request)&&request==1;
            registrationPolicyRead=true;
        }
        for(auto &q:queries) {
            if(!present[q.endpoint])continue;
            const bool binding=q.message==0x98||q.message==0x33;
            if(!binding&&!bound[q.endpoint])continue;
            // Explicit user request is a real modem setting operation,
            // not a fabricated registered/available response. Wait for
            // the physical card, ONLINE radio and real PS registration.
            if(q.message==0x8f&&(!registrationRequested||!modemSim.ready||modemOperatingMode!=0||modemRegistration!=1||modemPsAttach!=1))continue;
            if(q.pending&&now<q.deadline)continue;
            if(q.pending){q.pending=false;++failures;lastError=q.error=ETIMEDOUT;q.refresh=now+30000;q.done=true;}
            if(q.done) {
                if(!q.refresh||now<q.refresh)continue;
                q.done=false;if(q.message!=0x8f)q.attempts=0;q.refresh=0;
            }
            if(q.attempts>=3){q.done=true;q.refresh=q.message==0x8f?0:now+30000;continue;}
            uint8_t data[32]={};unsigned bytes=7;
            uint16_t transaction=next+1;if(!transaction)transaction=1;
            data[0]=0;cbd_wr16(data+1,transaction);cbd_wr16(data+3,q.message);
            if(binding) {
                // Public IMS/IMSA Bind selects primary subscription0;
                // these independent control points never select slot2.
                const uint8_t primary[4]={0,0,0,0};
                bytes+=cbd_tlv(data+bytes,sizeof data-bytes,q.endpoint?0x10:1,primary,sizeof primary);
            }
            if(q.message==0x22){const uint8_t one=1;bytes+=cbd_tlv(data+bytes,sizeof data-bytes,0x10,&one,1);bytes+=cbd_tlv(data+bytes,sizeof data-bytes,0x11,&one,1);}
            if(q.message==0x8f) {
                // Public IMS SetServicesEnabled0x8f: VoLTE enable and
                // IMS-service enable only. Preserve Wi-Fi calling, RCS,
                // SMS/UT, credentials and carrier configuration fields.
                const uint8_t one=1;bytes+=cbd_tlv(data+bytes,sizeof data-bytes,0x10,&one,1);
                bytes+=cbd_tlv(data+bytes,sizeof data-bytes,0x18,&one,1);
            }
            cbd_wr16(data+5,bytes-7);const auto &endpoint=endpoints[q.endpoint];
            if(!pong_modem_qrtr_send(&control.qrtr,ModemImsPort+q.endpoint,endpoint.node,endpoint.port,data,bytes)) {
                next=transaction;q.transaction=transaction;q.pending=true;q.deadline=now+5000;++q.attempts;
            }
        }
    }
    uint32_t field(const uint8_t *sdu,unsigned bytes,unsigned id,unsigned size=4) {
        unsigned n=0;const auto *value=cbd_find(sdu,bytes,id,&n);
        return value&&n==size?(size==1?value[0]:size==2?cbd_rd16(value):cbd_rd32(value)):~0u;
    }
    void state(unsigned index,unsigned message,bool indication,const uint8_t *sdu,unsigned bytes) {
        if(!index&&message==0x90) {
            voiceEnabled=field(sdu,bytes,0x11,1);registrationEnabled=field(sdu,bytes,0x19,1);
            if(voiceEnabled>1)voiceEnabled=~0u;if(registrationEnabled>1)registrationEnabled=~0u;
        }else if(index&&message==(indication?0x23u:0x20u)) {
            const auto value=field(sdu,bytes,indication?0x11:0x12);
            if(value<=3)registration=value; //3 is limited registration, not full voice availability
            const auto tech=field(sdu,bytes,indication?0x13:0x14);
            if(tech<=2)technology=tech;
            registrationError=field(sdu,bytes,indication?0x10:0x11,2);
        }else if(index&&message==(indication?0x24u:0x21u)) {
            const auto v=field(sdu,bytes,0x11),s=field(sdu,bytes,0x10),t=field(sdu,bytes,0x14);
            if(v<=2)voice=v;if(s<=2)sms=s;if(t<=2)voiceTechnology=t;
        }
        publish();
    }
    bool receive(uint32_t local,uint32_t node,uint32_t port,const uint8_t *sdu,unsigned bytes) {
        if(local<ModemImsPort||local>ModemImsPort+1)return false;
        const unsigned index=local-ModemImsPort;
        if(!present[index]||endpoints[index].node!=node||endpoints[index].port!=port||!cbd_sdu_ok(sdu,bytes))return true;
        const unsigned message=cbd_rd16(sdu+3);
        if(sdu[0]==4&&index&&(message==0x23||message==0x24)) {
            ++indications;state(index,message,true,sdu,bytes);return true;
        }
        if(sdu[0]!=2)return true;
        for(auto &q:queries)if(q.endpoint==index&&q.pending&&q.message==message&&q.transaction==cbd_rd16(sdu+1)) {
            q.pending=false;q.done=true;q.refresh=q.message==0x22||q.message==0x98||q.message==0x33||q.message==0x8f?0:nowMs()+30000;
            lastError=q.error=cbd_error(sdu,bytes);
            if(lastError){++failures;q.refresh=nowMs()+30000;return true;}
            if(q.message==0x98||q.message==0x33)bound[index]=true;
            if(q.message==0x8f) {
                IOLog("Pong IMS: physical VoLTE/IMS enable request acknowledged; carrier registration remains separately required\n");
                for(auto &query:queries)if(!query.pending&&(query.message==0x90||query.message==0x20||query.message==0x21)) {
                    query.done=false;query.refresh=0;query.attempts=0;
                }
            }
            ++replies;state(index,message,false,sdu,bytes);return true;
        }
        return true;
    }
    void report()const {
        IOLog("Pong IMS: services=%u/%u bound=%u/%u registration=%u tech=%u voice=%u SMS=%u voice_tech=%u error=%u\n",
            present[0],present[1],bound[0],bound[1],registration,technology,voice,sms,voiceTechnology,lastError);
        IOLog("Pong IMS registration: physical_reason=%u enable_requested=%u; no carrier response manufactured\n",registrationError,registrationRequested);
        IOLog("Pong IMS policy: voice_enabled=%u registration_enabled=%u replies=%u indications=%u failures=%u; physical modem results, call audio unqualified\n",
            voiceEnabled,registrationEnabled,replies,indications,failures);
        for(const auto &q:queries)if(q.error)IOLog("Pong IMS request: service=%u message=%x error=%u attempts=%u\n",q.endpoint?33:18,q.message,q.error,q.attempts);
    }
} modemIms;
