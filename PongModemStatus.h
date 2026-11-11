/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Native MPSS QMI capability/lifecycle checks needed before the iOS QMUX
 * backend is published. Read-only DMS revision,NAS serving-system,UIM card
 * status over actual discovered endpoints; no radio/SIM state fabricated.
 * Message/TLV layouts follow the public libqmi service definitions.
 */
constexpr uint32_t ModemStatusPort=0x110;
struct ModemStatusRequest {
    uint32_t service;uint16_t message,transaction=0;
    PongQrtrServer endpoint{};bool present=false,pending=false,answered=false;
    unsigned attempts=0;uint64_t deadline=0,refresh=0;
    uint32_t last_error=0,last_failure=0;
};
ModemStatusRequest modemStatusRequests[]={{2,0x23},{3,0x24},{11,0x2f},{2,0x2d},{2,0x25},{2,0x2e},{2,0x24},{3,0x1e},{11,0x3a},{2,0x7c}};
uint32_t modemOnlineQueued;
bool modemOnlineActive;
uint8_t modemOnlineMode=0,modemOnlineSentMode=0;
uint16_t modemStatusTransaction;
uint32_t modemStatusReplies,modemStatusErrors,modemRevisionBytes;
uint32_t modemRegistration=~0u,modemCsAttach=~0u,modemPsAttach=~0u,modemCards=~0u,modemFirstCard=~0u;
uint32_t modemOperatingMode=~0u,modemFirstCardError=~0u;
uint32_t modemOfflineReason=~0u,modemHardwareRestricted=~0u;
uint32_t modemInitializationState=~0u,modemInitializationFailure=~0u;
void modemStatusServer(const PongQrtrServer *s,bool added) {
    for(auto &request:modemStatusRequests)if(s->service==request.service) {
        if(added&&(!request.present||(s->instance>>8)<(request.endpoint.instance>>8))) {
            request.endpoint=*s;request.present=true;request.pending=request.answered=false;request.attempts=0;request.refresh=0;
        } else if(!added&&request.present&&s->node==request.endpoint.node&&s->port==request.endpoint.port) {
            request.present=request.pending=request.answered=false;
        }
    }
}
bool modemStatusReceive(uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    QcomQmiMessage m{};
    if(qcom_qmi_parse(static_cast<const uint8_t *>(data),bytes,&m)||m.type!=QCOM_QMI_RESPONSE)return false;
    for(auto &request:modemStatusRequests)if(request.present&&request.pending&&
        request.endpoint.node==node&&request.endpoint.port==port&&request.transaction==m.transaction&&request.message==m.message) {
        request.pending=false;
        uint32_t size=0;const auto *result=qcom_qmi_tlv(&m,2,&size);
        if(!result||size!=4||ms16(result)) {
            request.last_failure=1;request.last_error=result&&size==4?ms16(result+2):~0u;
            ++modemStatusErrors;
            if(request.message==0x2e&&request.service==2) {
                modemOnlineActive=false;
                unsigned n=0;const auto *extended=qcom_qmi_tlv(&m,0xe0,&n);
                IOLog("PongModem radio: actual target=%u error=%u extended_error=%x response_bytes=%u\n",
                    modemOnlineSentMode,request.last_error,extended&&n==4?ms32(extended):~0u,bytes);
                const auto *reason=qcom_qmi_tlv(&m,0x10,&n);
                IOLog("PongModem radio: physical initialization failure bytes=%u reason=%x (1=RF software,2=RF hardware,3=GPS)\n",
                    reason?n:0,reason&&n==4?ms32(reason):~0u);
                // 264/265 proved LOW_POWER recovery is InvalidTransition60
                // and ONLINE failure1 is physical RF software init. Keep
                // the real refusal and inspect its dependency, no cycling.
            }
            else request.refresh=nowMs()+30000;
            IOLog("PongModem: actual QMI status service=%u request=%x refused error=%u\n",request.service,request.message,result&&size==4?ms16(result+2):~0u);return true;
        }
        const auto *field=qcom_qmi_tlv(&m,request.service==11||request.service==3&&request.message==0x1e||request.service==2&&request.message==0x7c?0x10:
            request.service==2&&request.message==0x25?0x11:1,&size);
        bool valid=false;
        if(request.service==2&&request.message==0x2e) {
            // Only record the physical response. Re-read operating mode
            // and NAS; accepting the command is not proof of ONLINE.
            valid=true;modemOnlineActive=false;
            for(auto &query:modemStatusRequests)if(query.service==3||query.service==11||query.message==0x2d) {
                if(!query.pending){query.answered=false;query.attempts=0;query.refresh=0;}
            }
        }
        if(request.service==2&&request.message==0x23&&field&&size&&size<=256){
            modemRevisionBytes=size;valid=true;
            pong_baseband_transport_revision(reinterpret_cast<const char *>(field),size);
        }
        if(request.service==2&&request.message==0x2d&&field&&size==1){
            modemOperatingMode=field[0];valid=true;
            uint32_t n=0;const auto *reason=qcom_qmi_tlv(&m,0x10,&n);
            modemOfflineReason=reason?(n==2?ms16(reason):n==4?ms32(reason):~0u):~0u;
            const auto *restricted=qcom_qmi_tlv(&m,0x11,&n);
            modemHardwareRestricted=restricted?(n==1?restricted[0]:n==4?ms32(restricted):~0u):~0u;
            IOLog("PongModem: actual DMS mode=%u offline_reason=%x hardware_restricted=%u; physical optional fields only\n",modemOperatingMode,modemOfflineReason,modemHardwareRestricted);
        }
        if(request.service==2&&request.message==0x7c) {
            unsigned n=0;const auto *failure=qcom_qmi_tlv(&m,0x11,&n);
            if((!field||size==4)&&(!failure||n==4)) {
                modemInitializationState=field?ms32(field):~0u;
                modemInitializationFailure=failure?ms32(failure):~0u;valid=true;
                IOLog("PongModem: physical initialization state=%u failure=%u; 2=ready3=failed and1=RFsoftware\n",modemInitializationState,modemInitializationFailure);
            }
        }
        if(request.service==2&&request.message==0x25&&field)
            valid=pong_baseband_transport_imei(reinterpret_cast<const char *>(field),size);
        if(request.service==2&&request.message==0x24) {
            // An empty successful MSISDN is legitimate: not every SIM
            // stores its telephone number. Never synthesize a subscriber.
            valid=pong_baseband_transport_msisdn(reinterpret_cast<const char *>(field),field?size:0);
        }
        if(request.service==3&&request.message==0x1e&&field&&size>=2) {
            const unsigned count=ms16(field);
            if(count&&count<=8192&&count==size-2)
                valid=pong_baseband_transport_nas_messages(field+2,count);
        }
        if(request.service==3&&request.message==0x24&&field&&size>=5&&size>=5u+field[4]) {
            modemRegistration=field[0];modemCsAttach=field[1];modemPsAttach=field[2];valid=true;
        }
        if(request.service==11&&request.message==0x3a)
            valid=modemSimConfiguration(static_cast<const uint8_t *>(data),bytes);
        if(request.service==11&&request.message==0x2f&&field&&size>=9&&pong_baseband_transport_slots(field,size)) {
            modemSimCard(field,size);
            modemCards=field[8];
            if(!modemCards){modemFirstCard=~0u;valid=true;}
            else if(size>=14){modemFirstCard=field[9];modemFirstCardError=field[13];valid=true;}
        }
        if(!valid){request.last_failure=2;request.last_error=EINVAL;request.refresh=nowMs()+30000;++modemStatusErrors;return true;}
        request.answered=true;request.last_failure=request.last_error=0;++modemStatusReplies;
        if(request.service==11||request.service==3||request.message==0x2d||request.message==0x24)
            request.refresh=nowMs()+30000;
        if(request.service==11&&modemSim.card&&!modemSim.ready)
            request.refresh=nowMs()+2000; // follow physical application selection without30s stale UI
        if(request.service==2&&request.message==0x7c)request.refresh=nowMs()+30000;
        // No revision/IMEI/ICCID/IMSI/operator or user traffic is printed.
        IOLog("PongModem: actual QMI status service=%u request=%x accepted; NAS=%u CS=%u PS=%u cards=%u first_card_state=%u\n",
            request.service,request.message,modemRegistration,modemCsAttach,modemPsAttach,modemCards,modemFirstCard);
        return true;
    }
    return false;
}
void modemStatusPoll() {
    const uint64_t now=nowMs();
    if(__atomic_exchange_n(&modemOnlineQueued,0u,__ATOMIC_ACQ_REL)) {
        modemOnlineActive=true;modemOnlineMode=0;
        auto &command=modemStatusRequests[5];
        if(!command.pending){command.answered=false;command.attempts=0;}
    }
    for(auto &request:modemStatusRequests) {
        const bool onlineCommand=request.service==2&&request.message==0x2e;
        if(onlineCommand&&!modemOnlineActive)continue;
        if(request.refresh&&now>=request.refresh&&!request.pending) {
            request.answered=false;request.attempts=0;request.refresh=0;
        }
        if(!request.present||request.answered)continue;
        if(request.pending) {
            if(now<request.deadline)continue;
            request.pending=false;request.last_failure=3;request.last_error=ETIMEDOUT;
            if(!onlineCommand)request.refresh=now+30000;
            else if(request.attempts>=3)modemOnlineActive=false;
            ++modemStatusErrors;
        }
        if(request.attempts>=3)continue;
        uint8_t query[14]={QCOM_QMI_REQUEST};uint16_t txn=++modemStatusTransaction;
        if(!txn)txn=++modemStatusTransaction;
        msPut(query+1,txn,2);msPut(query+3,request.message,2);
        unsigned bytes=7;
        if(onlineCommand) {
            // libqmi DMS SetOperatingMode0x2e, TLV1/len1/ONLINE0.
            // This is transient runtime control, not an NV/EFS write.
            msPut(query+5,4,2);query[7]=1;query[8]=1;query[9]=0;query[10]=modemOnlineMode;bytes=11;
        } else if(request.service==11&&request.message==0x3a) {
            // Read automatic selection, personalization and subscription
            // hold configuration. Only the public halt boolean is logged.
            msPut(query+5,7,2);query[7]=0x10;query[8]=4;query[9]=0;
            msPut(query+10,7,4);bytes=14;
        }
        if(!pong_modem_qrtr_send(&control.qrtr,ModemStatusPort,request.endpoint.node,request.endpoint.port,query,bytes)) {
            if(onlineCommand)modemOnlineSentMode=modemOnlineMode;
            request.transaction=txn;request.pending=true;request.deadline=now+5000;++request.attempts;
        }
    }
}
