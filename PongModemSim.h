/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Read-only UIM identity acquisition from the actual ready application.
 * libqmi UIM CardStatus/ReadTransparent wire ABI. No PIN, persistent
 * provisioning, logical-slot switching or SIM writes. A detected, unselected real USIM
 * may be selected for primary GW through the native runtime session API.
 * Missing/locked applications stay
 * missing/locked; no DMS legacy-UIM success is synthesized.
 */
#include "coachz_bb_data.h"
constexpr uint32_t ModemSimPort=0x112;
struct ModemSimReader {
    PongQrtrServer server{};bool present=false,card=false,ready=false,pending=false;
    bool selectNeeded=false,selectionAttempted=false;
    uint8_t type=0,state=0,aidBytes=0,aid[32]{};
    uint8_t step=0;unsigned attempts=0;uint16_t transaction=0,message=0;
    uint64_t deadline=0;uint32_t error=0,reads=0;
    uint16_t primaryGw=0xffff;uint8_t application=0xff;
    bool haltKnown=false,haltSubscription=false,subscriptionAttempted=false;
    uint32_t subscriptionError=0;
} modemSim;
bool modemSimConfiguration(const uint8_t *sdu,unsigned bytes) {
    unsigned n=0;const auto *halt=cbd_find(sdu,bytes,0x12,&n);
    if(halt&&(n!=1||halt[0]>1))return false;
    modemSim.haltKnown=halt!=nullptr;modemSim.haltSubscription=halt&&halt[0];
    IOLog("PongModem SIM: actual UIM halt_subscription known=%u value=%u primary_GW=%x; card state unchanged\n",
        modemSim.haltKnown,modemSim.haltSubscription,modemSim.primaryGw);
    return true;
}
void modemSimServer(const PongQrtrServer *server,bool added) {
    if(server->service!=11)return;
    if(added&&(!modemSim.present||(server->instance>>8)<(modemSim.server.instance>>8))) {
        modemSim.server=*server;modemSim.present=true;modemSim.pending=false;
        modemSim.step=0;modemSim.attempts=0;
    } else if(!added&&modemSim.present&&server->node==modemSim.server.node&&server->port==modemSim.server.port) {
        modemSim.present=modemSim.card=modemSim.ready=modemSim.pending=false;
        modemSim.selectNeeded=modemSim.selectionAttempted=false;
        modemSim.primaryGw=0xffff;modemSim.application=0xff;
        modemSim.haltKnown=modemSim.haltSubscription=modemSim.subscriptionAttempted=false;
        bzero(modemSim.aid,sizeof modemSim.aid);modemSim.aidBytes=0;
    }
}
void modemSimCard(const uint8_t *data,uint32_t bytes) {
    // Called only after the complete variable-sized CardStatus payload
    // passed the bridge's bounds parser. Primary physical slot remains1.
    uint8_t type=0,state=0,length=0,application=0xff;const uint8_t *aid=nullptr;
    const uint16_t primaryGw=bytes>=2?cbd_rd16(data):0xffff;
    bool card=bytes>=15&&data[8]&&data[9]==1;
    if(card) {
        unsigned at=15;
        for(unsigned n=0;n<data[14];n++) {
            const unsigned count=data[at+6];
            if((data[at]==1||data[at]==2)&&count<=32&&(!type||data[at]==2)) {
                type=data[at];state=data[at+1];length=count;aid=data+at+7;application=n;
                if(type==2)break;
            }
            at+=14+count;
        }
    }
    const bool ready=card&&type&&state==7;
    const bool identityChanged=modemSim.card!=card||modemSim.type!=type||
        modemSim.aidBytes!=length||(length&&memcmp(modemSim.aid,aid,length));
    const bool changed=identityChanged||modemSim.state!=state||modemSim.ready!=ready||modemSim.primaryGw!=primaryGw;
    if(!changed)return;
    const bool becameReady=ready&&!modemSim.ready;
    modemSim.card=card;modemSim.type=type;modemSim.state=state;modemSim.ready=ready;
    modemSim.primaryGw=primaryGw;modemSim.application=application;
    modemSim.aidBytes=length;bzero(modemSim.aid,sizeof modemSim.aid);if(length)memcpy(modemSim.aid,aid,length);
    modemSim.pending=false;modemSim.step=0;modemSim.attempts=0;modemSim.error=0;
    if(identityChanged) {
        modemSim.selectionAttempted=modemSim.subscriptionAttempted=false;
        modemSim.haltKnown=modemSim.haltSubscription=false;
    }
    // Runtime primary-GW application selection is needed on this modem
    // when both GW index bytes are FF and a real USIM remains DETECTED.
    // Do not steal another selected slot/application or bypass PIN/PUK.
    modemSim.selectNeeded=card&&type==2&&state==1&&length&&data[0]==0xff&&data[1]==0xff;
    pong_baseband_transport_sim_identity(0,nullptr,0); // revoke old card/application identity
    IOLog("PongModem SIM: actual slot1 card=%u application_type=%u state=%u ready=%u primary_GW=%x selected_app=%u; AID/identity omitted\n",card,type,state,ready,primaryGw,application);
    // Native ONLINE can precede physical SIM/application initialization.
    // Retry its still-current intent once on the real READY edge; do not
    // force radio state or retry over a later airplane/offline request.
    if(becameReady&&pong_modem_native_online_requested())(void)pong_modem_request_online();
}
void modemSimPoll() {
    const bool releaseSubscription=modemSim.ready&&modemSim.primaryGw==modemSim.application&&
        modemSim.haltKnown&&modemSim.haltSubscription&&!modemSim.subscriptionAttempted&&
        pong_modem_native_online_requested();
    if(!modemSim.present||!modemSim.card||(modemSim.step>=2&&!releaseSubscription))return;
    const auto now=nowMs();
    if(modemSim.pending) {
        if(now<modemSim.deadline)return;
        modemSim.pending=false;modemSim.error=ETIMEDOUT;
    }
    if(modemSim.attempts>=3){
        if(modemSim.message==0x38)modemSim.selectionAttempted=true;
        else if(modemSim.message==0x40)modemSim.subscriptionAttempted=true;
        else ++modemSim.step;
        modemSim.attempts=0;return;
    }
    uint8_t query[96]={},session[34]={},file[7]={},readInfo[4]={};
    const bool select=modemSim.selectNeeded&&!modemSim.selectionAttempted;
    const bool imsi=modemSim.step==1;const unsigned fileId=imsi?CBD_EF_IMSI:CBD_EF_ICCID;
    // ICCID can be read at card/MF level before application READY. IMSI
    // still waits for the physical application state; never infer readiness
    // from acceptance of the selection request.
    if(!select&&imsi&&!modemSim.ready)return;
    // ICCID: card-slot1/MF. IMSI: actual ready SIM/USIM application,
    // nonprovisioning slot1 with its real AID, no slot/session mutation.
    session[0]=imsi?4:6;session[1]=imsi?modemSim.aidBytes:0;
    if(session[1])memcpy(session+2,modemSim.aid,session[1]);
    cbd_wr16(file,fileId);file[2]=imsi?4:2;file[3]=0;file[4]=0x3f;
    if(imsi){file[5]=modemSim.type==2?0xff:0x20;file[6]=0x7f;}
    cbd_wr16(readInfo+2,imsi?9:10);
    unsigned used=7;
    if(releaseSubscription) {
        // Only release an explicitly reported modem subscription hold for
        // this actual READY primary-GW application. Never unlock a PIN or
        // manufacture SIM/network state. This is runtime UIM0x40, not NV.
        const uint8_t primary[2]={0,0},allow=1;
        used+=cbd_tlv(query+used,sizeof query-used,1,primary,sizeof primary);
        used+=cbd_tlv(query+used,sizeof query-used,2,&allow,1);
    } else if(select) {
        const uint8_t change[2]={0,1}; // actual UIM PrimaryGW, activate
        uint8_t application[34]={1,modemSim.aidBytes};
        memcpy(application+2,modemSim.aid,modemSim.aidBytes);
        used+=cbd_tlv(query+used,sizeof query-used,1,change,sizeof change);
        used+=cbd_tlv(query+used,sizeof query-used,0x10,application,2+modemSim.aidBytes);
    } else {
        used+=cbd_tlv(query+used,sizeof query-used,1,session,2+session[1]);
        used+=cbd_tlv(query+used,sizeof query-used,2,file,3+file[2]);
        used+=cbd_tlv(query+used,sizeof query-used,3,readInfo,sizeof readInfo);
    }
    uint16_t transaction=modemSim.transaction+1;if(!transaction)transaction=1;
    const uint16_t message=releaseSubscription?0x40:select?0x38:CBD_UIM_READ_TRANSPARENT;
    cbd_request(query,transaction,message,used-7);
    const auto &server=modemSim.server;
    if(!pong_modem_qrtr_send(&control.qrtr,ModemSimPort,server.node,server.port,query,used)) {
        modemSim.transaction=transaction;modemSim.message=message;modemSim.pending=true;modemSim.deadline=now+5000;++modemSim.attempts;
    }
}
bool modemSimReceive(uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    const auto *sdu=static_cast<const uint8_t *>(data);
    if(!modemSim.pending||!modemSim.present||node!=modemSim.server.node||port!=modemSim.server.port||
       !cbd_sdu_ok(sdu,bytes)||sdu[0]!=2||cbd_rd16(sdu+1)!=modemSim.transaction||cbd_rd16(sdu+3)!=modemSim.message)return true;
    modemSim.pending=false;modemSim.error=cbd_error(sdu,bytes);
    if(modemSim.message==0x40) {
        modemSim.subscriptionAttempted=true;modemSim.subscriptionError=modemSim.error;modemSim.attempts=0;
        IOLog("PongModem SIM: actual primary-GW Subscription OK response error=%u; radio/registration still require physical confirmation\n",modemSim.error);
        if(!modemSim.error&&modemSim.ready&&pong_modem_native_online_requested())(void)pong_modem_request_online();
        return true;
    }
    if(modemSim.message==0x38) {
        modemSim.selectionAttempted=true;modemSim.attempts=0;
        IOLog("PongModem SIM: actual slot1 primary-GW selection response error=%u; READY still requires card-status indication\n",modemSim.error);
        return true;
    }
    const bool imsi=modemSim.step==1;bool valid=false;uint8_t content[16];
    if(!modemSim.error) {
        const unsigned length=cbd_uim_read_content(sdu,bytes,content,sizeof content);
        valid=pong_baseband_transport_sim_identity(imsi?CBD_EF_IMSI:CBD_EF_ICCID,content,length);
        if(!valid)modemSim.error=EINVAL;
    }
    if(valid)++modemSim.reads;
    IOLog("PongModem SIM: actual slot1 %s read valid=%u error=%u; subscriber contents omitted\n",imsi?"IMSI":"ICCID",valid,modemSim.error);
    ++modemSim.step;modemSim.attempts=0;return true;
}
