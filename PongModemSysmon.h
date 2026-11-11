/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Cape remoteproc SysMon: actual ADSP/MPSS lifecycle exchange over their
 * independent QRTR links. Protocol follows NothingOSS qcom_sysmon.c.
 * ADSP sends are copied through its existing GLINK owner queue; no second
 * reset, IPCC receiver or hardware FIFO owner is introduced.
 */
#include "ShengAdsp.h"
extern "C" bool pong_adsp_running(void);
constexpr uint32_t SysmonPort=0x103;
struct SysmonPeer {
    PongQrtrServer endpoint{};bool present=false,pending=false;
    uint16_t transaction=0;uint32_t state=~0u,acknowledged=~0u,attempts=0;uint64_t deadline=0;
};
IOLock *sysmonLock;
PongModemQrtr adspRouter;
ShengAdspChannel *adspRouterChannel;
uint8_t adspRouterWorkspace[PongQrtrHeader+PongQrtrMaxPayload];
SysmonPeer adspSysmon,modemSysmon;
uint32_t sysmonAcks,sysmonErrors;
int sysmonAdspSend(void *,const void *data,uint32_t bytes) {
    return bytes<=SHENG_ADSP_MAX_MESSAGE&&adspRouterChannel?
        sheng_adsp_send(adspRouterChannel,data,bytes):EMSGSIZE;
}
void sysmonEndpoint(SysmonPeer &peer,const PongQrtrServer *s,bool added,uint32_t instance) {
    if(s->service!=43||s->instance!=instance)return;
    if(added){peer={};peer.endpoint=*s;peer.present=true;}
    else if(peer.present&&peer.endpoint.node==s->node&&peer.endpoint.port==s->port)peer={};
}
bool sysmonReply(SysmonPeer &peer,uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    QcomQmiMessage m{};
    if(!peer.present||peer.endpoint.node!=node||peer.endpoint.port!=port||
       qcom_qmi_parse(static_cast<const uint8_t *>(data),bytes,&m)||
       m.type!=QCOM_QMI_RESPONSE||m.message!=0x25||!peer.pending||m.transaction!=peer.transaction)return false;
    uint32_t size=0;const auto *result=qcom_qmi_tlv(&m,2,&size);
    peer.pending=false;
    if(result&&size==4&&!ms16(result)){peer.acknowledged=peer.state;peer.attempts=0;++sysmonAcks;IOLog("PongModem: actual SysMon lifecycle ACK state=%u node=%u\n",peer.state,node);}
    else {++sysmonErrors;IOLog("PongModem: actual SysMon lifecycle refusal state=%u error=%u\n",peer.state,result&&size==4?ms16(result+2):~0u);}
    return true;
}
void sysmonAdspServer(void *,const PongQrtrServer *s,bool added) {
    sysmonEndpoint(adspSysmon,s,added,0x1402);
}
bool sysmonAdspReceive(void *,uint32_t local,uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    if(local==SysmonPort)return sysmonReply(adspSysmon,node,port,data,bytes);
    if(local==0x100) {
        uint8_t answer[512];const uint32_t length=qcom_servloc_answer(PongPdDomains,
            sizeof PongPdDomains/sizeof *PongPdDomains,static_cast<const uint8_t *>(data),bytes,answer,sizeof answer);
        if(length)(void)pong_modem_qrtr_send(&adspRouter,local,node,port,answer,length);
        return length!=0;
    }
    return false;
}
void sysmonAdspState(void *,int up) {
    if(!sysmonLock)return;IOLockLock(sysmonLock);
    if(up)(void)pong_modem_qrtr_start(&adspRouter);
    else {pong_modem_qrtr_disconnect(&adspRouter);adspSysmon={};}
    IOLockUnlock(sysmonLock);
}
void sysmonAdspData(void *,const uint8_t *data,uint32_t bytes) {
    if(!sysmonLock)return;IOLockLock(sysmonLock);
    (void)pong_modem_qrtr_receive(&adspRouter,data,bytes);
    (void)pong_modem_qrtr_poll(&adspRouter);
    IOLockUnlock(sysmonLock);
}
bool sysmonStart() {
    if(sysmonLock)return adspRouterChannel!=nullptr;
    sysmonLock=IOLockAlloc();if(!sysmonLock)return false;
    const PongModemQrtrOps ops{sysmonAdspSend,sysmonAdspServer,sysmonAdspReceive,nullptr};
    if(!pong_modem_qrtr_init(&adspRouter,1,adspRouterWorkspace,sizeof adspRouterWorkspace,&ops,nullptr))return false;
    if(pong_modem_qrtr_register(&adspRouter,QCOM_SERVLOC_SERVICE,QCOM_SERVLOC_INSTANCE,0x100))return false;
    const ShengAdspClient client{sysmonAdspState,sysmonAdspData};
    adspRouterChannel=sheng_adsp_channel("IPCRTR",0x4000,2,1,&client,nullptr);
    return adspRouterChannel!=nullptr;
}
void sysmonModemServer(const PongQrtrServer *server,bool added) {
    if(!sysmonLock)return;IOLockLock(sysmonLock);
    sysmonEndpoint(modemSysmon,server,added,0x1202);IOLockUnlock(sysmonLock);
}
bool sysmonModemReceive(uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    if(!sysmonLock)return false;IOLockLock(sysmonLock);
    const bool received=sysmonReply(modemSysmon,node,port,data,bytes);IOLockUnlock(sysmonLock);return received;
}
void sysmonSend(PongModemQrtr &router,SysmonPeer &peer,const char *name,uint32_t state) {
    if(!peer.present)return;
    if(peer.pending) {
        if(nowMs()<peer.deadline)return;
        peer.pending=false;++sysmonErrors;
        IOLog("PongModem: SysMon lifecycle reply timeout state=%u; no ACK inferred\n",peer.state);
    }
    if(peer.acknowledged==state)return;
    if(peer.state!=state)peer.attempts=0;
    if(peer.attempts>=3)return;
    uint8_t message[64]={};const uint32_t nameBytes=uint32_t(strlen(name));uint32_t at=7;
    message[0]=QCOM_QMI_REQUEST;const uint16_t transaction=uint16_t(peer.transaction+1);
    msPut(message+1,transaction,2);msPut(message+3,0x25,2);
    message[at++]=1;msPut(message+at,nameBytes+1,2);at+=2;message[at++]=uint8_t(nameBytes);
    memcpy(message+at,name,nameBytes);at+=nameBytes;
    const uint8_t tags[3]={2,3,0x10};const uint32_t values[3]={state,transaction,0};
    for(unsigned i=0;i<3;i++){message[at++]=tags[i];msPut(message+at,4,2);at+=2;msPut(message+at,values[i],4);at+=4;}
    msPut(message+5,at-7,2);
    if(!pong_modem_qrtr_send(&router,SysmonPort,peer.endpoint.node,peer.endpoint.port,message,at)) {
        peer.state=state;peer.transaction=transaction;peer.pending=true;peer.deadline=nowMs()+5000;++peer.attempts;
        IOLog("PongModem: actual SysMon queued %s state=%u; remote ACK pending\n",name,state);
    }
}
void sysmonPoll() {
    if(!sysmonLock)return;IOLockLock(sysmonLock);
    (void)pong_modem_qrtr_poll(&adspRouter);
    const bool modemUp=controlInitialized&&!control.failed&&(control.slave_state&Ready)&&!(control.slave_state&Fatal);
    // Native enum AFTER_POWERUP=1, AFTER_SHUTDOWN=3. Only notify hardware
    // observed running; unstarted CDSP/SLPI domains are never advertised up.
    if(modemUp&&pong_adsp_running())sysmonSend(control.qrtr,modemSysmon,"adsp",1);
    if(adspSysmon.present)sysmonSend(adspRouter,adspSysmon,"modem",modemUp?1:3);
    IOLockUnlock(sysmonLock);
}
