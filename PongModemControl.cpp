/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "PongModemControl.h"
#include <string.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOLib.h>
#include "PongPlatformResources.h"
namespace {
constexpr uint32_t packet=PongQrtrHeader+PongQrtrMaxPayload;
bool fifo(QcomGlinkFifo f,bool optional) {
    // The shared descriptor exists before MPSS allocates FIFO1's data.
    // qcom_glink_init always resets our receive tail, so even an absent
    // remote data area requires the real descriptor's aligned indices.
    if(!f.data)return optional && !f.length && f.head && f.tail &&
        !(reinterpret_cast<uintptr_t>(f.head)&3) && !(reinterpret_cast<uintptr_t>(f.tail)&3);
    if(!f.head||!f.tail||f.length<64||(f.length&7)||
       (reinterpret_cast<uintptr_t>(f.head)&3)||(reinterpret_cast<uintptr_t>(f.tail)&3))return false;
    uint32_t head=*f.head,tail=*f.tail;
    return head<f.length && tail<f.length && !(head&7) && !(tail&7);
}
void kick(void *v){auto *c=static_cast<PongModemControl *>(v);c->ops.kick(c->context,0);}
int transmit(void *v,const void *data,uint32_t bytes) {
    auto *c=static_cast<PongModemControl *>(v);
    if(!c->transport_up||!c->ipcrtr||c->failed)return QcomGlinkNotOpen;
    return qcom_glink_send(&c->glink,c->ipcrtr,data,bytes);
}
void server(void *v,const PongQrtrServer *s,bool added) {
    auto *c=static_cast<PongModemControl *>(v);
    if(c->ops.qrtr.server)c->ops.qrtr.server(c->context,s,added);
}
bool receive(void *v,uint32_t local,uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    auto *c=static_cast<PongModemControl *>(v);
    return c->ops.qrtr.receive && c->ops.qrtr.receive(c->context,local,node,port,data,bytes);
}
void link(void *v,bool up) {
    auto *c=static_cast<PongModemControl *>(v);
    if(c->ops.qrtr.link)c->ops.qrtr.link(c->context,up);
}
void channel_state(void *v,QcomGlinkChannel *,int up) {
    auto *c=static_cast<PongModemControl *>(v);c->transport_up=up!=0;
    if(up)(void)pong_modem_qrtr_start(&c->qrtr);
    else pong_modem_qrtr_disconnect(&c->qrtr);
}
void channel_receive(void *v,QcomGlinkChannel *,const uint8_t *data,uint32_t bytes) {
    auto *c=static_cast<PongModemControl *>(v);
    if(pong_modem_qrtr_receive(&c->qrtr,data,bytes)<0)c->errors++;
}
void at_state(void *v,QcomGlinkChannel *,int up) {
    auto *c=static_cast<PongModemControl *>(v);c->at_up=up!=0;
    if(!up)c->at_ping_sent=false;
    IOLog("PongModem: actual DS AT channel %s\n",up?"up":"down");
}
void at_receive(void *v,QcomGlinkChannel *,const uint8_t *data,uint32_t bytes) {
    auto *c=static_cast<PongModemControl *>(v);++c->at_packets;c->at_bytes+=bytes;
    // Do not print identities or unsolicited SMS. Classify only actual
    // attention response text; a missing reply remains unconfirmed.
    bool ok=false,error=false;
    for(uint32_t i=0;i+3<bytes;++i) {
        if(data[i]=='\r'&&data[i+1]=='\n'&&data[i+2]=='O'&&data[i+3]=='K')ok=true;
        if(i+4<bytes&&data[i]=='E'&&data[i+1]=='R'&&data[i+2]=='R'&&data[i+3]=='O'&&data[i+4]=='R')error=true;
    }
    if(c->at_packets<=4)IOLog("PongModem: actual AT response packets=%u bytes=%u OK=%u ERROR=%u\n",c->at_packets,bytes,ok?1:0,error?1:0);
}
void ssm_state(void *v,QcomGlinkChannel *,int up) {
    auto *c=static_cast<PongModemControl *>(v);c->ssm_up=up!=0;
    IOLog("PongModem: actual SSM transport %s; secure mode not inferred\n",up?"up":"down");
}
bool ssm_field(const uint8_t *data,uint32_t &out) {
    uint32_t value=0;bool digit=false;
    for(unsigned n=0;n<10;n++) {
        if(data[n]==' '&&!digit)continue;
        if(data[n]<'0'||data[n]>'9'||value>(UINT32_MAX-(data[n]-'0'))/10)return false;
        value=value*10+data[n]-'0';digit=true;
    }
    if(!digit||data[10]!='|')return false;out=value;return true;
}
void ssm_receive(void *v,QcomGlinkChannel *,const uint8_t *data,uint32_t bytes) {
    auto *c=static_cast<PongModemControl *>(v);++c->ssm_packets;
    uint32_t command=0,error=0;
    if(bytes<22||bytes>256||!ssm_field(data,command)||!ssm_field(data+11,error)) {
        if(++c->ssm_invalid<=4)IOLog("PongModem: SSM unsupported actual frame bytes=%u; no secure reply fabricated\n",bytes);
        return;
    }
    c->ssm_last_command=command;c->ssm_last_error=error;
    if(c->ssm_packets<=8)IOLog("PongModem: actual SSM status command=%u error=%u bytes=%u\n",command,error,bytes);
}
}
bool pong_modem_control_init(PongModemControl *c,QcomGlinkFifo tx,QcomGlinkFifo rx,
    volatile uint32_t *out,volatile uint32_t *in,uint32_t qrtr_local_node,void *intents,uint32_t intent_bytes,
    void *workspace,uint32_t workspace_bytes,const PongModemControlOps *ops,void *context)
{
    if(!c||!ops||!ops->kick||!out||(reinterpret_cast<uintptr_t>(out)&3)||
       !intents||intent_bytes<2*packet||!workspace||workspace_bytes<packet||
       !fifo(tx,false)||!fifo(rx,true)||
       (in&&qcom_smp2p_check_in(in,0,1)))return false;
    memset(c,0,sizeof(*c));c->ops=*ops;c->context=context;
    qcom_smp2p_init_out(&c->smp2p,out,0,1);c->smp2p.in=in;
    c->stop_entry=qcom_smp2p_add_entry(&c->smp2p,"master-kernel");
    c->ipa_entry=qcom_smp2p_add_entry(&c->smp2p,"ipa");
    if(c->stop_entry<0||c->ipa_entry<0)return false;
    const PongModemQrtrOps qrtr={transmit,server,receive,link};
    if(!pong_modem_qrtr_init(&c->qrtr,qrtr_local_node,workspace,workspace_bytes,&qrtr,c))return false;
    qcom_glink_init(&c->glink,tx,rx,kick,c);
    const QcomGlinkClient client={channel_state,channel_receive};
    c->ipcrtr=qcom_glink_channel(&c->glink,"IPCRTR",packet,2,static_cast<uint8_t *>(intents),&client,c,1);
    if(!c->ipcrtr)return false;
    c->ops.kick(c->context,2);return true;
}
bool pong_modem_control_remote(PongModemControl *c,QcomGlinkFifo rx,volatile uint32_t *in)
{
    if(!c||c->failed||!fifo(rx,false)||!in||qcom_smp2p_check_in(in,0,1))return false;
    // Descriptor indices are owned by the shared partition, not copied.
    if(c->glink.rx.data && (c->glink.rx.data!=rx.data||c->glink.rx.head!=rx.head||
       c->glink.rx.tail!=rx.tail||c->glink.rx.length!=rx.length))return false;
    c->glink.rx=rx;c->smp2p.in=in;return true;
}
bool pong_modem_control_attach_at(PongModemControl *c,void *storage,uint32_t bytes)
{
    if(!c||c->failed||c->at||!storage||bytes<2*0x4000)return false;
    const QcomGlinkClient client={at_state,at_receive};
    c->at=qcom_glink_channel(&c->glink,"DS",0x4000,2,static_cast<uint8_t *>(storage),&client,c,1);
    return c->at!=nullptr;
}
bool pong_modem_control_attach_ssm(PongModemControl *c,void *storage,uint32_t bytes)
{
    if(!c||c->failed||c->ssm||!storage||bytes<512)return false;
    const QcomGlinkClient client={ssm_state,ssm_receive};
    c->ssm=qcom_glink_channel(&c->glink,"SSM_RTR_MODEM_APPS",256,2,static_cast<uint8_t *>(storage),&client,c,0);
    return c->ssm!=nullptr;
}
int pong_modem_control_poll(PongModemControl *c)
{
    if(!c||c->failed||!c->ipcrtr)return QcomGlinkNotOpen;
    if(c->smp2p.in) {
        uint32_t value=0,changed=0;
        if(qcom_smp2p_service(&c->smp2p,"slave-kernel",&value,&changed))c->ops.kick(c->context,2);
        c->slave_state=value;c->slave_changed=changed;
        if(changed&&c->ops.state)c->ops.state(c->context,value,changed);
        if(value&1u){pong_modem_control_reset(c);return QcomGlinkNotOpen;}
        uint32_t ipa=0,ipa_changed=0;
        if(qcom_smp2p_service(&c->smp2p,"ipa",&ipa,&ipa_changed))c->ops.kick(c->context,2);
        c->ipa_state=ipa;c->ipa_changed=ipa_changed;
        // Nothing's IPA5.1 query is rising bit0. Reply complete=bit0,
        // actual retained clock vote=bit1; neither bit means GSI/IPA ready.
        if((ipa&1)&&!c->ipa_clock_replied) {
            c->ipa_clock_on=c->ops.ipa_clock&&c->ops.ipa_clock(c->context);
            if(qcom_smp2p_update(&c->smp2p,c->ipa_entry,3,c->ipa_clock_on?3:1))c->ops.kick(c->context,2);
            c->ipa_clock_replied=true;
            IOLog("PongModem: actual IPA clock query=%x response=%x; datapath readiness separate\n",ipa,c->ipa_clock_on?3:1);
        }
    }
    int result=qcom_glink_poll(&c->glink);
    if(result<0){pong_modem_control_reset(c);return result;}
    if(c->transport_up)(void)pong_modem_qrtr_poll(&c->qrtr);
    if(c->at_up&&!c->at_ping_sent) {
        const char attention[]="AT\r";
        if(!qcom_glink_send(&c->glink,c->at,attention,sizeof attention-1))c->at_ping_sent=true;
    }
    return result;
}
int pong_modem_control_request_stop(PongModemControl *c,bool stop)
{
    if(!c||c->failed||c->stop_entry<0)return QcomGlinkNotOpen;
    // Q6V5 stop bit0 is owned by apps. No ready/ack bit is synthesized.
    if(qcom_smp2p_update(&c->smp2p,c->stop_entry,1u,stop?1u:0u))c->ops.kick(c->context,2);
    return 0;
}
void pong_modem_control_reset(PongModemControl *c)
{
    if(!c)return;c->failed=true;c->transport_up=false;c->at_up=false;c->ssm_up=false;
    if(c->ipa_entry>=0&&qcom_smp2p_update(&c->smp2p,c->ipa_entry,3,0))c->ops.kick(c->context,2);
    c->ipa_clock_replied=false;
    pong_modem_qrtr_disconnect(&c->qrtr);
}
namespace {
void modem_glink_event(void *v) {
    auto *d=static_cast<PongModemDoorbell *>(v);__atomic_fetch_add(&d->glink_events,1u,__ATOMIC_RELAXED);
    d->wake(d->context,PongModemGlinkEvent);
}
void modem_smp2p_event(void *v) {
    auto *d=static_cast<PongModemDoorbell *>(v);__atomic_fetch_add(&d->smp2p_events,1u,__ATOMIC_RELAXED);
    d->wake(d->context,PongModemSmp2pEvent);
}
}
int pong_modem_doorbell_init(PongModemDoorbell *d,void (*wake)(void *,uint32_t),void *context)
{
    if(!d||!wake)return kIOReturnBadArgument;
    if(d->wake && (d->wake!=wake||d->context!=context))return kIOReturnExclusiveAccess;
    d->wake=wake;d->context=context;
    if(!d->glink_registered) {
        int result=pong_ipcc_subscribe(2,0,modem_glink_event,d);
        if(result)return result;
        d->glink_registered=true;
    }
    if(!d->smp2p_registered) {
        int result=pong_ipcc_subscribe(2,2,modem_smp2p_event,d);
        if(result)return result;
        d->smp2p_registered=true;
    }
    return kIOReturnSuccess;
}
bool pong_modem_doorbell_send(uint32_t signal)
{
    if(signal!=0 && signal!=2)return false;
    return pong_ipcc_send(2,signal);
}
