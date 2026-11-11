/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Adapted from UniXNU-sheng QcomQrtr protocol structure. Board-owned 64KiB
 * workspace replaces the reference's 512-byte stack packet: QMI/UIM messages
 * must not be truncated, and kernel stacks must not hold 64KiB arrays.
 */
#include "PongModemQrtr.h"
#include <string.h>
#include <sys/errno.h>
#include <IOKit/IOLib.h>
#include <kern/clock.h>
namespace {
constexpr uint32_t Ctrl=0xfffffffeu,Broadcast=0xffffffffu;
enum {Data=1,Hello=2,Bye=3,NewServer=4,DelServer=5,DelClient=6,Resume=7,Exit=8,NewLookup=10};
uint32_t rd(const uint8_t *p){return p[0]|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
void wr(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=uint8_t(v>>(8*i));}
bool ready(const PongModemQrtr *q){return q && q->ops.transmit && q->workspace && q->capacity>=PongQrtrHeader+PongQrtrMaxPayload;}
void registrationTrace(PongModemQrtr *q,uint8_t stage,uint32_t local,uint32_t node,uint32_t port,const uint8_t *sdu,uint32_t bytes) {
    unsigned service=0;
    for(unsigned i=0;i<q->server_count;i++)if(q->servers[i].node==node&&q->servers[i].port==port){service=q->servers[i].service;break;}
    if(bytes<7)return;
    const uint16_t message=sdu[3]|uint16_t(sdu[4])<<8;
    const bool telephony=service==5||service==9;
    if(service!=3&&!telephony&&!(service==2&&message==0x2e)&&!(service==11&&(message==0x38||message==0x3a||message==0x40)))return;
    if(uint32_t(sdu[5]|uint16_t(sdu[6])<<8)+7u!=bytes)return;
    uint32_t result=~0u;
    if(sdu[0]==2)for(unsigned at=7;at+3<=bytes;) {
        const unsigned n=sdu[at+1]|unsigned(sdu[at+2])<<8;
        if(n>bytes-at-3)break;
        if(sdu[at]==2&&n==4){result=(sdu[at+3]|unsigned(sdu[at+4])<<8)?sdu[at+5]|unsigned(sdu[at+6])<<8:0;break;}
        at+=3+n;
    }
    if(telephony) {
        static unsigned noted[2];const unsigned index=service==9;
        if(noted[index]++<96)IOLog("Pong call-SMS wire: service=%u direction=%s local=%x type=%u message=%x transaction=%u bytes=%u physical_error=%u; no numbers or message contents\n",
            service,stage==1?"TX":"RX",local,sdu[0],message,sdu[1]|uint16_t(sdu[2])<<8,bytes,result);
    }
    uint32_t operation=~0u;
    if(sdu[0]==0&&((service==2&&message==0x2e)||(service==3&&message==0x45)))
        for(unsigned at=7;at+3<=bytes;) {
            const unsigned n=sdu[at+1]|unsigned(sdu[at+2])<<8;
            if(n>bytes-at-3)break;
            if(sdu[at]==1&&n==1){operation=sdu[at+3];break;}
            at+=3+n;
        }
    uint64_t ns=0;absolutetime_to_nanoseconds(mach_absolute_time(),&ns);
    const uint32_t sequence=q->registration_sequence+1;
    auto &record=q->registration_trace[(sequence-1)%64];
    __atomic_store_n(&record.sequence,0u,__ATOMIC_RELEASE);
    record.millis=uint32_t(ns/1000000);record.local=local;record.node=node;record.port=port;
    record.result=result;record.operation=operation;record.message=message;record.transaction=sdu[1]|uint16_t(sdu[2])<<8;
    record.bytes=bytes;record.stage=stage;record.type=sdu[0];
    __atomic_store_n(&record.sequence,sequence,__ATOMIC_RELEASE);
    __atomic_store_n(&q->registration_sequence,sequence,__ATOMIC_RELEASE);
}
int emit(PongModemQrtr *q,uint32_t type,uint32_t from,uint32_t node,uint32_t port,const void *body,uint32_t bytes,bool confirm=false) {
    if(!ready(q) || bytes>PongQrtrMaxPayload || (bytes&&!body))return EINVAL;
    uint32_t padded=(bytes+3u)&~3u;uint8_t *p=q->workspace;
    wr(p,1);wr(p+4,type);wr(p+8,q->local_node);wr(p+12,from);wr(p+16,confirm?1u:0u);
    wr(p+20,bytes);wr(p+24,node);wr(p+28,port);
    if(bytes)memmove(p+PongQrtrHeader,body,bytes);
    if(padded!=bytes)memset(p+PongQrtrHeader+bytes,0,padded-bytes);
    int result=q->ops.transmit(q->context,p,PongQrtrHeader+padded);
    if(result)q->tx_refused++;else q->tx++;
    return result;
}
int control(PongModemQrtr *q,uint32_t command,uint32_t node,const uint32_t *words=nullptr) {
    uint8_t body[20]={};wr(body,command);
    if(words)for(unsigned i=0;i<4;i++)wr(body+4+4*i,words[i]);
    return emit(q,command,Ctrl,node,Ctrl,body,sizeof body);
}
void server(PongModemQrtr *q,const uint8_t *body,bool add) {
    PongQrtrServer s={rd(body+4),rd(body+8),rd(body+12),rd(body+16)};
    if(!s.service&&!s.instance&&!s.node&&!s.port)return; // real end-of-list record
    if(!s.service || s.node==Broadcast || s.port==Ctrl || s.port==Broadcast){q->invalid++;return;}
    for(unsigned i=0;i<q->server_count;i++) {
        auto old=q->servers[i];
        if(old.node!=s.node || old.port!=s.port)continue;
        if(add && old.service==s.service && old.instance==s.instance)return;
        if(q->ops.server)q->ops.server(q->context,&old,false);
        q->servers[i]=q->servers[--q->server_count];break;
    }
    if(!add)return;
    if(q->server_count==PongQrtrMaxServers){q->invalid++;return;}
    q->servers[q->server_count++]=s;
    if(q->ops.server)q->ops.server(q->context,&s,true);
}
}
bool pong_modem_qrtr_init(PongModemQrtr *q,uint32_t node,void *workspace,uint32_t bytes,const PongModemQrtrOps *ops,void *context) {
    if(!q || node==Ctrl || node==Broadcast || !workspace || bytes<PongQrtrHeader+PongQrtrMaxPayload || !ops || !ops->transmit)return false;
    memset(q,0,sizeof *q);q->local_node=node;q->remote_node=Broadcast;q->workspace=(uint8_t *)workspace;
    q->capacity=bytes;q->ops=*ops;q->context=context;return true;
}
int pong_modem_qrtr_register(PongModemQrtr *q,uint32_t service,uint32_t instance,uint32_t port) {
    if(!ready(q)||!service||port==Ctrl||port==Broadcast)return EINVAL;
    for(unsigned i=0;i<q->local_count;i++) {
        const auto &s=q->local_servers[i];
        if(s.port==port)return s.service==service&&s.instance==instance?0:EEXIST;
    }
    if(q->local_count==8)return ENOSPC;
    const unsigned i=q->local_count++;
    q->local_servers[i]={service,instance,q->local_node,port};q->local_dirty|=1u<<i;
    return 0;
}
int pong_modem_qrtr_start(PongModemQrtr *q) {
    if(!ready(q))return EINVAL;
    int result=control(q,Hello,q->remote_node);if(!result)q->hello_sent=true;return result;
}
int pong_modem_qrtr_poll(PongModemQrtr *q) {
    if(!ready(q))return EINVAL;
    if(!q->hello_sent)return pong_modem_qrtr_start(q);
    if(q->hello_received && !q->lookup_sent) {
        int result=control(q,NewLookup,q->remote_node);if(!result)q->lookup_sent=true;return result;
    }
    // Advertise only endpoints with an actual registered request handler.
    // A missing remote intent retains the announcement for the next poll.
    for(unsigned i=0;q->hello_received && i<q->local_count;i++)if(q->local_dirty&(1u<<i)) {
        const auto &s=q->local_servers[i];const uint32_t words[4]={s.service,s.instance,s.node,s.port};
        const int result=control(q,NewServer,q->remote_node,words);
        if(result)return result;
        q->local_dirty&=~(1u<<i);
    }
    // GLINK may temporarily lack a receive intent. Keep the actual
    // confirm_rx acknowledgements until queued, otherwise a modem can stop
    // sending forever even though its previous packet was consumed.
    while(q->hello_received && q->resume_count) {
        const auto &pending=q->pending_resume[0];uint8_t body[20]={};
        wr(body,Resume);wr(body+4,pending.node);wr(body+8,pending.port);
        int result=emit(q,Resume,pending.port,pending.destination,pending.destination_port,body,sizeof body);
        if(result)return result;
        q->resumes++;q->resume_count--;
        memmove(q->pending_resume,q->pending_resume+1,q->resume_count*sizeof q->pending_resume[0]);
    }
    return 0;
}
void pong_modem_qrtr_disconnect(PongModemQrtr *q) {
    if(!ready(q))return;
    while(q->server_count) {
        auto s=q->servers[--q->server_count];if(q->ops.server)q->ops.server(q->context,&s,false);
    }
    bool was=q->hello_received;q->hello_received=q->hello_sent=q->lookup_sent=false;q->remote_node=Broadcast;q->resume_count=0;q->local_dirty=(1u<<q->local_count)-1;
    memset(q->tx_flow,0,sizeof q->tx_flow);
    memset(q->qmi_receipts,0,sizeof q->qmi_receipts);
    if(was && q->ops.link)q->ops.link(q->context,false);
}
int pong_modem_qrtr_receive(PongModemQrtr *q,const void *packet,uint32_t bytes) {
    if(!ready(q) || !packet || bytes<PongQrtrHeader)return EINVAL;
    const auto *p=(const uint8_t *)packet;
    uint32_t type=rd(p+4),node=rd(p+8),port=rd(p+12),confirm=rd(p+16),size=rd(p+20),destination=rd(p+24),to=rd(p+28);
    if(rd(p)!=1 || node==Broadcast || size>PongQrtrMaxPayload || size>bytes-PongQrtrHeader ||
       bytes-PongQrtrHeader-size>3 || confirm>1 || (destination!=q->local_node && destination!=Broadcast)) {
        q->invalid++;return EINVAL;
    }
    const uint8_t *body=p+PongQrtrHeader;q->rx++;
    if(type==Data) {
        if(to==Ctrl || !q->hello_received){q->invalid++;return EPROTO;}
        registrationTrace(q,2,to,node,port,body,size);
        // A matched physical QMI response proves its request was consumed,
        // even when firmware omits the aggregate RESUME. Retire exactly
        // that real request's credit once, never a timer or guessed reply.
        // Epoch matching prevents an old response subtracting credit from
        // a new flow after a real RESUME reset.
        if(size>=7&&body[0]==2&&uint32_t(body[5]|uint16_t(body[6])<<8)+7u<=size) {
            const uint16_t txn=body[1]|uint16_t(body[2])<<8,msg=body[3]|uint16_t(body[4])<<8;
            for(auto &receipt:q->qmi_receipts)if(receipt.used&&receipt.from==to&&receipt.node==node&&receipt.port==port&&receipt.transaction==txn&&receipt.message==msg) {
                auto &flow=q->tx_flow[receipt.flow];
                if(flow.used&&flow.node==node&&flow.port==port&&flow.epoch==receipt.epoch&&flow.pending) {
                    --flow.pending;++q->flow_response_consumed;
                }
                receipt.used=false;break;
            }
        }
        if(!q->ops.receive || !q->ops.receive(q->context,to,node,port,body,size))q->unrouted++;
        if(confirm) {
            // RESUME identifies the receiver endpoint (original dst),
            // which is the remote sender's flow-control destination key.
            // Echoing the source node/port leaves its pending count stuck.
            const uint32_t words[4]={q->local_node,to,0,0};
            uint8_t body[20]={};wr(body,Resume);wr(body+4,words[0]);wr(body+8,words[1]);
            if(!emit(q,Resume,to,node,port,body,sizeof body))q->resumes++;
            else {
                for(unsigned i=0;i<q->resume_count;i++)
                    if(q->pending_resume[i].node==q->local_node&&q->pending_resume[i].port==to&&q->pending_resume[i].destination==node&&q->pending_resume[i].destination_port==port)return 0;
                if(q->resume_count==64){q->invalid++;return ENOBUFS;}
                q->pending_resume[q->resume_count++]={q->local_node,to,node,port};
            }
        }
        return 0;
    }
    if(type==Resume) {
        // Unlike name-service controls, RESUME is addressed back to the
        // actual originating client, not necessarily QRTR_PORT_CTRL.
        if(size<12||rd(body)!=Resume||rd(body+4)!=node){q->invalid++;return EPROTO;}
        const uint32_t remotePort=rd(body+8);
        for(auto &flow:q->tx_flow)if(flow.used&&flow.node==node&&flow.port==remotePort) {
            const unsigned index=unsigned(&flow-q->tx_flow);
            flow.pending=0;++flow.epoch;q->flow_resumed++;
            for(auto &receipt:q->qmi_receipts)if(receipt.used&&receipt.flow==index)receipt.used=false;
            break;
        }
        return 0;
    }
    if(to!=Ctrl || size<4 || rd(body)!=type){q->invalid++;return EPROTO;}
    if(type==Hello) {
        if(q->hello_received && q->remote_node!=node)pong_modem_qrtr_disconnect(q);
        bool first=!q->hello_received;q->remote_node=node;q->hello_received=true;
        if(first)q->local_dirty=(1u<<q->local_count)-1;
        if(first && q->ops.link)q->ops.link(q->context,true);
        return pong_modem_qrtr_poll(q);
    }
    if(!q->hello_received){q->invalid++;return EPROTO;}
    if(type==NewLookup) {
        if(size<20){q->invalid++;return EPROTO;}
        const uint32_t service=rd(body+4),instance=rd(body+8);
        for(unsigned i=0;i<q->local_count;i++)if((!service||q->local_servers[i].service==service)&&
            (!instance||q->local_servers[i].instance==instance))q->local_dirty|=1u<<i;
        if(service) {
            bool present=false,noted=false;
            for(unsigned i=0;i<q->local_count;i++)
                present|=q->local_servers[i].service==service&&(!instance||q->local_servers[i].instance==instance);
            if(!present) {
                ++q->missing_lookup_total;
                for(unsigned i=0;i<q->missing_lookup_count;i++)
                    noted|=q->missing_lookups[i].service==service&&q->missing_lookups[i].instance==instance;
                if(!noted&&q->missing_lookup_count<16) {
                    q->missing_lookups[q->missing_lookup_count++]={service,instance};
                    IOLog("PongModem: physical peer requested missing host service=%u instance=%x node=%u; no endpoint fabricated\n",service,instance,node);
                }
            }
        }
        return pong_modem_qrtr_poll(q);
    }
    if(type==NewServer || type==DelServer) {
        if(size<20){q->invalid++;return EPROTO;}
        server(q,body,type==NewServer);
        if(type==DelServer) {
            for(auto &receipt:q->qmi_receipts)if(receipt.used&&receipt.node==rd(body+12)&&receipt.port==rd(body+16))receipt.used=false;
            for(auto &flow:q->tx_flow)
                if(flow.used&&flow.node==rd(body+12)&&flow.port==rd(body+16))flow={};
        }
    } else if(type==Bye || type==Exit) {
        if(node==q->remote_node)pong_modem_qrtr_disconnect(q);
    }
    return 0;
}
int pong_modem_qrtr_send(PongModemQrtr *q,uint32_t from,uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    if(!ready(q) || !q->hello_received)return ENETDOWN;
    if(node==Broadcast || from==Ctrl || port==Ctrl)return EINVAL;
    // QRTR low/high watermarks are5/10 per remote node+port. Count only
    // accepted GLINK packets; an unsuccessful attempt owns no credit.
    // All calls and Resume packets execute on the same GLINK owner thread.
    decltype(&q->tx_flow[0]) selected=nullptr;
    for(auto &flow:q->tx_flow)if(flow.used&&flow.node==node&&flow.port==port){selected=&flow;break;}
    if(!selected)for(auto &flow:q->tx_flow)if(!flow.used){flow={node,port,0,true};selected=&flow;break;}
    if(!selected)return ENOSPC;
    if(selected->pending>=10){q->flow_blocked++;return EAGAIN;}
    // Native iOS issues/cancels NAS operations concurrently. If only the
    // fifth request asks for RESUME, an unconsumed operation can withhold
    // the whole endpoint's acknowledgement while other requests complete.
    // Ask the physical NAS receiver to acknowledge each consumed packet;
    // keep the same10-credit cap and require actual ACK/response evidence.
    bool nasEndpoint=false;
    for(unsigned i=0;i<q->server_count;i++)
        if(q->servers[i].service==3&&q->servers[i].node==node&&q->servers[i].port==port){nasEndpoint=true;break;}
    const bool confirm=nasEndpoint||selected->pending+1==5;
    int result=emit(q,Data,from,node,port,data,bytes,confirm);
    if(!result){selected->pending++;if(confirm)q->flow_confirmed++;
        registrationTrace(q,1,from,node,port,static_cast<const uint8_t *>(data),bytes);
        const auto *sdu=static_cast<const uint8_t *>(data);
        bool qmi=false;
        for(unsigned i=0;i<q->server_count;i++)if(q->servers[i].node==node&&q->servers[i].port==port&&q->servers[i].service<256)qmi=true;
        if(qmi&&bytes>=7&&sdu[0]==0&&uint32_t(sdu[5]|uint16_t(sdu[6])<<8)+7u==bytes) {
            const uint16_t txn=sdu[1]|uint16_t(sdu[2])<<8,msg=sdu[3]|uint16_t(sdu[4])<<8;
            for(auto &receipt:q->qmi_receipts)if(!receipt.used) {
                receipt={true,txn,msg,from,node,port,uint32_t(selected-q->tx_flow),selected->epoch};break;
            }
        }
    }
    return result;
}
int pong_modem_qrtr_delete_client(PongModemQrtr *q,uint32_t port) {
    if(!ready(q) || !q->hello_received)return ENETDOWN;
    if(port==Ctrl || port==Broadcast)return EINVAL;
    uint32_t words[4]={q->local_node,port,0,0};const int result=control(q,DelClient,q->remote_node,words);
    if(!result)for(auto &receipt:q->qmi_receipts)if(receipt.used&&receipt.from==port)receipt.used=false;
    return result;
}
void pong_modem_qrtr_report_registration(const PongModemQrtr *q) {
    if(!q)return;
    const uint32_t end=__atomic_load_n(&q->registration_sequence,__ATOMIC_ACQUIRE);
    // Already-observed transactions add no information to later snapshots.
    static uint32_t reported;
    const uint32_t prior=__atomic_exchange_n(&reported,end,__ATOMIC_ACQ_REL);
    uint32_t begin=end>64?end-64:0;
    if(prior>begin&&prior<=end)begin=prior;
    for(uint32_t sequence=begin+1;sequence&&sequence<=end;sequence++) {
        const auto &source=q->registration_trace[(sequence-1)%64];
        if(__atomic_load_n(&source.sequence,__ATOMIC_ACQUIRE)!=sequence)continue;
        const auto record=source;
        if(__atomic_load_n(&source.sequence,__ATOMIC_ACQUIRE)!=sequence)continue;
        IOLog("Pong registration wire: seq=%u ms=%u direction=%s local=%x endpoint=%u:%u type=%u msg=%x txn=%u bytes=%u result=%u operation=%u; no subscriber contents\n",
            sequence,record.millis,record.stage==1?"TX":"RX",record.local,record.node,record.port,record.type,record.message,record.transaction,record.bytes,record.result,record.operation);
    }
}
