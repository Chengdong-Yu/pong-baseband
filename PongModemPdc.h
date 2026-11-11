/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Read-only physical PDC GetSelectedConfig22, following public libqmi.
 * Apple IPCC completion is not evidence that the actual modem selected a
 * Qualcomm platform/software configuration. Observe both independently;
 * never select, load, activate, delete or print a configuration/identity.
 */
constexpr uint32_t ModemPdcPort=0x114;
struct ModemPdc {
    PongQrtrServer endpoint{};bool present=false;
    struct Query {bool pending=false,acked=false,done=false,known=false,active=false,staged=false;
        uint16_t transaction=0;uint32_t token=0,error=0;unsigned attempts=0;uint64_t deadline=0;} queries[2]{};
    uint16_t next=0;
    void server(const PongQrtrServer *s,bool added) {
        if(s->service!=0x24)return;
        if(added&&(!present||(s->instance>>8)<(endpoint.instance>>8))) {
            endpoint=*s;present=true;for(auto &q:queries)q={};
        } else if(!added&&present&&endpoint.node==s->node&&endpoint.port==s->port) {
            present=false;for(auto &q:queries)q={};
        }
    }
    void poll() {
        if(!present)return;
        for(unsigned type=0;type<2;type++) {
            auto &q=queries[type];if(q.done)continue;
            if(q.pending) {
                if(nowMs()<q.deadline)continue;
                q.pending=false;q.error=ETIMEDOUT;
            }
            if(q.attempts>=3){q.done=true;continue;}
            uint8_t request[21]={0};const uint16_t txn=++next?next:++next;
            uint8_t value[4];cbd_wr32(value,type);
            unsigned used=7+cbd_tlv(request+7,sizeof request-7,1,value,4);
            const uint32_t token=uint32_t(txn)<<8|type;cbd_wr32(value,token);
            used+=cbd_tlv(request+used,sizeof request-used,0x10,value,4);
            cbd_request(request,txn,0x22,used-7);
            if(!pong_modem_qrtr_send(&control.qrtr,ModemPdcPort,endpoint.node,endpoint.port,request,used)) {
                q.pending=true;q.acked=false;q.transaction=txn;q.token=token;
                q.deadline=nowMs()+10000;++q.attempts;
            }
        }
    }
    bool receive(uint32_t node,uint32_t port,const uint8_t *sdu,unsigned bytes) {
        if(!present||endpoint.node!=node||endpoint.port!=port||!cbd_sdu_ok(sdu,bytes)||cbd_rd16(sdu+3)!=0x22)return true;
        if(sdu[0]==2) {
            for(auto &q:queries)if(q.pending&&q.transaction==cbd_rd16(sdu+1)) {
                const unsigned error=cbd_error(sdu,bytes);q.error=error;
                if(error){q.pending=false;q.done=true;}else q.acked=true;
                return true;
            }
        } else if(sdu[0]==4) {
            unsigned n=0;const auto *token=cbd_find(sdu,bytes,0x10,&n);
            if(!token||n!=4)return true;
            for(unsigned type=0;type<2;type++) {
                auto &q=queries[type];if(!q.pending||q.token!=cbd_rd32(token))continue;
                const auto *result=cbd_find(sdu,bytes,1,&n);
                if(!result||n!=2)return true;
                q.error=cbd_rd16(result);bool valid=true,active=false,staged=false;
                for(unsigned tag=0x11;tag<=0x12;tag++) {
                    const auto *id=cbd_find(sdu,bytes,tag,&n);
                    if(!id)continue;
                    if(!n||n!=1u+id[0]){valid=false;break;}
                    if(tag==0x11)active=id[0]!=0;else staged=id[0]!=0;
                }
                if(!valid)return true;
                q.pending=false;q.done=true;q.known=!q.error;
                q.active=q.known&&active;q.staged=q.known&&staged;
                IOLog("PongModem PDC: actual type=%u result=%u known=%u active_config=%u pending_config=%u; IDs and contents omitted, no configuration written\n",
                    type,q.error,q.known,q.active,q.staged);
                return true;
            }
        }
        return true;
    }
    void report()const {
        for(unsigned type=0;type<2;type++) {
            const auto &q=queries[type];
            IOLog("PongModem PDC snapshot: service=%u type=%u pending=%u ack=%u known=%u active=%u staged=%u error=%u attempts=%u; actual configuration metadata only\n",
                present,type,q.pending,q.acked,q.known,q.active,q.staged,q.error,q.attempts);
        }
    }
} modemPdc;
