/* SPDX-License-Identifier: BSD-2-Clause
 * Native22G100 creates more NAS logical clients than this modem accepts.
 * Keep two real QRTR control points, one per physical subscription, and
 * translate transactions back to their original QMUX client. All methods
 * run with bbGate on the existing MPSS transport owner; no second reader.
 * NAS BindSubscription45 uses the public NAS0/1 subscription enum, not a
 * SIM-presence claim. Results and indications always come from the modem.
 */
struct PongNasMultiplexer {
    static constexpr uint32_t Port=0x130;
    struct Client {uint32_t owner=0,known=0,enabled=0;uint8_t subscription=0;uint16_t error=0;};
    struct Request {
        bool used=false;uint8_t subscription=0;uint16_t transaction=0,original=0,message=0;
        uint32_t slot=0,owner=0,known=0,enabled=0,wireKnown=0;
    };
    struct Backend {bool used=false;uint32_t node=0,port=0,reportsKnown=0;uint16_t next=0;};
    Client clients[CBQ_MAX_CLIENTS]{};Request requests[128]{};Backend backends[2]{};
    uint32_t accepted=0,replies=0,indications=0,orphaned=0,blocked=0,bindErrors=0;
    uint32_t owner(unsigned slot)const {
        const auto &c=bridge.client[slot];
        return c.used&&c.service==3?1u+c.cid+(uint32_t(c.channel)<<8):0;
    }
    bool reportBoolean(unsigned type)const {
        // Public NAS RegisterIndications3 boolean fields. Preserve every
        // other field verbatim; do not OR arbitrary enum/structured TLVs.
        return type==0x10||(type>=0x12&&type<=0x15)||(type>=0x17&&type<=0x20);
    }
    bool stateRequest(unsigned message)const {return message==3||message==0x45;}
    void reset() {
        for(auto &c:clients)c={};for(auto &r:requests)r={};for(auto &b:backends)b={};
    }
    void release(unsigned slot) {
        clients[slot]={};
        // A closed native client no longer receives replies. Retain the
        // real wire transaction until its response or actual DEL_CLIENT;
        // it may still hold a backend's state-changing operation.
        for(auto &r:requests)if(r.used&&r.slot==slot)r.owner=0;
    }
    void poll() {
        for(unsigned slot=0;slot<CBQ_MAX_CLIENTS;slot++)
            if(clients[slot].owner&&clients[slot].owner!=owner(slot))release(slot);
        for(unsigned sub=0;sub<2;sub++)if(backends[sub].used) {
            bool users=false;
            for(const auto &c:clients)if(c.owner&&c.subscription==sub){users=true;break;}
            if(!users&&!pong_modem_qrtr_delete_client(transport,Port+sub)) {
                for(auto &r:requests)if(r.used&&r.subscription==sub)r={};
                // Do not reuse a transaction number for a new native
                // generation while a late old response may be in flight.
                const uint16_t next=backends[sub].next;
                backends[sub]={};backends[sub].next=next;
            }
        }
    }
    bool frame(unsigned slot,const uint8_t *sdu,unsigned bytes,uint16_t transaction) {
        if(slot>=CBQ_MAX_CLIENTS||!owner(slot)||bytes>FrameMax-CBQ_HDR)return false;
        const auto &c=bridge.client[slot];
        const unsigned header=cbq_frame_header(scratch,bytes,3,c.cid);
        memcpy(scratch+header,sdu,bytes);cbd_wr16(scratch+header+1,transaction);
        return push(c.channel,scratch,header+bytes);
    }
    unsigned reporting(unsigned slot,unsigned sub,const uint8_t *sdu,unsigned bytes,
        uint32_t &changed,uint32_t &enabled,uint32_t &wireKnown) {
        changed=enabled=0;
        for(unsigned at=7;at<bytes;at+=3+cbd_rd16(sdu+at+1)) {
            const unsigned type=sdu[at],n=cbd_rd16(sdu+at+1);
            if(reportBoolean(type)&&n==1&&sdu[at+3]<=1) {
                const uint32_t bit=1u<<(type-0x10);changed|=bit;
                if(sdu[at+3])enabled|=bit;
            }
        }
        uint32_t known=backends[sub].reportsKnown,unionEnabled=0;
        for(unsigned i=0;i<CBQ_MAX_CLIENTS;i++) {
            const auto &c=clients[i];
            if(!c.owner||c.owner!=owner(i)||c.subscription!=sub||c.error)continue;
            known|=c.known|(i==slot?changed:0);
            unionEnabled|=i==slot?(c.enabled&~changed)|enabled:c.enabled;
        }
        unsigned used=7;
        memcpy(scratch,sdu,7);
        for(unsigned at=7;at<bytes;at+=3+cbd_rd16(sdu+at+1)) {
            const unsigned n=cbd_rd16(sdu+at+1),type=sdu[at];
            if(reportBoolean(type)&&n==1&&sdu[at+3]<=1)continue;
            if(used>FrameMax-3-n)return 0;
            memcpy(scratch+used,sdu+at,3+n);used+=3+n;
        }
        for(unsigned bit=0;bit<=16;bit++)if(known&(1u<<bit)) {
            const uint8_t value=bool(unionEnabled&(1u<<bit));
            const unsigned n=cbd_tlv(scratch+used,FrameMax-used,0x10+bit,&value,1);
            if(!n)return 0;used+=n;
        }
        wireKnown=known;cbd_wr16(scratch+5,used-7);return used;
    }
    int send(unsigned slot,uint32_t node,uint32_t port,const uint8_t *sdu,unsigned bytes) {
        if(slot>=CBQ_MAX_CLIENTS||!owner(slot)||!cbd_sdu_ok(sdu,bytes)||sdu[0]!=0)return EINVAL;
        auto &client=clients[slot];
        if(client.owner!=owner(slot)){release(slot);client.owner=owner(slot);}
        const uint16_t message=cbd_rd16(sdu+3),original=cbd_rd16(sdu+1);
        unsigned sub=client.subscription;
        if(message==0x45) {
            unsigned n=0;const auto *value=cbd_find(sdu,bytes,1,&n);
            if(!value||n!=1||*value>1)return EINVAL;
            sub=*value;
        } else if(client.error) {
            // A real failed subscription bind must not expose the other
            // card's default NAS context. Keep that actual error until a
            // new physical bind, never manufacture an empty subscription.
            const auto &c=bridge.client[slot];
            const unsigned n=cbq_private_answer(sdu,3,c.cid,client.error,nullptr,0,scratch,FrameMax);
            if(!n||!push(c.channel,scratch,n))return ENOBUFS;
            ++bindErrors;return 0;
        }
        auto &backend=backends[sub];
        if(backend.used&&(backend.node!=node||backend.port!=port))return ENETDOWN;
        for(const auto &r:requests)if(r.used&&r.subscription==sub&&stateRequest(r.message)) {
            ++blocked;return EAGAIN;
        }
        Request *available=nullptr;
        for(auto &r:requests)if(!r.used){available=&r;break;}
        if(!available){++blocked;return EAGAIN;}
        uint16_t transaction=backend.next;
        bool free=false;
        for(unsigned tries=0;tries<129;tries++) {
            if(!++transaction)++transaction;
            free=true;
            for(const auto &r:requests)if(r.used&&r.subscription==sub&&r.transaction==transaction){free=false;break;}
            if(free)break;
        }
        if(!free)return EAGAIN;
        uint32_t known=0,enabled=0,wireKnown=0;unsigned wireBytes=bytes;
        if(message==3) {
            wireBytes=reporting(slot,sub,sdu,bytes,known,enabled,wireKnown);
            if(!wireBytes)return EINVAL;
        } else memcpy(scratch,sdu,bytes);
        cbd_wr16(scratch+1,transaction);
        const int result=pong_modem_qrtr_send(transport,Port+sub,node,port,scratch,wireBytes);
        if(result)return result;
        backend.used=true;backend.node=node;backend.port=port;backend.next=transaction;
        client.subscription=sub;
        *available={true,uint8_t(sub),transaction,original,message,slot,client.owner,known,enabled,wireKnown};
        for(auto &metric:nasMetrics)if(metric.message==message)++metric.sent;
        ++accepted;return 0;
    }
    bool receive(uint32_t local,uint32_t node,uint32_t port,const uint8_t *sdu,unsigned bytes) {
        if(local<Port||local>=Port+2)return false;
        const unsigned sub=local-Port;auto &backend=backends[sub];
        if(!backend.used||backend.node!=node||backend.port!=port||!cbd_sdu_ok(sdu,bytes))return true;
        const uint16_t message=cbd_rd16(sdu+3),transaction=cbd_rd16(sdu+1);
        if(sdu[0]==2) {
            for(auto &r:requests)if(r.used&&r.subscription==sub&&r.transaction==transaction&&r.message==message) {
                const unsigned error=cbd_error(sdu,bytes);
                if(message==3&&!error)backend.reportsKnown|=r.wireKnown;
                if(r.owner&&r.owner==owner(r.slot)&&r.owner==clients[r.slot].owner) {
                    auto &c=clients[r.slot];
                    if(message==0x45)c.error=error;
                    else if(message==3&&!error) {
                        c.known|=r.known;c.enabled=(c.enabled&~r.known)|r.enabled;
                    }
                    for(auto &metric:nasMetrics)if(metric.message==message)++metric.received;
                    if(frame(r.slot,sdu,bytes,r.original)){++received;++replies;}else ++failed;
                } else ++orphaned;
                r={};return true;
            }
            ++orphaned;
        } else if(sdu[0]==4) {
            ++indications;
            for(unsigned slot=0;slot<CBQ_MAX_CLIENTS;slot++) {
                const auto &c=clients[slot];
                if(c.owner&&c.owner==owner(slot)&&c.subscription==sub&&!c.error)
                    if(frame(slot,sdu,bytes,transaction))++received;else ++failed;
            }
        }
        return true;
    }
    void report()const {
        unsigned users=0,pending=0,physical=0;
        for(const auto &c:clients)users+=c.owner!=0;
        for(const auto &r:requests)pending+=r.used;
        for(const auto &b:backends)physical+=b.used;
        IOLog("Pong NAS broker: logical=%u physical=%u pending=%u accepted=%u replies=%u indications=%u orphaned=%u admission_waits=%u prior_bind_errors=%u; actual modem responses only\n",
            users,physical,pending,accepted,replies,indications,orphaned,blocked,bindErrors);
    }
} nasMux;
