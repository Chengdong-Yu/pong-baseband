/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Bounded modem DIAG transport, using the public linux-msm/diag QRTR wire
 * protocol. Service4097 uses raw instances0/control,1/command,2/data,
 * unlike normal QMI version/instance packing. Feature negotiation reports
 * only implemented framing and request/reply transport. No NV writes,
 * calibration changes, arbitrary commands or blanket message masks.
 */
constexpr uint32_t ModemDiagControlPort=0x140,ModemDiagDataPort=0x141,ModemDiagCommandPort=0x142;
struct ModemDiag {
    PongQrtrServer command{};
    bool registered=false,present=false,haveControl=false,featurePending=false,featuresSent=false;
    bool versionSent=false,versionAnswered=false;
    uint32_t controlNode=0,controlPort=0,features=0,remoteFeatures=0;
    uint32_t controlMessages=0,registrations=0,dataFrames=0,commandFrames=0,invalid=0,lastControl=0,lastCommand=0;
    uint64_t deadline=0;
    void offline() {
        present=haveControl=featurePending=featuresSent=versionSent=versionAnswered=false;
        features=remoteFeatures=0;deadline=0;
    }
    bool registerServices() {
        if(registered)return true;
        if(pong_modem_qrtr_register(&control.qrtr,4097,0,ModemDiagControlPort))return false;
        if(pong_modem_qrtr_register(&control.qrtr,4097,2,ModemDiagDataPort))return false;
        registered=true;return true;
    }
    void server(const PongQrtrServer *s,bool added) {
        if(s->service!=4097||s->instance!=1)return;
        if(added){command=*s;present=true;versionSent=versionAnswered=false;}
        else if(present&&command.node==s->node&&command.port==s->port) {
            present=featuresSent=versionSent=versionAnswered=false;
        }
    }
    void controlPacket(uint32_t node,uint32_t port,const uint8_t *data,unsigned bytes) {
        if(node!=control.qrtr.remote_node){++invalid;return;}
        if(haveControl&&(controlNode!=node||controlPort!=port)){++invalid;return;}
        haveControl=true;controlNode=node;controlPort=port;
        unsigned at=0;
        while(bytes-at>=8) {
            const uint32_t kind=cbd_rd32(data+at),n=cbd_rd32(data+at+4);
            if(n>bytes-at-8){++invalid;return;}
            const auto *p=data+at+8;++controlMessages;lastControl=kind;
            if(kind==8) {
                if(n<5||!cbd_rd32(p)||cbd_rd32(p)>n-4){++invalid;return;}
                const unsigned maskBytes=cbd_rd32(p)<4?cbd_rd32(p):4;
                remoteFeatures=0;
                for(unsigned i=0;i<maskBytes;i++)remoteFeatures|=uint32_t(p[4+i])<<(8*i);
                // Mask exchange, command/reply, raw command transport and
                // QRTR sockets are implemented. Do not claim DIAG IDs or
                // common masks, logging modes, buffering or STM ownership.
                features=remoteFeatures&0x2051u;featurePending=true;
            } else if(kind==1) {
                if(n<12||cbd_rd16(p+8)>(n-12)/8){++invalid;return;}
                registrations+=cbd_rd16(p+8);
            }
            at+=8+n;
        }
        if(at!=bytes)++invalid;
    }
    void frame(bool response,uint32_t node,uint32_t port,const uint8_t *data,unsigned bytes) {
        if(response&&(!present||command.node!=node||command.port!=port)){++invalid;return;}
        if(!response&&node!=control.qrtr.remote_node){++invalid;return;}
        unsigned at=0;
        while(bytes-at>=5) {
            const unsigned n=cbd_rd16(data+at+2);
            if(data[at]!=0x7e||data[at+1]!=1||n>bytes-at-5||data[at+4+n]!=0x7e){++invalid;return;}
            if(response) {
                ++commandFrames;lastCommand=n?data[at+4]:~0u;
                if(versionSent&&n&&data[at+4]==0) {
                    versionAnswered=true;
                    IOLog("PongModem DIAG: actual read-only VERSION reply bytes=%u; version/build/device contents omitted\n",n);
                }
            } else ++dataFrames;
            at+=5+n;
        }
        if(at!=bytes)++invalid;
    }
    bool receive(uint32_t local,uint32_t node,uint32_t port,const uint8_t *data,unsigned bytes) {
        if(local==ModemDiagControlPort)controlPacket(node,port,data,bytes);
        else if(local==ModemDiagCommandPort)frame(true,node,port,data,bytes);
        else if(local==ModemDiagDataPort)frame(false,node,port,data,bytes);
        else return false;
        return true;
    }
    void poll() {
        if(featurePending&&haveControl) {
            uint8_t reply[16];cbd_wr32(reply,8);cbd_wr32(reply+4,8);
            cbd_wr32(reply+8,4);cbd_wr32(reply+12,features);
            if(!pong_modem_qrtr_send(&control.qrtr,ModemDiagControlPort,controlNode,controlPort,reply,sizeof reply)) {
                featurePending=false;featuresSent=true;
                IOLog("PongModem DIAG: actual feature exchange remote=%x implemented=%x, registrations=%u; NV/radio unchanged\n",remoteFeatures,features,registrations);
            }
        }
        if(present&&featuresSent&&!versionSent&&(features&0x50)==0x50) {
            const uint8_t version=0;
            if(!pong_modem_qrtr_send(&control.qrtr,ModemDiagCommandPort,command.node,command.port,&version,1)) {
                versionSent=true;deadline=nowMs()+10000;
            }
        }
        if(versionSent&&!versionAnswered&&deadline&&nowMs()>=deadline) {
            deadline=0;IOLog("PongModem DIAG: read-only VERSION response unavailable; no diagnostic success inferred\n");
        }
    }
    void report()const {
        IOLog("PongModem DIAG snapshot: registered=%u control=%u command=%u features_sent=%u version=%u/%u control_frames=%u ranges=%u data=%u replies=%u invalid=%u last_control=%u last_command=%u; no payload contents\n",
            registered,haveControl,present,featuresSent,versionSent,versionAnswered,controlMessages,registrations,dataFrames,commandFrames,invalid,lastControl,lastCommand);
    }
} modemDiag;
