/* SPDX-License-Identifier: BSD-2-Clause
 * QMI data-port setup adapted from HoshinoYumeka/chiba233's
 * UniXNU/QcomBaseband coachz_bb_data.h. Cape IPA5.1 has WAN endpoints
 * 2/23, not Coachz IPA4.2's 1/9 (NothingOSS ipa-utils.c).
 * All traffic runs on the actual QRTR owner. A configuration ACK is not
 * an IPA/GSI DMA or PDP connectivity success.
 */
#include "coachz_bb_data.h"
constexpr uint32_t DataPorts[2]={0x120,0x121};
struct ModemDataSetup {
    PongQrtrServer endpoint[2]{};
    bool present[2]{},requested=false,pending=false;
    uint8_t step=0,formatIndex=0;
    uint16_t transaction=0;
    unsigned attempts=0;
    uint64_t deadline=0,discoveryDeadline=0;
    uint32_t dpmError=~0u,wdaError=~0u,llp=~0u,ul=~0u,dl=~0u;
} modemData;
uint32_t modemDataRequested;
int modemDataState=EAGAIN;
void modemDataServer(const PongQrtrServer *server,bool added) {
    const unsigned index=server->service==CBD_SVC_DPM?0:server->service==CBD_SVC_WDA?1:2;
    if(index==2)return;
    if(added&&(!modemData.present[index]||(server->instance>>8)<(modemData.endpoint[index].instance>>8))) {
        modemData.endpoint[index]=*server;modemData.present[index]=true;
        modemData.step=modemData.formatIndex=0;modemData.pending=false;modemData.attempts=0;modemData.discoveryDeadline=0;
        __atomic_store_n(&modemDataState,EAGAIN,__ATOMIC_RELEASE);
    } else if(!added&&modemData.present[index]&&server->node==modemData.endpoint[index].node&&server->port==modemData.endpoint[index].port) {
        modemData.present[index]=false;modemData.pending=false;modemData.step=modemData.formatIndex=0;modemData.attempts=0;
        __atomic_store_n(&modemDataState,EAGAIN,__ATOMIC_RELEASE);
    }
}
void modemDataPoll() {
    if(__atomic_exchange_n(&modemDataRequested,0u,__ATOMIC_ACQ_REL))modemData.requested=true;
    if(!modemData.requested||modemData.step>=3||!control.qrtr.hello_received)return;
    const unsigned index=modemData.step?1:0;
    const uint64_t now=nowMs();
    if(!modemData.present[index]) {
        if(!modemData.discoveryDeadline)modemData.discoveryDeadline=now+15000;
        if(now>=modemData.discoveryDeadline) {
            __atomic_store_n(&modemDataState,ENODEV,__ATOMIC_RELEASE);modemData.step=3;
            IOLog("PongModem data: actual %s service unavailable; native bind not acknowledged\n",index?"WDA":"DPM");
        }
        return;
    }
    modemData.discoveryDeadline=0;
    if(modemData.pending) {
        if(now<modemData.deadline)return;
        modemData.pending=false;
    }
    if(modemData.attempts>=3) {
        __atomic_store_n(&modemDataState,ETIMEDOUT,__ATOMIC_RELEASE);
        modemData.step=3;return;
    }
    uint8_t query[128];uint16_t transaction=modemData.transaction+1;if(!transaction)transaction=1;
    unsigned bytes=0;
    if(!index) {
        // DPM lists the receiver/transmitter from the modem's viewpoint:
        // AP producer2 receives at modem, AP consumer23 transmits there.
        uint8_t port[17]={1};cbd_wr32(port+1,CBD_EP_EMBEDDED);cbd_wr32(port+5,CBD_EP_INTERFACE);
        cbd_wr32(port+9,2);cbd_wr32(port+13,23);
        bytes=cbd_request(query,transaction,CBD_DPM_OPEN_PORT,cbd_tlv(query+7,sizeof query-7,0x11,port,sizeof port));
    } else if(modemData.step==1) {
        // This physical software-checksummed WAN backend consumes MAP5,
        // without MAPv4 checksum metadata/trailers. Negotiate its actual
        // wire format, not a capability it cannot parse or generate.
        const uint32_t formats[2]={CBD_DAP_QMAP,0};
        bytes=cbd_wda_set(query,sizeof query,transaction,formats[modemData.formatIndex]);
    } else bytes=cbd_request(query,transaction,CBD_WDA_GET_DATA_FORMAT,
        cbd_tlv_endpoint(query+7,sizeof query-7,0x10));
    const auto &server=modemData.endpoint[index];
    if(bytes&&!pong_modem_qrtr_send(&control.qrtr,DataPorts[index],server.node,server.port,query,bytes)) {
        modemData.transaction=transaction;modemData.pending=true;modemData.deadline=now+5000;++modemData.attempts;
    }
}
bool modemDataReceive(uint32_t local,uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    const unsigned index=local==DataPorts[0]?0:local==DataPorts[1]?1:2;
    if(index==2)return false;
    const auto *sdu=static_cast<const uint8_t *>(data);
    if(!modemData.pending||(modemData.step?1u:0u)!=index||modemData.step>=3||!modemData.present[index]||
       modemData.endpoint[index].node!=node||modemData.endpoint[index].port!=port||!cbd_sdu_ok(sdu,bytes)||
       sdu[0]!=2||cbd_rd16(sdu+1)!=modemData.transaction||
       cbd_rd16(sdu+3)!=(modemData.step==2?CBD_WDA_GET_DATA_FORMAT:0x20))return true;
    modemData.pending=false;
    const uint32_t error=cbd_error(sdu,bytes);
    (index?modemData.wdaError:modemData.dpmError)=error;
    if(error) {
        if(index&&modemData.formatIndex<1) {
            ++modemData.formatIndex;modemData.step=1;modemData.attempts=0;return true;
        }
        modemData.step=3;__atomic_store_n(&modemDataState,EIO,__ATOMIC_RELEASE);
        IOLog("PongModem data: actual %s refused QMI_error=%u; no data success published\n",index?"WDA":"DPM",error);return true;
    }
    if(index) {
        modemData.llp=cbd_u32(sdu,bytes,0x11);modemData.ul=cbd_u32(sdu,bytes,0x12);modemData.dl=cbd_u32(sdu,bytes,0x13);
        // SET success alone is insufficient: this modem returned disabled
        // aggregation despite a QMAPv4 request. Read the actual format,
        // then negotiate the next supported transport instead of declaring
        // an unobserved QMAP configuration successful.
        if(modemData.step==1){modemData.step=2;modemData.attempts=0;return true;}
        const uint32_t formats[2]={CBD_DAP_QMAP,0};
        const bool valid=modemData.llp==CBD_LLP_RAW_IP&&modemData.ul==formats[modemData.formatIndex]&&modemData.dl==formats[modemData.formatIndex];
        if(!valid&&modemData.formatIndex<1){++modemData.formatIndex;modemData.step=1;modemData.attempts=0;return true;}
        __atomic_store_n(&modemDataState,valid?0:EPROTONOSUPPORT,__ATOMIC_RELEASE);
        IOLog("PongModem data: actual DPM/WDA port setup link=%u uplink=%u downlink=%u valid=%u; GSI/PDP not inferred\n",modemData.llp,modemData.ul,modemData.dl,valid);
    }
    ++modemData.step;modemData.attempts=0;return true;
}
