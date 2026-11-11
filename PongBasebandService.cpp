/* SPDX-License-Identifier: BSD-2-Clause
 * Pong's native22G100 IOABP QMUX channels, over its actual MPSS QRTR owner.
 * QMUX framing/client allocation is UniXNU/QcomBaseband's public bridge
 * (HoshinoYumeka/chiba233). The native boot exchange is an explicit software
 * compatibility endpoint over already-authenticated MPSS, never Apple
 * firmware execution. No synthetic activation/SIM or empty PDP interface.
 */
#include "PongBasebandService.h"
#include "PongModemRuntime.h"
#include "coachz_bb_qmux.h"
#include "coachz_bb_sahara.h"
#include "coachz_bb_data.h"
#include "coachz_bb_pdp.h"
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <kern/thread_call.h>
#include <kern/clock.h>
#include <sys/errno.h>

namespace {
constexpr unsigned FrameMax=65536,Frames=1024,Reads=8,TxCount=64,ChannelCount=4;
constexpr unsigned PblChannel=2,SaharaChannel=3;
// The reviewed native Mav24 package's software protocol profile. This is
// not the physical X65 ID and is never used by PAS/SCM, QMI or SIM queries.
constexpr uint32_t NativeBootProfileChip=0x002af0e1;
constexpr uint32_t ActualPongSocSerial=2380287147u;
struct Frame {uint8_t *data;uint32_t bytes;};
struct Read {OSAsyncReference64 reference;IOMemoryDescriptor *memory;void *owner;};
struct Channel {Frame frames[Frames];unsigned head,count;Read reads[Reads];unsigned waiting;void *owner;uint8_t instance;uint16_t link;};
struct Tx {uint8_t *data;uint32_t bytes,local,node,port;};
Channel channels[ChannelCount];Tx tx[TxCount];unsigned txHead,txCount;
cbq_bridge bridge;IOLock *bbGate;thread_call_t completion;PongModemQrtr *transport;
uint8_t *scratch;bool published,online;
uint32_t sent,received,failed,opened,privateRequests;
uint64_t nativeManagerState,nativeBasebandState;
uint32_t nativeRadioIntent=~0u;
IOService *boardProvider;
char actualRevision[257];
char actualImei[16];
char actualMsisdn[33];
uint32_t actualSlots;
uint8_t actualSlotState[8],actualSlotError[8];
void publishSlots() {
    if(!boardProvider||!actualSlots)return;
    auto *slots=OSArray::withCapacity(actualSlots);
    if(!slots)return;
    bool complete=true;
    for(unsigned n=0;n<actualSlots;n++) {
        auto *slot=OSDictionary::withCapacity(4);
        if(!slot){complete=false;break;}
        const char *keys[]={"Slot","CardState","CardError"};
        const uint32_t values[]={n+1,actualSlotState[n],actualSlotError[n]};
        for(unsigned i=0;i<3;i++) {
            auto *value=OSNumber::withNumber(values[i],32);
            if(!value){complete=false;break;}
            slot->setObject(keys[i],value);value->release();
        }
        if(complete)slots->setObject(slot);slot->release();if(!complete)break;
    }
    if(complete) {
        boardProvider->setProperty("PongSimSlots",slots);
        boardProvider->setProperty("PongSimSlotCount",actualSlots,32);
    }
    slots->release();
}
uint32_t controlOpens,controlReads,boardCalls,lastBoardSelector;
cbs_device nativeBoot;bool bootImageAccepted;
uint64_t nativeBootBytes;uint32_t nativeBootQueries;
uint32_t asyncDelivered,asyncFailed,readCopied,readCopyFailed;
struct ActivationSubscription {bool active;uint8_t cid;} activation[2];
struct SimRead {bool active;uint8_t channel,cid;uint16_t transaction,file;} simReads[8];
unsigned nextSimRead;
uint32_t actualIms[7]={~0u,~0u,~0u,~0u,~0u,~0u,~0u};
void publishIms() {
    if(!boardProvider)return;
    const char *keys[]={"PongIMSRegistration","PongIMSRegistrationTechnology","PongIMSVoiceService","PongIMSSMSService",
        "PongIMSVoiceTechnology","PongIMSVoiceEnabled","PongIMSRegistrationEnabled"};
    for(unsigned i=0;i<7;i++)if(actualIms[i]!=~0u)boardProvider->setProperty(keys[i],actualIms[i],32);else boardProvider->removeProperty(keys[i]);
}
cbp_client bb_pdp_clients[CBQ_MAX_CLIENTS]{};
uint32_t bb_pdp_owners[CBQ_MAX_CLIENTS]{};
int (*pong_wan_sender)(uint32_t,const uint8_t *,uint32_t);
bool (*pong_wan_ready)(void);
void (*pong_wan_receive)(uint32_t,const uint8_t *,uint32_t,uint32_t);
int pong_wan_send(uint32_t mux,const uint8_t *ip,uint32_t bytes) {
    return pong_wan_sender&&pong_wan_ready&&pong_wan_ready()?pong_wan_sender(mux,ip,bytes):ENETDOWN;
}
uint8_t simIccid[CBD_ICCID_BYTES],simImsi[CBD_IMSI_BYTES];bool haveIccid,haveImsi;
uint8_t nasMessages[8192];unsigned nasMessageBytes;
struct NasMetric {uint16_t message;uint32_t queued,sent,received,unsupported;};
NasMetric nasMetrics[]={{0x45,0,0,0,0},{0x4f,0,0,0,0},{0x24,0,0,0,0}};
void complete(thread_call_param_t,thread_call_param_t);
bool initialize() {
    if(bbGate)return completion&&scratch;
    bbGate=IOLockAlloc();scratch=static_cast<uint8_t *>(IOMallocData(FrameMax));
    completion=thread_call_allocate(complete,nullptr);cbq_init(&bridge);
    return bbGate&&scratch&&completion;
}
Frame pop(Channel &c) {
    if(!c.count)return {};
    Frame f=c.frames[c.head];c.frames[c.head]={};c.head=(c.head+1)%Frames;--c.count;return f;
}
bool push(unsigned channel,const void *data,unsigned bytes) {
    if(channel>=ChannelCount||!bytes||bytes>FrameMax)return false;
    auto &c=channels[channel];if(c.count==Frames)return false;
    auto *copy=static_cast<uint8_t *>(IOMallocData(bytes));if(!copy)return false;
    memcpy(copy,data,bytes);c.frames[(c.head+c.count)%Frames]={copy,bytes};++c.count;
    IOLockWakeup(bbGate,&c,false);thread_call_enter(completion);return true;
}
bool pushPair(unsigned channel,const void *first,unsigned firstBytes,const void *second,unsigned secondBytes) {
    if(channel>=ChannelCount||!firstBytes||!secondBytes||firstBytes>FrameMax||secondBytes>FrameMax)return false;
    auto &c=channels[channel];if(c.count>Frames-2)return false;
    auto *a=static_cast<uint8_t *>(IOMallocData(firstBytes));
    auto *b=static_cast<uint8_t *>(IOMallocData(secondBytes));
    if(!a||!b){if(a)IOFreeData(a,firstBytes);if(b)IOFreeData(b,secondBytes);return false;}
    memcpy(a,first,firstBytes);memcpy(b,second,secondBytes);
    c.frames[(c.head+c.count)%Frames]={a,firstBytes};++c.count;
    c.frames[(c.head+c.count)%Frames]={b,secondBytes};++c.count;
    IOLockWakeup(bbGate,&c,false);thread_call_enter(completion);return true;
}
unsigned activationFrame(unsigned channel,uint8_t cid,uint8_t *out,unsigned capacity) {
    (void)channel;
    uint8_t tlvs[64];unsigned bytes=0;
    // This non-Apple firmware owner has no Apple activation-ticket gate.
    // This state describes the software bridge, not an Apple activation
    // reply, a SIM card, NAS registration or PDP state.
    const uint8_t state=pong_modem_is_ready()?0:2;
    bytes+=cbd_tlv(tlvs+bytes,sizeof tlvs-bytes,1,&state,1);
    // These BSP flags describe the local software activation/provision
    // gate, not carrier network authentication. The PAS owner has already
    // loaded Pong's real NV and firmware; release this software gate as
    // upstream does. Requiring IMSI before releasing it creates a cycle
    // when native provisioning waits for these flags before reading IMSI.
    // Actual subscriber fields are still absent until the card supplies them.
    const uint8_t provisioned=pong_modem_is_ready()?CBD_PROVISIONED:0,accepted=1;
    bytes+=cbd_tlv(tlvs+bytes,sizeof tlvs-bytes,0x4f,&provisioned,1);
    bytes+=cbd_tlv(tlvs+bytes,sizeof tlvs-bytes,0x50,&provisioned,1);
    for(unsigned n=0;n<actualSlots&&n<2;n++) {
        // Slot acceptance is the bridge's own no-SIM-lock policy. Card
        // presence remains in the actual UIM response/ICCID, never here.
        bytes+=cbd_tlv(tlvs+bytes,sizeof tlvs-bytes,0x56+n,&accepted,1);
    }
    if(actualSlots&&actualSlotState[0]==1&&haveIccid) {
        bytes+=cbd_tlv(tlvs+bytes,sizeof tlvs-bytes,0x42,simIccid,sizeof simIccid);
        if(haveImsi)bytes+=cbd_tlv(tlvs+bytes,sizeof tlvs-bytes,0x43,simImsi,sizeof simImsi);
    }
    return cbq_private_indication(CBD_BSP_ACTIVATION_REGISTER,CBD_SVC_BSP,cid,tlvs,bytes,out,capacity);
}
void activationChanged() {
    for(unsigned ch=0;ch<2;ch++)if(activation[ch].active) {
        if(cbq_client_find(&bridge,ch,CBD_SVC_BSP,activation[ch].cid)<0){activation[ch]={};continue;}
        uint8_t frame[96];unsigned size=activationFrame(ch,activation[ch].cid,frame,sizeof frame);
        if(size)(void)push(ch,frame,size);
    }
}
#include "PongNasMultiplexer.h"
class Async:public IOUserClient {
public:static IOReturn send(OSAsyncReference64 ref,IOReturn result,uint64_t bytes) {
    io_user_reference_t value=bytes;return sendAsyncResult64(ref,result,&value,1);
}};
void finish(Read &r,IOReturn result,Frame f={}) {
    uint64_t bytes=0;
    if(result==kIOReturnSuccess) {
        const uint64_t room=r.memory->getLength();
        const uint64_t n=f.bytes<room?f.bytes:room;
        bytes=r.memory->writeBytes(0,f.data,n);
        if(bytes!=n){result=kIOReturnVMError;__atomic_fetch_add(&readCopyFailed,1u,__ATOMIC_RELAXED);}
        else if(f.bytes>room)result=kIOReturnOverrun;
        else __atomic_fetch_add(&readCopied,1u,__ATOMIC_RELAXED);
    }
    r.memory->complete();r.memory->release();
    IOReturn delivered=Async::send(r.reference,result,bytes);
    __atomic_fetch_add(delivered==kIOReturnSuccess?&asyncDelivered:&asyncFailed,1u,__ATOMIC_RELAXED);
    static unsigned observed;
    if(__atomic_fetch_add(&observed,1u,__ATOMIC_RELAXED)<8||delivered!=kIOReturnSuccess)
        IOLog("PongBaseband: actual async read result=%x bytes=%llu notification=%x native64=%u\n",result,bytes,delivered,!!(r.reference[0]&1));
}
void complete(thread_call_param_t,thread_call_param_t) {
    for(;;) {
        Read r{};Frame f{};bool found=false;
        IOLockLock(bbGate);
        for(auto &c:channels)if(c.waiting&&c.count) {
            r=c.reads[0];--c.waiting;memmove(c.reads,c.reads+1,c.waiting*sizeof(Read));f=pop(c);found=true;break;
        }
        IOLockUnlock(bbGate);if(!found)return;
        finish(r,kIOReturnSuccess,f);IOFreeData(f.data,f.bytes);
    }
}
void abortReads(unsigned n,void *owner,IOReturn reason=kIOReturnAborted) {
    Read ended[Reads];unsigned count=0;IOLockLock(bbGate);auto &c=channels[n];
    for(unsigned i=0;i<c.waiting;) {
        if(!owner||c.reads[i].owner==owner) {
            ended[count++]=c.reads[i];--c.waiting;memmove(c.reads+i,c.reads+i+1,(c.waiting-i)*sizeof(Read));
        } else ++i;
    }
    IOLockWakeup(bbGate,&c,false);IOLockUnlock(bbGate);
    for(unsigned i=0;i<count;i++)finish(ended[i],reason);
}
IOReturn writeFrame(unsigned ch,const uint8_t *data,uint32_t size) {
    if(!online)return kIOReturnOffline;
    if(ch==SaharaChannel) {
        if(!pong_modem_is_ready())return kIOReturnNotReady;
        // Protocol-only BBUpdater compatibility exchange. MPSS has already
        // authenticated this Pong's actual firmware; Apple inputs are
        // consumed here and are never submitted to the physical modem.
        if(channels[ch].count>Frames-2)return kIOReturnBusy;
        unsigned offset=0;
        while(offset<size) {
            cbs_out answer{};
            const bool identity=nativeBoot.state==CBS_COMMAND&&size-offset>=8&&
                cbs_get32(data+offset)==CBS_EXECUTE_DATA;
            const uint32_t execute=nativeBoot.last_execute;
            const unsigned before=nativeBoot.state;
            unsigned used=cbs_receive(&nativeBoot,data+offset,size-offset,&answer);
            if(!used)return kIOReturnBadArgument;
            if(before!=nativeBoot.state)IOLog("PongBaseband: native Sahara compatibility state=%u->%u command=%u response_frames=%u\n",before,nativeBoot.state,nativeBoot.last_command,answer.count);
            for(unsigned i=0;i<answer.count;i++) {
                if(identity&&execute==CBS_EXEC_HW_ID&&answer.len[i]==8) {
                    bzero(answer.data[i],8);cbs_put32(answer.data[i]+4,NativeBootProfileChip);
                } else if(identity&&execute==CBS_EXEC_SERIAL&&answer.len[i]==4)
                    cbs_put32(answer.data[i],ActualPongSocSerial);
                if(!push(ch,answer.data[i],answer.len[i]))return kIOReturnNoMemory;
            }
            offset+=used;
            if(nativeBoot.state==CBS_FAILED)return kIOReturnBadArgument;
        }
        return kIOReturnSuccess;
    }
    if(ch>=2)return kIOReturnUnsupported;
    if(size<CBQ_HDR+CBQ_CTL_HDR||data[0]!=CBQ_IF_TYPE||data[3]||
       cbq_rd16(data+1)+1u!=size)return kIOReturnBadArgument;
    // Reserve both queues before changing CTL client ownership. A temporary
    // full queue returns Busy; never acknowledge a silently dropped write.
    if(txCount==TxCount||channels[ch].count==Frames)return kIOReturnBusy;
    if(size>=CBQ_HDR+CBQ_CTL_HDR&&!data[4]) {
        if(data[CBQ_HDR]||CBQ_HDR+CBQ_CTL_HDR+cbq_rd16(data+CBQ_HDR+4)!=size)return kIOReturnBadArgument;
        const uint16_t id=cbq_rd16(data+CBQ_HDR+2);
        static unsigned requests;
        if(__atomic_fetch_add(&requests,1u,__ATOMIC_RELAXED)<16)
            IOLog("PongBaseband: actual QMI CTL channel=%u message=%x transaction=%u tlv_bytes=%u\n",ch,id,data[CBQ_HDR+1],cbq_rd16(data+CBQ_HDR+4));
        if(id==0x20) {
            // SetInstanceID is local QMUX ownership, not a radio command.
            // Native CTL requires a two-byte LinkID TLV in the successful
            // reply (libqmi qmi-service-ctl.json), not an empty success.
            uint32_t size=0;const auto *instance=cbq_tlv(data+CBQ_HDR+CBQ_CTL_HDR,
                cbq_rd16(data+CBQ_HDR+4),1,&size);
            if(!instance||size!=1) {
                unsigned n=cbq_ctl_answer(scratch,FrameMax,data[CBQ_HDR+1],id,CBQ_ERR_MISSING_ARGUMENT,nullptr,0);
                return n&&push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
            }
            const uint16_t link=uint16_t(((ch+1u)<<8)|instance[0]);
            uint8_t info[2]={uint8_t(link),uint8_t(link>>8)};
            unsigned n=cbq_ctl_answer(scratch,FrameMax,data[CBQ_HDR+1],id,0,info,sizeof info);
            if(!n||!push(ch,scratch,n))return kIOReturnNoMemory;
            channels[ch].instance=instance[0];channels[ch].link=link;
            return kIOReturnSuccess;
        }
        if(id==CBQ_CTL_GET_VERSION_INFO) {
            // The local CTL service is real and terminates here. Include
            // its version, then every unique discovered modem service;
            // the reference's 32-entry truncation hid later services on
            // this modem, which currently publishes 43+ QRTR endpoints.
            uint8_t list[1+5*(CBQ_MAX_SERVERS+1)]={};unsigned count=1;
            list[1]=0;cbq_wr16(list+2,1);cbq_wr16(list+4,0);
            for(unsigned i=0;i<CBQ_MAX_SERVERS;i++) {
                const auto &server=bridge.server[i];
                if(!server.present||!server.service||cbq_server_find(&bridge,server.service)!=&server)continue;
                auto *item=list+1+5*count++;item[0]=uint8_t(server.service);
                cbq_wr16(item+1,server.version);cbq_wr16(item+3,0);
            }
            list[0]=uint8_t(count);
            unsigned n=cbq_ctl_answer(scratch,FrameMax,data[CBQ_HDR+1],id,0,list,1+5*count);
            return n&&push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
        }
        if(id==0x2a) {
            uint32_t size=0;const auto *state=cbq_tlv(data+CBQ_HDR+CBQ_CTL_HDR,
                cbq_rd16(data+CBQ_HDR+4),1,&size);
            uint32_t error=0,mode=~0u;
            if(!state||size!=4)error=CBQ_ERR_MISSING_ARGUMENT;
            else {
                mode=cbd_rd32(state);
                // This QMUX owner is really awake; mode0 is idempotent
                // and needs no external Apple PCIe sleep transaction.
                // Sleeping a shared physical DSP needs a separate owner;
                // report DeviceUnsupported25, not a made-up sleep ACK.
                if(mode)error=25;
            }
            unsigned n=cbq_ctl_answer(scratch,FrameMax,data[CBQ_HDR+1],id,error,nullptr,0);
            static unsigned powerNotes;
            if(__atomic_fetch_add(&powerNotes,1u,__ATOMIC_RELAXED)<8)
                IOLog("PongBaseband: actual local QMUX power request mode=%u result=%u; physical radio unchanged\n",mode,error);
            return n&&push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
        }
        if(id==0x2b) {
            // GetPowerSaveMode reports this transport's actual awake
            // policy, not NAS registration or physical radio power.
            const uint8_t awake[4]={0,0,0,0};
            unsigned n=cbq_ctl_answer(scratch,FrameMax,data[CBQ_HDR+1],id,0,awake,sizeof awake);
            return n&&push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
        }
        if(id!=CBQ_CTL_GET_VERSION_INFO&&id!=CBQ_CTL_GET_CLIENT_ID&&
           id!=CBQ_CTL_RELEASE_CLIENT_ID&&id!=CBQ_CTL_SYNC) {
            const unsigned n=cbq_ctl_answer(scratch,FrameMax,data[CBQ_HDR+1],id,CBQ_ERR_NOT_SUPPORTED,nullptr,0);
            return push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
        }
    }
    const cbq_result r=cbq_from_host(&bridge,ch,data,size,scratch,FrameMax);
    if(r.kind==CBQ_TO_HOST)return push(ch,scratch,r.len)?kIOReturnSuccess:kIOReturnNoMemory;
    if(r.kind==CBQ_PRIVATE) {
        const uint8_t *sdu=data+CBQ_HDR;
        if(r.len>=7&&cbd_sdu_ok(sdu,r.len)&&r.service==0xe5&&cbd_rd16(sdu+3)==0x1000) {
            // UniXNU's legacy Vinyl GetCsn result: this transport has no
            // Apple CSN. An explicit NoCapableUICC error lets the native
            // client finish this query; generic NotSupported leaves it
            // unready. No EID/CSN/profile or physical card state is made up.
            unsigned length=0;const auto *command=cbd_find(sdu,r.len,2,&length);
            if(command&&length==6&&command[0]==1) {
                const uint32_t error=command[5]>=1&&command[5]<=2?0x204u:48u;
                const unsigned n=cbq_private_answer(sdu,r.service,r.cid,error,nullptr,0,scratch,FrameMax);
                static unsigned logged;
                if(__atomic_fetch_add(&logged,1u,__ATOMIC_RELAXED)<4)
                    IOLog("PongBaseband: native legacy Vinyl GetCsn actual transport has no Apple CSN; explicit error=%x slot=%u\n",error,command[5]);
                return n&&push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
            }
        }
        if(r.len>=7&&cbd_sdu_ok(sdu,r.len)&&r.service==CBD_SVC_BSP&&cbd_rd16(sdu+3)==CBD_BSP_ACTIVATION_REGISTER) {
            uint8_t answer[32],indication[96];
            unsigned n=cbq_private_answer(sdu,r.service,r.cid,0,nullptr,0,answer,sizeof answer);
            unsigned size=activationFrame(ch,r.cid,indication,sizeof indication);
            if(!n||!size||!pushPair(ch,answer,n,indication,size))return kIOReturnNoMemory;
            activation[ch]={true,r.cid};return kIOReturnSuccess;
        }
        if(r.len>=7&&cbd_sdu_ok(sdu,r.len)&&r.service==CBD_SVC_BSP&&cbd_rd16(sdu+3)==CBD_BSP_CHIP_INFO) {
            uint8_t tlvs[12];unsigned len=cbd_bsp_chip_info(NativeBootProfileChip,ActualPongSocSerial,tlvs,sizeof tlvs);
            unsigned n=cbq_private_answer(sdu,r.service,r.cid,0,tlvs,len,scratch,FrameMax);
            return n&&push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
        }
        if(r.len>=7&&cbd_sdu_ok(sdu,r.len)&&r.service==CBD_SVC_BSP&&cbd_rd16(sdu+3)==CBD_BSP_SEND_FILE) {
            cbd_file_segment segment{};
            if(!cbd_bsp_file_segment(sdu,r.len,&segment))return kIOReturnBadArgument;
            const bool final=segment.segment+1u==segment.count;
            if(channels[ch].count>Frames-(final?2u:1u))return kIOReturnBusy;
            uint8_t tlvs[12],answer[64],indication[64];unsigned len=cbd_bsp_file_answer(&segment,tlvs,sizeof tlvs);
            unsigned n=cbq_private_answer(sdu,r.service,r.cid,0,tlvs,len,answer,sizeof answer);
            if(!n)return kIOReturnNoMemory;
            if(final) {
                len=cbd_bsp_file_done(&segment,tlvs,sizeof tlvs);
                unsigned done=cbq_private_indication(CBD_BSP_FILE_TRANSFER_STATUS,r.service,r.cid,tlvs,len,indication,sizeof indication);
                if(!done||!pushPair(ch,answer,n,indication,done))return kIOReturnNoMemory;
                IOLog("PongBaseband: native carrier protocol file received type=%u segments=%u; actual Pong NV unchanged\n",segment.type,segment.count);
            } else if(!push(ch,answer,n))return kIOReturnNoMemory;
            return kIOReturnSuccess;
        }
        if(r.len>=7&&cbd_sdu_ok(sdu,r.len)&&r.service==CBD_SVC_BSP&&cbd_rd16(sdu+3)==CBD_BSP_SET_CONFIG) {
            // Apple's carrier-file protocol has completed locally. The
            // physical modem retains this Pong's own NV/carrier settings,
            // exactly as in the public non-Apple boot exchange.
            unsigned n=cbq_private_answer(sdu,r.service,r.cid,0,nullptr,0,scratch,FrameMax);
            return n&&push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
        }
        ++privateRequests;const unsigned n=cbq_private_unsupported(sdu,r.service,r.cid,scratch,FrameMax);
        static unsigned noted;
        if(__atomic_fetch_add(&noted,1u,__ATOMIC_RELAXED)<12)
            IOLog("PongBaseband: actual private service=%x message=%x remains unsupported\n",r.service,r.len>=7?cbq_rd16(sdu+3):0xffff);
        return push(ch,scratch,n)?kIOReturnSuccess:kIOReturnNoMemory;
    }
    if(r.kind!=CBQ_TO_MODEM)return kIOReturnBadArgument;
    if(r.service==3&&r.len>=7) {
        const unsigned message=cbd_rd16(data+CBQ_HDR+3);
        for(auto &metric:nasMetrics)if(metric.message==message)++metric.queued;
        if(nasMessageBytes&&
           (message/8>=nasMessageBytes||!(nasMessages[message/8]&(1u<<(message%8))))) {
            // Return the physical service's advertised limitation instead
            // of forwarding a non-existent operation and waiting for a
            // silent firmware dispatcher. Never infer absence from timeout.
            const auto n=cbq_private_answer(data+CBQ_HDR,r.service,r.cid,71,nullptr,0,scratch,FrameMax);
            if(n&&push(ch,scratch,n)) {
                for(auto &metric:nasMetrics)if(metric.message==message)++metric.unsupported;
                return kIOReturnSuccess;
            }
            return kIOReturnNoMemory;
        }
    }
    const auto fixed=cbd_endpoint_fix(r.service,data+CBQ_HDR,r.len,scratch,FrameMax);
    const uint32_t sendBytes=fixed.len?fixed.len:r.len;
    auto *copy=static_cast<uint8_t *>(IOMallocData(sendBytes));if(!copy)return kIOReturnNoMemory;
    memcpy(copy,fixed.len?scratch:data+CBQ_HDR,sendBytes);
    if(r.service==2&&sendBytes>=7&&copy[0]==0&&cbd_rd16(copy+3)==0x2e) {
        unsigned length=0;const auto *mode=cbd_find(copy,sendBytes,1,&length);
        if(mode&&length==1)__atomic_store_n(&nativeRadioIntent,unsigned(*mode),__ATOMIC_RELEASE);
    }
    if(r.service==CBD_SVC_WDS&&r.local_port>=CBQ_PORT_BASE&&r.local_port<CBQ_PORT_BASE+CBQ_MAX_CLIENTS) {
        const unsigned slot=r.local_port-CBQ_PORT_BASE;
        const auto key=1u+r.cid+(uint32_t(ch)<<8);
        if(bb_pdp_owners[slot]!=key){bb_pdp_clients[slot]={};bb_pdp_owners[slot]=key;}
        cbp_observe(&bb_pdp_clients[slot],copy,sendBytes);
    }
    tx[(txHead+txCount)%TxCount]={copy,sendBytes,r.local_port,r.node,r.port};++txCount;
    if(fixed.len) {
        static unsigned noted;
        if(__atomic_fetch_add(&noted,1u,__ATOMIC_RELAXED)<8)
            IOLog("PongBaseband: native service=%u message=%x data endpoint %u/%u -> embedded4/1 inserted=%u\n",r.service,cbd_rd16(copy+3),fixed.before_type,fixed.before_interface,fixed.inserted);
    }
    if((r.service==CBD_SVC_WDS&&cbd_rd16(copy+3)==CBD_WDS_BIND_MUX_DATA_PORT)||
       (r.service==CBD_SVC_QOS&&cbd_rd16(copy+3)==CBD_QOS_BIND_DATA_PORT))pong_modem_request_data_port();
    if(r.service==CBD_SVC_UIM) {
        const unsigned file=cbd_uim_read_file(data+CBQ_HDR,r.len);
        if(file==CBD_EF_ICCID||file==CBD_EF_IMSI)
            simReads[nextSimRead++%8]={true,uint8_t(ch),r.cid,cbq_rd16(data+CBQ_HDR+1),uint16_t(file)};
    }
    return kIOReturnSuccess;
}
}

class AppleBasebandPCIUserClient:public IOUserClient {
    OSDeclareDefaultStructors(AppleBasebandPCIUserClient)
    task_t task_;unsigned channel_;bool opened_;
public:
    bool initWithTask(task_t t,void *s,UInt32 type,OSDictionary *props) override {
        OSObject *permission=copyClientEntitlement(t,"com.apple.driver.AppleBasebandPCI.user-access");
        const bool allowed=permission==kOSBooleanTrue||
            clientHasPrivilege(t,kIOClientPrivilegeAdministrator)==kIOReturnSuccess;
        if(permission)permission->release();
        if(!allowed)return false;
        task_=t;channel_=ChannelCount;opened_=false;return IOUserClient::initWithTask(t,s,type,props);
    }
    void setChannel(unsigned n){channel_=n;}
    void closeChannel() {
        if(channel_>=ChannelCount)return;
        IOLockLock(bbGate);auto &c=channels[channel_];
        if(c.owner==this) {
            c.owner=nullptr;opened_=false;
            c.instance=0;c.link=0;
            if(channel_<2)for(unsigned i=0;i<CBQ_MAX_CLIENTS;i++)if(bridge.client[i].used&&bridge.client[i].channel==channel_)cbq_client_free(&bridge,i);
            if(channel_<2){activation[channel_]={};for(auto &request:simReads)if(request.channel==channel_)request.active=false;}
            while(c.count){Frame f=pop(c);IOFreeData(f.data,f.bytes);}
        }
        IOLockUnlock(bbGate);abortReads(channel_,this);
    }
    IOReturn clientClose() override {closeChannel();terminate();return kIOReturnSuccess;}
    bool didTerminate(IOService *p,IOOptionBits o,bool *defer) override {closeChannel();return IOUserClient::didTerminate(p,o,defer);}
    IOReturn externalMethod(uint32_t selector,IOExternalMethodArguments *a,IOExternalMethodDispatch *,OSObject *,void *) override {
        if(!a||channel_>=ChannelCount)return kIOReturnBadArgument;
        bool async=a->asyncWakePort!=MACH_PORT_NULL;
        if(channel_>=2&&selector<16) {
            static uint32_t seen[ChannelCount];const uint32_t bit=1u<<selector;
            if(!(__atomic_fetch_or(&seen[channel_],bit,__ATOMIC_RELAXED)&bit))
                IOLog("PongBaseband: native boot channel=%s method=%u async=%u refs=%u scalars=%u struct_in=%llu struct_out=%llu scalar_length=%llu register=%llu\n",
                    channel_==PblChannel?"pbl":"sahara",selector,async,a->asyncReferenceCount,a->scalarInputCount,
                    a->structureInputDescriptor?a->structureInputDescriptor->getLength():uint64_t(a->structureInputSize),
                    a->structureOutputDescriptor?a->structureOutputDescriptor->getLength():uint64_t(a->structureOutputSize),
                    a->scalarInputCount==2&&a->scalarInput?a->scalarInput[1]:0,
                    selector==5&&a->scalarInputCount&&a->scalarInput?a->scalarInput[0]:0);
        }
        if(async&&(!a->asyncReference||a->asyncReferenceCount!=3))return kIOReturnBadArgument;
        if(selector==0) {
            if(async||a->scalarInputCount!=1)return kIOReturnBadArgument;
            IOLockLock(bbGate);auto &c=channels[channel_];const bool live=online;
            bool available=live&&(!c.owner||c.owner==this);
            if(available){c.owner=this;opened_=true;++opened;
                if(channel_==SaharaChannel&&pong_modem_is_ready()) {
                    const uint32_t images[]={0x15};cbs_init(&nativeBoot,images,1,FrameMax);
                    cbs_out hello{};cbs_start(&nativeBoot,&hello);
                    for(unsigned i=0;i<hello.count;i++)push(channel_,hello.data[i],hello.len[i]);
                    IOLog("PongBaseband: native Sahara HELLO queued on actual ready transport; native first-stage query precedes SendImage\n");
                }
            }
            IOLockUnlock(bbGate);
            if(available)IOLog("PongBaseband: native22G100 channel=%s opened; transport=%s\n",
                channel_==0?"qmux1":channel_==1?"qmux2":channel_==PblChannel?"pbl":"sahara",
                channel_<2?"actual MPSS QRTR":"explicit BBUpdater software compatibility");
            return available?kIOReturnSuccess:live?kIOReturnExclusiveAccess:kIOReturnOffline;
        }
        if(selector==1){if(async||a->scalarInputCount)return kIOReturnBadArgument;closeChannel();return kIOReturnSuccess;}
        IOLockLock(bbGate);bool owns=opened_&&channels[channel_].owner==this,live=online;IOLockUnlock(bbGate);
        if(!owns)return kIOReturnNotOpen;if(!live)return kIOReturnOffline;
        if(selector==5&&(channel_==PblChannel||channel_==SaharaChannel)) {
            if(async||a->scalarInputCount!=1||!a->scalarInput)return kIOReturnBadArgument;
            const uint64_t length=a->structureOutputDescriptor?a->structureOutputDescriptor->getLength():a->structureOutputSize;
            // 22G100 queries register4 as a 96-byte structure on sahara
            // before it ever issues a read/write or opens pbl. libIOABP's
            // register ABI is shared by both boot channels, not PBL-only.
            if(!length||length>96)return kIOReturnBadArgument;
            uint8_t value[96]={};const uint64_t reg=a->scalarInput[0];
            if(reg==0&&length>=4)cbs_put32(value,ActualPongSocSerial);
            else if(reg==3&&length>=8)cbs_put32(value+4,NativeBootProfileChip);
            else if(reg==4&&(length==32||length==96)) {
                // QcomBaseband's software-loader default is also present
                // in this exact 22G100 BBULoader. This describes our
                // non-executing boot endpoint, not Pong's physical fuses,
                // an Apple signing certificate or an authentication result.
                cbs_read_register(4,value,uint32_t(length));
            }
            else {
                // No borrowed Apple certificate/public-key hash is supplied.
                IOLog("PongBaseband: PBL profile query reg=%llu bytes=%llu unavailable; no physical fuse value fabricated\n",reg,length);
                return kIOReturnUnsupported;
            }
            IOReturn result=kIOReturnSuccess;
            if(a->structureOutputDescriptor) {
                auto *m=a->structureOutputDescriptor;result=m->prepare();
                if(result==kIOReturnSuccess){if(m->writeBytes(0,value,length)!=length)result=kIOReturnVMError;m->complete();a->structureOutputDescriptorSize=uint32_t(length);}
            } else if(a->structureOutput)memcpy(a->structureOutput,value,length);else result=kIOReturnBadArgument;
            __atomic_fetch_add(&nativeBootQueries,1u,__ATOMIC_RELAXED);
            IOLog("PongBaseband: native %s software profile query reg=%llu bytes=%llu result=%x; real PAS owner remains powered=%u\n",channel_==PblChannel?"PBL":"Sahara",reg,length,result,pong_modem_is_powered());
            return result;
        }
        if(selector==4&&channel_==PblChannel) {
            if(a->scalarInputCount!=2||!a->scalarInput)return kIOReturnBadArgument;
            uint64_t address=a->scalarInput[0],length=a->scalarInput[1];
            if(!address||length<64||length>64*1024*1024||address>UINT64_MAX-length)return kIOReturnBadArgument;
            auto *memory=IOMemoryDescriptor::withAddressRange(address,length,kIODirectionOut,task_);
            if(!memory)return kIOReturnNoMemory;
            IOReturn result=memory->prepare();
            if(result!=kIOReturnSuccess){memory->release();return result;}
            auto *chunk=static_cast<uint8_t *>(IOMallocData(FrameMax));
            if(!chunk)result=kIOReturnNoMemory;
            for(uint64_t offset=0;result==kIOReturnSuccess&&offset<length;) {
                uint64_t n=length-offset<FrameMax?length-offset:FrameMax;
                if(memory->readBytes(offset,chunk,n)!=n)result=kIOReturnVMError;
                else if(!offset&&(memcmp(chunk,"\x7f" "ELF",4)||chunk[5]!=1))result=kIOReturnBadArgument;
                offset+=n;
            }
            if(chunk)IOFreeData(chunk,FrameMax);memory->complete();memory->release();
            IOLockLock(bbGate);
            if(result==kIOReturnSuccess&&channels[channel_].owner==this&&online&&pong_modem_is_ready()) {
                bootImageAccepted=true;nativeBootBytes+=length;
            } else if(result==kIOReturnSuccess)result=kIOReturnNotReady;
            IOLockUnlock(bbGate);
            if(result==kIOReturnSuccess)IOLog("PongBaseband: consumed %llu native BBUpdater compatibility bytes; actual Pong firmware already PAS-authenticated, Apple input not executed\n",length);
            if(async&&result==kIOReturnSuccess){OSAsyncReference64 ref{};memcpy(ref,a->asyncReference,3*sizeof(io_user_reference_t));io_user_reference_t values[2]={length,0};(void)sendAsyncResult64(ref,result,values,2);}
            return result;
        }
        if(selector==6||selector==7) {
            if(a->scalarInputCount!=1)return kIOReturnBadArgument;
            if(selector==6)abortReads(channel_,this);
            if(async){OSAsyncReference64 ref{};memcpy(ref,a->asyncReference,3*sizeof(io_user_reference_t));(void)sendAsyncResult64(ref,kIOReturnSuccess,nullptr,0);}
            return kIOReturnSuccess;
        }
        if(selector!=2&&selector!=3)return kIOReturnUnsupported;
        if(a->scalarInputCount!=2)return kIOReturnBadArgument;
        const uint64_t address=a->scalarInput[0],length=async?a->scalarInput[1]:
            selector==2?(a->structureInputDescriptor?a->structureInputDescriptor->getLength():a->structureInputSize):
                        (a->structureOutputDescriptor?a->structureOutputDescriptor->getLength():a->structureOutputSize);
        if(!length||length>FrameMax||(async&&(!address||address>UINT64_MAX-length)))return kIOReturnBadArgument;
        IOMemoryDescriptor *memory=async?IOMemoryDescriptor::withAddressRange(address,length,selector==2?kIODirectionOut:kIODirectionIn,task_):
            selector==2?a->structureInputDescriptor:a->structureOutputDescriptor;
        if(!async&&memory)memory->retain();
        IOReturn result=memory?memory->prepare():async?kIOReturnNoMemory:kIOReturnSuccess;
        if(result!=kIOReturnSuccess){if(memory)memory->release();return result;}
        OSAsyncReference64 ref{};if(async)memcpy(ref,a->asyncReference,3*sizeof(io_user_reference_t));
        if(selector==2) {
            auto *copy=static_cast<uint8_t *>(IOMallocData(length));
            if(!copy)result=kIOReturnNoMemory;
            else if(memory) {if(memory->readBytes(0,copy,length)!=length)result=kIOReturnVMError;}
            else if(a->structureInput)memcpy(copy,a->structureInput,length);else result=kIOReturnBadArgument;
            if(memory){memory->complete();memory->release();}
            if(result==kIOReturnSuccess){IOLockLock(bbGate);
                result=opened_&&channels[channel_].owner==this?writeFrame(channel_,copy,uint32_t(length)):kIOReturnNotOpen;
                IOLockUnlock(bbGate);}
            if(copy)IOFreeData(copy,length);
            if(async&&result==kIOReturnSuccess){io_user_reference_t n=length;(void)sendAsyncResult64(ref,result,&n,1);}
            return result;
        }
        if(async) {
            IOLockLock(bbGate);auto &c=channels[channel_];bool queued=c.waiting<Reads&&online&&c.owner==this;
            if(queued){auto &r=c.reads[c.waiting++];memcpy(r.reference,ref,sizeof ref);r.memory=memory;r.owner=this;if(c.count)thread_call_enter(completion);}
            IOLockUnlock(bbGate);
            if(!queued){memory->complete();memory->release();return kIOReturnBusy;}
            return kIOReturnSuccess;
        }
        uint64_t deadline=0;clock_interval_to_deadline(30,kSecondScale,&deadline);
        IOLockLock(bbGate);auto &c=channels[channel_];int waited=THREAD_AWAKENED;
        while(!c.count&&online&&c.owner==this&&waited==THREAD_AWAKENED)waited=IOLockSleepDeadline(bbGate,&c,deadline,THREAD_INTERRUPTIBLE);
        Frame f=c.owner==this?pop(c):Frame{};IOLockUnlock(bbGate);
        if(!f.data)result=waited==THREAD_TIMED_OUT?kIOReturnTimeout:kIOReturnAborted;
        else {
            const uint64_t n=f.bytes<length?f.bytes:length;
            if(memory){if(memory->writeBytes(0,f.data,n)!=n)result=kIOReturnVMError;a->structureOutputDescriptorSize=uint32_t(n);}
            else if(a->structureOutput){memcpy(a->structureOutput,f.data,n);a->structureOutputSize=uint32_t(n);}else result=kIOReturnBadArgument;
            if(result==kIOReturnSuccess&&f.bytes>length)result=kIOReturnOverrun;
            IOFreeData(f.data,f.bytes);
        }
        if(memory){memory->complete();memory->release();}return result;
    }
};
OSDefineMetaClassAndStructors(AppleBasebandPCIUserClient,IOUserClient)

class AppleBasebandPCIInterface:public IOService {
    OSDeclareDefaultStructors(AppleBasebandPCIInterface)
    unsigned channel_;
public:
    // Native IOABP puts ABPInterfaceProtocol at the top level of its
    // matching dictionary. Generic IOService only compares known keys;
    // without these family overrides qmux clients select the last Sahara
    // service. Keep the public QcomBaseband family-matching semantics.
    bool matchProtocol(OSDictionary *table) const {
        if(!table)return false;
        auto *requested=table->getObject("ABPInterfaceProtocol");
        if(!requested)return true;
        auto *protocol=OSDynamicCast(OSString,requested);
        const char *expected=channel_==0?"qmux1":channel_==1?"qmux2":channel_==PblChannel?"pbl":"sahara";
        return protocol&&protocol->isEqualTo(expected);
    }
    bool matchPropertyTable(OSDictionary *table,SInt32 *score) override {
        return IOService::matchPropertyTable(table,score)&&matchProtocol(table);
    }
    bool matchPropertyTable(OSDictionary *table) override {
        return IOService::matchPropertyTable(table)&&matchProtocol(table);
    }
    void setChannel(unsigned n) {
        channel_=n;setProperty("ABPInterfaceProtocol",n==0?"qmux1":n==1?"qmux2":n==PblChannel?"pbl":"sahara");
        setProperty("PongTransport","MPSS GLINK/QRTR");setProperty("PongNativeBuild","22G100");
        if(n>=2){setProperty("PongTransport","native BBUpdater software compatibility over authenticated running MPSS");setProperty("PongPhysicalFirmwareReplaced",kOSBooleanFalse);}
        setProperty("IOUserClientClass","AppleBasebandPCIUserClient");
    }
    IOReturn newUserClient(task_t t,void *s,UInt32 type,OSDictionary *p,IOUserClient **out) override {
        if(!out)return kIOReturnBadArgument;*out=nullptr;if(type)return kIOReturnUnsupported;
        auto *c=OSTypeAlloc(AppleBasebandPCIUserClient);if(!c)return kIOReturnNoMemory;
        if(!c->initWithTask(t,s,type,p)||!c->attach(this)){c->release();return kIOReturnError;}
        c->setChannel(channel_);if(!c->start(this)){c->detach(this);c->release();return kIOReturnError;}
        *out=c;return kIOReturnSuccess;
    }
    IOReturn newUserClient(task_t t,void *s,UInt32 type,IOUserClient **out) override{return newUserClient(t,s,type,nullptr,out);}
};
OSDefineMetaClassAndStructors(AppleBasebandPCIInterface,IOService)

/* Native BootController first creates libTelephonyBaseband's controller,
 * before attempting any QMUX channel. These controls expose the existing
 * integrated PAS4 owner, never pretend to toggle an Apple external GPIO.
 * Manager/baseband states are native ABM's software state, not radio state.
 */
class AppleBasebandUserClient:public IOUserClient {
    OSDeclareDefaultStructors(AppleBasebandUserClient)
public:
    bool initWithTask(task_t t,void *s,UInt32 type,OSDictionary *p) override {
        auto *permission=copyClientEntitlement(t,"com.apple.driver.AppleBasebandPCI.user-access");
        const bool allowed=permission==kOSBooleanTrue||clientHasPrivilege(t,kIOClientPrivilegeAdministrator)==kIOReturnSuccess;
        if(permission)permission->release();return allowed&&IOUserClient::initWithTask(t,s,type,p);
    }
    IOReturn clientClose() override {terminate();return kIOReturnSuccess;}
    IOReturn externalMethod(uint32_t selector,IOExternalMethodArguments *a,IOExternalMethodDispatch *,OSObject *,void *) override {
        if(!a||a->asyncWakePort||a->asyncReferenceCount)return kIOReturnBadArgument;
        auto *in=a->scalarInput;const unsigned nin=a->scalarInputCount;
        if(nin&&!in)return kIOReturnBadArgument;
        uint64_t value=0;bool output=false;IOReturn result=kIOReturnSuccess;
        IOLockLock(bbGate);
        ++boardCalls;lastBoardSelector=selector;
        switch(selector) {
        case 15: // native self-identification carries the actual caller name
            if(nin||a->structureInputSize>4096||a->structureInputDescriptor&&a->structureInputDescriptor->getLength()>4096)result=kIOReturnBadArgument;
            else IOLog("PongBaseband: native22G100 board controller client identified; actual PAS powered=%u ready=%u\n",pong_modem_is_powered(),pong_modem_is_ready());
            break;
        case 1: // idempotent power-on is already satisfied by real PAS4
            if(nin!=1)result=kIOReturnBadArgument;
            else if(!in[0]||!pong_modem_is_powered())result=kIOReturnUnsupported;
            break;
        case 3:if(nin)result=kIOReturnBadArgument;else {value=pong_modem_is_ready()?0:1;output=true;}break;
        case 11:if(nin)result=kIOReturnBadArgument;else {value=pong_modem_is_powered();output=true;}break;
        case 22:case 27:
            if(nin!=1)result=kIOReturnBadArgument;
            else if(selector==22)nativeManagerState=in[0];else nativeBasebandState=in[0];
            break;
        case 23:case 26:
            if(nin)result=kIOReturnBadArgument;else {value=selector==23?nativeManagerState:nativeBasebandState;output=true;}
            break;
        default:result=kIOReturnUnsupported;break; // reset/off/SPMI need an actual board operation
        }
        if(result==kIOReturnSuccess&&output) {
            if(a->scalarOutputCount!=1||!a->scalarOutput)result=kIOReturnBadArgument;
            else {a->scalarOutput[0]=value;a->scalarOutputCount=1;}
        } else if(result==kIOReturnSuccess)a->scalarOutputCount=0;
        IOLockUnlock(bbGate);
        if(result==kIOReturnUnsupported) {
            static uint64_t reported;uint64_t bit=selector<64?UINT64_C(1)<<selector:0;
            if(bit&&!(__atomic_fetch_or(&reported,bit,__ATOMIC_RELAXED)&bit))
                IOLog("PongBaseband: native board operation selector=%u requires real owner; returned unsupported\n",selector);
        }
        return result;
    }
};
OSDefineMetaClassAndStructors(AppleBasebandUserClient,IOUserClient)
class AppleBaseband:public IOService {
    OSDeclareDefaultStructors(AppleBaseband)
public:
    IOReturn newUserClient(task_t t,void *s,UInt32 type,OSDictionary *p,IOUserClient **out) override {
        if(!out)return kIOReturnBadArgument;*out=nullptr;if(type)return kIOReturnUnsupported;
        auto *c=OSTypeAlloc(AppleBasebandUserClient);if(!c)return kIOReturnNoMemory;
        if(!c->initWithTask(t,s,type,p)||!c->attach(this)){c->release();return kIOReturnNotPermitted;}
        if(!c->start(this)){c->detach(this);c->release();return kIOReturnError;}
        *out=c;return kIOReturnSuccess;
    }
    IOReturn newUserClient(task_t t,void *s,UInt32 type,IOUserClient **out) override{return newUserClient(t,s,type,nullptr,out);}
};
OSDefineMetaClassAndStructors(AppleBaseband,IOService)

/* Native libIOABP opens this independent control/logger object before its
 * QMUX interfaces. It represents the existing MPSS owner; a missing raw
 * firmware diagnostics stream is an explicit NotReady, not fake log bytes.
 */
class AppleBasebandPCIControlUserClient:public IOUserClient {
    OSDeclareDefaultStructors(AppleBasebandPCIControlUserClient)
    bool opened_;
public:
    bool initWithTask(task_t t,void *s,UInt32 type,OSDictionary *p) override {
        auto *permission=copyClientEntitlement(t,"com.apple.driver.AppleBasebandPCIControl.user-access");
        bool allowed=permission==kOSBooleanTrue||clientHasPrivilege(t,kIOClientPrivilegeAdministrator)==kIOReturnSuccess;
        if(permission)permission->release();opened_=false;
        return allowed&&IOUserClient::initWithTask(t,s,type,p);
    }
    IOReturn clientClose() override {opened_=false;terminate();return kIOReturnSuccess;}
    IOReturn externalMethod(uint32_t selector,IOExternalMethodArguments *a,IOExternalMethodDispatch *,OSObject *,void *) override {
        if(!a)return kIOReturnBadArgument;
        const bool async=a->asyncWakePort!=MACH_PORT_NULL;
        if(async&&(!a->asyncReference||a->asyncReferenceCount!=3))return kIOReturnBadArgument;
        if(selector==0) {
            if(async||a->scalarInputCount!=1)return kIOReturnBadArgument;
            if(!pong_modem_is_ready())return kIOReturnNotReady;
            opened_=true;__atomic_fetch_add(&controlOpens,1u,__ATOMIC_RELAXED);
            IOLog("PongBaseband: native22G100 PCI control opened; physical MPSS ready\n");
            return kIOReturnSuccess;
        }
        if(selector==1){if(async||a->scalarInputCount)return kIOReturnBadArgument;opened_=false;return kIOReturnSuccess;}
        if(!opened_)return kIOReturnNotOpen;
        if(selector==2) {
            if(!async||a->scalarInputCount!=3||!a->scalarInput)return kIOReturnBadArgument;
            const uint64_t address=a->scalarInput[0],bytes=a->scalarInput[1];
            if(!address||!bytes||bytes>FrameMax||address>UINT64_MAX-bytes)return kIOReturnBadArgument;
            if(__atomic_fetch_add(&controlReads,1u,__ATOMIC_RELAXED)<4)
                IOLog("PongBaseband: native firmware diagnostic read not ready; QMUX control remains independent\n");
            return kIOReturnNotReady;
        }
        // Logger tuning requires the real raw diagnostic backend; do not
        // acknowledge a remote filter setting that has never been applied.
        if(selector==3&&(!async&&a->scalarInputCount!=4))return kIOReturnBadArgument;
        return kIOReturnUnsupported;
    }
};
OSDefineMetaClassAndStructors(AppleBasebandPCIControlUserClient,IOUserClient)
class AppleBasebandPCIControl:public IOService {
    OSDeclareDefaultStructors(AppleBasebandPCIControl)
public:
    IOReturn newUserClient(task_t t,void *s,UInt32 type,OSDictionary *p,IOUserClient **out) override {
        if(!out)return kIOReturnBadArgument;*out=nullptr;if(type)return kIOReturnUnsupported;
        auto *c=OSTypeAlloc(AppleBasebandPCIControlUserClient);if(!c)return kIOReturnNoMemory;
        if(!c->initWithTask(t,s,type,p)||!c->attach(this)){c->release();return kIOReturnNotPermitted;}
        if(!c->start(this)){c->detach(this);c->release();return kIOReturnError;}
        *out=c;return kIOReturnSuccess;
    }
    IOReturn newUserClient(task_t t,void *s,UInt32 type,IOUserClient **out) override{return newUserClient(t,s,type,nullptr,out);}
};
OSDefineMetaClassAndStructors(AppleBasebandPCIControl,IOService)

#include "PongPdpInterfaces.h"

class AppleIPAppenderUserClient:public IOUserClient {
    OSDeclareDefaultStructors(AppleIPAppenderUserClient)
public:
    IOReturn clientClose() override {terminate();return kIOReturnSuccess;}
    IOReturn externalMethod(uint32_t selector,IOExternalMethodArguments *a,IOExternalMethodDispatch *,OSObject *,void *) override {
        if(!a||a->asyncWakePort||a->asyncReferenceCount)return kIOReturnBadArgument;
        if(selector==16) {
            if(a->scalarInputCount!=2||!a->scalarInput||a->scalarOutputCount||a->structureInputSize||a->structureOutputSize)return kIOReturnBadArgument;
            return bb_pdp_block(uint32_t(a->scalarInput[0]),uint32_t(a->scalarInput[1]));
        }
        if(selector==3||selector==17) {
            if(a->scalarInputCount!=1||!a->scalarInput||a->scalarOutputCount!=1||!a->scalarOutput||a->structureInputSize||a->structureOutputSize)return kIOReturnBadArgument;
            // The raw-IP stack has no Apple QoS prepend or metadata
            // trailer. Disabling it is real; enabling is unsupported.
            if(a->scalarInput[0])return kIOReturnUnsupported;
            a->scalarOutput[0]=0;return kIOReturnSuccess;
        }
        static uint32_t seen;
        if(selector<32&&!(__atomic_fetch_or(&seen,1u<<selector,__ATOMIC_RELAXED)&(1u<<selector)))
            IOLog("Pong PDP: native appender selector=%u not implemented; no zero-success/offload result substituted\n",selector);
        return kIOReturnUnsupported;
    }
};
OSDefineMetaClassAndStructors(AppleIPAppenderUserClient,IOUserClient)
class AppleIPAppender:public IOService {
    OSDeclareDefaultStructors(AppleIPAppender)
public:
    IOReturn newUserClient(task_t t,void *s,UInt32 type,OSDictionary *p,IOUserClient **out) override {
        if(!out)return kIOReturnBadArgument;*out=nullptr;if(type)return kIOReturnUnsupported;
        auto *c=OSTypeAlloc(AppleIPAppenderUserClient);if(!c)return kIOReturnNoMemory;
        if(!c->initWithTask(t,s,type,p)||!c->attach(this)){c->release();return kIOReturnNotPermitted;}
        if(!c->start(this)){c->detach(this);c->release();return kIOReturnError;}
        *out=c;return kIOReturnSuccess;
    }
    IOReturn newUserClient(task_t t,void *s,UInt32 type,IOUserClient **out) override{return newUserClient(t,s,type,nullptr,out);}
};
OSDefineMetaClassAndStructors(AppleIPAppender,IOService)
class AppleBasebandPCIPDPManagerBase:public IOService {OSDeclareDefaultStructors(AppleBasebandPCIPDPManagerBase)};
OSDefineMetaClassAndStructors(AppleBasebandPCIPDPManagerBase,IOService)
class AppleBasebandPCIPDPManager:public AppleBasebandPCIPDPManagerBase {OSDeclareDefaultStructors(AppleBasebandPCIPDPManager)};
OSDefineMetaClassAndStructors(AppleBasebandPCIPDPManager,AppleBasebandPCIPDPManagerBase)
class AppleBasebandPCIMAVPDPManager:public AppleBasebandPCIPDPManager {OSDeclareDefaultStructors(AppleBasebandPCIMAVPDPManager)};
OSDefineMetaClassAndStructors(AppleBasebandPCIMAVPDPManager,AppleBasebandPCIPDPManager)

template<class Service>bool publishPdp(IOService *provider) {
    auto *s=OSTypeAlloc(Service);if(!s)return false;
    if(!s->init()){s->release();return false;}
    s->setProperty("PongTransport","actual raw-IP PDP control; physical WAN readiness separately gated");
    s->setProperty("PongNativeBuild","22G100");
    if(!s->attach(provider)){s->release();return false;}
    if(!s->start(provider)){s->detach(provider);s->release();return false;}
    s->registerService();return true;
}

bool pong_baseband_transport_start(PongModemQrtr *owner) {
    if(published&&online&&transport==owner)return true;
    if(!owner||!owner->hello_received||!owner->server_count||!initialize())return false;
    bb_pdp_init();
    IOLockLock(bbGate);transport=owner;online=true;
    for(unsigned i=0;i<owner->server_count;i++){const auto &s=owner->servers[i];cbq_server_new(&bridge,s.service,s.instance,s.node,s.port);}
    IOLockUnlock(bbGate);
    if(published) {
        boardProvider->setProperty("PongPasAuthenticated",pong_modem_is_powered()?kOSBooleanTrue:kOSBooleanFalse);
        boardProvider->setProperty("PongSmp2pReady",pong_modem_is_ready()?kOSBooleanTrue:kOSBooleanFalse);
        boardProvider->setProperty("PongQrtrOnline",kOSBooleanTrue);
        return true;
    }
    auto *provider=IOService::getResourceService();if(!provider)return false;
    auto *board=OSTypeAlloc(AppleBaseband);
    if(!board||!board->init()){if(board)board->release();return false;}
    board->setProperty("PongTransport","real integrated MPSS PAS4 owner");
    board->setProperty("IOUserClientClass","AppleBasebandUserClient");
    if(!board->attach(provider)){board->release();return false;}
    if(!board->start(provider)){board->detach(provider);board->release();return false;}
    auto *control=OSTypeAlloc(AppleBasebandPCIControl);
    if(!control||!control->init()){if(control)control->release();board->stop(provider);board->detach(provider);board->release();return false;}
    control->setProperty("PongTransport","MPSS GLINK/QRTR owner");
    control->setProperty("PongNativeBuild","22G100");
    control->setProperty("PongRawDiagnosticsAvailable",kOSBooleanFalse);
    control->setProperty("IOUserClientClass","AppleBasebandPCIControlUserClient");
    if(!control->attach(provider)){control->release();board->stop(provider);board->detach(provider);board->release();return false;}
    if(!control->start(provider)){control->detach(provider);control->release();board->stop(provider);board->detach(provider);board->release();return false;}
    // Publication has no dependency on ADSP timing or Wi-Fi's DMA/context.
    AppleBasebandPCIInterface *made[ChannelCount]={};
    for(unsigned n=0;n<ChannelCount;n++) {
        auto *s=OSTypeAlloc(AppleBasebandPCIInterface);
        if(!s||!s->init()){if(s)s->release();break;}
        s->setChannel(n);if(!s->attach(provider)){s->release();break;}
        if(!s->start(provider)){s->detach(provider);s->release();break;}made[n]=s;
    }
    bool all=true;for(auto *s:made)all=all&&s;
    if(!all){for(auto *s:made)if(s){s->stop(provider);s->detach(provider);s->release();}control->stop(provider);control->detach(provider);control->release();board->stop(provider);board->detach(provider);board->release();return false;}
    published=true;boardProvider=board;
    board->setProperty("PongPasAuthenticated",pong_modem_is_powered()?kOSBooleanTrue:kOSBooleanFalse);
    board->setProperty("PongSmp2pReady",pong_modem_is_ready()?kOSBooleanTrue:kOSBooleanFalse);
    board->setProperty("PongQrtrOnline",kOSBooleanTrue);
    if(actualRevision[0])board->setProperty("PongFirmwareRevision",actualRevision);
    if(actualImei[0])board->setProperty("PongModemIMEI",actualImei);
    if(actualMsisdn[0])board->setProperty("PongModemMSISDN",actualMsisdn);
    publishIms();
    publishSlots();
    board->registerService();control->registerService();for(auto *s:made)s->registerService();
    const bool pdp=publishPdp<AppleBasebandPCIMAVPDPManager>(provider);
    const bool appender=publishPdp<AppleIPAppender>(provider);
    IOLog("Pong PDP: native manager published=%u appender=%u; real interfaces initially down, WAN and WDS gate link\n",pdp,appender);
    IOLog("PongBaseband: native22G100 PAS/PCI control, real qmux1/qmux2 and explicit PBL/Sahara compatibility published over %u QRTR services; SIM/data not inferred\n",owner->server_count);
    return true;
}
void pong_baseband_transport_server(const PongQrtrServer *s,bool added) {
    if(!bbGate||!s)return;IOLockLock(bbGate);
    if(s->service==3&&!added)nasMux.reset();
    if(added)cbq_server_new(&bridge,s->service,s->instance,s->node,s->port);else cbq_server_del(&bridge,s->service,s->node,s->port);
    IOLockUnlock(bbGate);
}
bool pong_baseband_transport_receive(uint32_t local,uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    if(local>=PongNasMultiplexer::Port&&local<PongNasMultiplexer::Port+2) {
        if(!bbGate)return true;IOLockLock(bbGate);
        const bool consumed=nasMux.receive(local,node,port,static_cast<const uint8_t *>(data),bytes);
        IOLockUnlock(bbGate);return consumed;
    }
    if(local<CBQ_PORT_BASE||local>=CBQ_PORT_BASE+CBQ_MAX_CLIENTS)return false;
    if(!bbGate)return true;IOLockLock(bbGate);
    unsigned slot=local-CBQ_PORT_BASE;bool endpoint=false;
    if(bridge.client[slot].used){auto *s=cbq_server_find(&bridge,bridge.client[slot].service);endpoint=s&&s->node==node&&s->port==port;}
    if(endpoint){auto r=cbq_from_modem(&bridge,local,node,static_cast<const uint8_t *>(data),bytes,scratch,FrameMax);
        if(r.kind==CBQ_TO_HOST&&r.service==CBD_SVC_UIM&&bytes>=7) {
            const auto *sdu=static_cast<const uint8_t *>(data);
            const auto message=cbd_rd16(sdu+3);
            const bool status=(sdu[0]==2&&message==0x2f&&!cbd_error(sdu,bytes))||
                (sdu[0]==4&&message==0x32);
            unsigned length=0;
            if(status&&cbd_sdu_ok(sdu,bytes)&&!cbd_find(sdu,bytes,0x21,&length)&&r.len<=FrameMax-5) {
                // Upstream's native Vinyl capability vector must accompany
                // both card replies and indications. Pong has physical
                // UICC slots, no embedded Tape/eUICC transport. Advertise
                // precisely that board limitation; keep all card/AID/PIN/
                // application/identity bytes and any physical0x21 intact.
                const uint8_t physicalSlots[2]={0,0};
                const unsigned appended=cbd_tlv(scratch+r.len,FrameMax-r.len,0x21,physicalSlots,2);
                if(appended) {
                    r.len+=appended;
                    cbd_wr16(scratch+1,r.len-1);
                    cbd_wr16(scratch+CBQ_HDR+5,bytes-7+appended);
                    static unsigned reported;
                    if(__atomic_fetch_add(&reported,1u,__ATOMIC_RELAXED)<4)
                        IOLog("Pong SIM: native card-status physical-slot capability vector added; actual card state unchanged\n");
                }
            }
        }
        if(r.kind==CBQ_TO_HOST&&push(r.channel,scratch,r.len)) {
            ++received;const auto *sdu=static_cast<const uint8_t *>(data);
            if(r.service==3&&bytes>=7&&sdu[0]==2)
                for(auto &metric:nasMetrics)if(metric.message==cbd_rd16(sdu+3))++metric.received;
            if(r.service==CBD_SVC_WDS)cbp_observe(&bb_pdp_clients[slot],sdu,bytes);
            if(r.service==CBD_SVC_UIM&&bytes>=7&&sdu[0]==2&&cbq_rd16(sdu+3)==CBD_UIM_READ_TRANSPARENT)
                for(auto &request:simReads)if(request.active&&request.channel==r.channel&&request.cid==r.cid&&request.transaction==cbq_rd16(sdu+1)) {
                    request.active=false;uint8_t ef[16],value[CBD_ICCID_BYTES];
                    unsigned n=cbd_uim_read_content(sdu,bytes,ef,sizeof ef);
                    bool iccid=request.file==CBD_EF_ICCID;
                    bool valid=iccid?cbd_iccid_from_ef(ef,n,value):cbd_imsi_from_ef(ef,n,value);
                    if(valid){memcpy(iccid?simIccid:simImsi,value,iccid?sizeof simIccid:sizeof simImsi);if(iccid)haveIccid=true;else haveImsi=true;activationChanged();}
                    break;
                }
        }else ++failed;
    }else ++failed;IOLockUnlock(bbGate);return true;
}
void pong_baseband_transport_poll() {
    if(!bbGate||!transport)return;
    IOLockLock(bbGate);
    nasMux.poll();
    struct {uint32_t node,port;} blocked[TxCount];unsigned blockedCount=0;
    const unsigned initial=txCount;unsigned accepted=0;
    for(unsigned n=0;online&&n<initial&&accepted<16&&txCount;n++) {
        auto &t=tx[txHead];const unsigned slot=t.local-CBQ_PORT_BASE;
        bool alive=slot<CBQ_MAX_CLIENTS&&bridge.client[slot].used;
        bool paused=false;for(unsigned i=0;i<blockedCount;i++)if(blocked[i].node==t.node&&blocked[i].port==t.port){paused=true;break;}
        if(alive&&paused) {
            Tx retained=t;t={};txHead=(txHead+1)%TxCount;--txCount;
            tx[(txHead+txCount)%TxCount]=retained;++txCount;continue;
        }
        if(alive&&t.bytes>=7) {
            const auto &client=bridge.client[slot];const unsigned message=cbd_rd16(t.data+3);
            const bool bind=(client.service==CBD_SVC_WDS&&message==CBD_WDS_BIND_MUX_DATA_PORT)||
                (client.service==CBD_SVC_QOS&&message==CBD_QOS_BIND_DATA_PORT);
            const int state=bind?pong_modem_data_port_status():0;
            if(state==EAGAIN) {
                blocked[blockedCount++]={t.node,t.port};
                Tx retained=t;t={};txHead=(txHead+1)%TxCount;--txCount;
                tx[(txHead+txCount)%TxCount]=retained;++txCount;continue;
            }
            if(state) {
                // Return the real prerequisite failure through QMI, not
                // a successful bind to an unconfigured hardware endpoint.
                const unsigned n=cbq_private_answer(t.data,client.service,client.cid,52,nullptr,0,scratch,FrameMax);
                if(!n||!push(client.channel,scratch,n))break;
                ++failed;IOFreeData(t.data,t.bytes);t={};txHead=(txHead+1)%TxCount;--txCount;continue;
            }
        }
        int result=alive?(bridge.client[slot].service==3?
            nasMux.send(slot,t.node,t.port,t.data,t.bytes):
            pong_modem_qrtr_send(transport,t.local,t.node,t.port,t.data,t.bytes)):0;
        if(result==EAGAIN) {
            blocked[blockedCount++]={t.node,t.port};
            Tx retained=t;t={};txHead=(txHead+1)%TxCount;--txCount;
            tx[(txHead+txCount)%TxCount]=retained;++txCount;continue;
        }
        if(result)break; // retain actual unsent frame until GLINK accepts it
        if(alive){++sent;++accepted;}
        IOFreeData(t.data,t.bytes);t={};txHead=(txHead+1)%TxCount;--txCount;
    }
    // Clear release_pending only when the actual DEL_CLIENT was accepted.
    for(unsigned n=0;online&&n<CBQ_MAX_CLIENTS;n++)if(bridge.client[n].release_pending) {
        bool queued=false;
        for(unsigned j=0;j<txCount;j++)if(tx[(txHead+j)%TxCount].local==CBQ_PORT_BASE+n){queued=true;break;}
        // Do not reuse a QRTR slot while its previous owner's cancelled
        // frames remain behind another blocked transmission in the FIFO.
        if(!queued) {
            if(bridge.client[n].service==3){nasMux.release(n);bridge.client[n].release_pending=0;}
            else if(!pong_modem_qrtr_delete_client(transport,CBQ_PORT_BASE+n))bridge.client[n].release_pending=0;
        }
    }
    IOLockUnlock(bbGate);
    bb_pdp_poll();
}
void pong_baseband_transport_offline() {
    if(!bbGate||!online)return;IOLockLock(bbGate);online=false;transport=nullptr;
    if(boardProvider) {
        boardProvider->setProperty("PongPasAuthenticated",kOSBooleanFalse);
        boardProvider->setProperty("PongSmp2pReady",kOSBooleanFalse);
        boardProvider->setProperty("PongQrtrOnline",kOSBooleanFalse);
    }
    while(txCount){auto &t=tx[txHead];IOFreeData(t.data,t.bytes);t={};txHead=(txHead+1)%TxCount;--txCount;}
    cbq_init(&bridge);
    nasMux.reset();
    for(auto &value:actualIms)value=~0u;publishIms();
    bzero(bb_pdp_clients,sizeof bb_pdp_clients);bzero(bb_pdp_owners,sizeof bb_pdp_owners);
    bzero(activation,sizeof activation);bzero(simReads,sizeof simReads);
    haveIccid=haveImsi=false;bzero(simIccid,sizeof simIccid);bzero(simImsi,sizeof simImsi);
    bzero(actualRevision,sizeof actualRevision);if(boardProvider)boardProvider->removeProperty("PongFirmwareRevision");
    nasMessageBytes=0;
    bzero(actualImei,sizeof actualImei);if(boardProvider)boardProvider->removeProperty("PongModemIMEI");
    bzero(actualMsisdn,sizeof actualMsisdn);if(boardProvider)boardProvider->removeProperty("PongModemMSISDN");
    actualSlots=0;
    if(boardProvider){boardProvider->removeProperty("PongSimSlots");boardProvider->removeProperty("PongSimSlotCount");}
    for(auto &c:channels){while(c.count){Frame f=pop(c);IOFreeData(f.data,f.bytes);}IOLockWakeup(bbGate,&c,false);}
    bootImageAccepted=false;bzero(&nativeBoot,sizeof nativeBoot);
    IOLockUnlock(bbGate);for(unsigned n=0;n<ChannelCount;n++)abortReads(n,nullptr,kIOReturnOffline);
    bb_pdp_poll();
}
void pong_baseband_transport_report() {
    if(!bbGate)return;IOLockLock(bbGate);
    IOLog("PongBaseband snapshot: qmux_published=%u transport_online=%u opens=%u sent=%u received=%u errors=%u private_unimplemented=%u queued=%u; ABM/PDP not yet qualified\n",published,online,opened,sent,received,failed,privateRequests,txCount);
    IOLog("PongBaseband snapshot: native_control_opens=%u diagnostic_reads=%u board_calls=%u last_board_selector=%u actual_firmware_revision=%u\n",
        controlOpens,controlReads,boardCalls,lastBoardSelector,actualRevision[0]!=0);
    IOLog("PongBaseband snapshot: native_boot_profile_queries=%u consumed_bytes=%llu sahara_state=%u; Apple firmware never executed, actual SIM/network unchanged\n",nativeBootQueries,nativeBootBytes,nativeBoot.state);
    IOLog("PongBaseband snapshot: actual_DMS_IMEI_present=%u; identity contents not logged\n",actualImei[0]!=0);
    IOLog("PongBaseband snapshot: actual_MSISDN_present=%u ICCID_present=%u IMSI_present=%u; subscriber contents not logged\n",actualMsisdn[0]!=0,haveIccid,haveImsi);
    IOLog("PongBaseband snapshot: actual_read_copies=%u copy_failed=%u async_delivered=%u async_failed=%u slots=%u\n",readCopied,readCopyFailed,asyncDelivered,asyncFailed,actualSlots);
    if(transport)IOLog("PongBaseband snapshot: QRTR_confirm_sent=%u resumes_received=%u credit_waits=%u response_consumed=%u; real per-endpoint flow control\n",transport->flow_confirmed,transport->flow_resumed,transport->flow_blocked,transport->flow_response_consumed);
    for(const auto &metric:nasMetrics)
        IOLog("Pong NAS: message=%x queued=%u sent=%u received=%u physically_unsupported=%u\n",metric.message,metric.queued,metric.sent,metric.received,metric.unsupported);
    nasMux.report();
    if(transport) {
        const auto *nas=cbq_server_find(&bridge,3);
        if(nas)for(const auto &flow:transport->tx_flow)if(flow.used&&flow.node==nas->node&&flow.port==nas->port)
            IOLog("Pong NAS: actual endpoint node=%u port=%u outstanding=%u supported_bitmap_bytes=%u\n",nas->node,nas->port,flow.pending,nasMessageBytes);
    }
    IOLockUnlock(bbGate);
    bb_pdp_report(0);
}
bool pong_baseband_transport_nas_messages(const uint8_t *data,uint32_t bytes) {
    if(!data||!bytes||bytes>sizeof nasMessages||!bbGate)return false;
    IOLockLock(bbGate);memcpy(nasMessages,data,bytes);nasMessageBytes=bytes;
    IOLog("Pong NAS: physical GetSupportedMessages received bytes=%u message45=%u message4f=%u; unsupported native operations keep real errors\n",
        bytes,bytes>0x45/8&&bool(data[0x45/8]&(1u<<(0x45%8))),bytes>0x4f/8&&bool(data[0x4f/8]&(1u<<(0x4f%8))));
    IOLockUnlock(bbGate);return true;
}
void pong_baseband_transport_revision(const char *revision,uint32_t bytes) {
    if(!revision||!bytes||bytes>256)return;
    while(bytes&&revision[bytes-1]==0)--bytes;if(!bytes)return;
    for(unsigned i=0;i<bytes;i++)if(revision[i]<32||revision[i]>126)return;
    // Only the MPSS thread publishes/updates these bytes, following a real
    // transaction- and endpoint-matched, successful DMS GetRevision reply.
    if(bbGate)IOLockLock(bbGate);
    memcpy(actualRevision,revision,bytes);actualRevision[bytes]=0;
    if(boardProvider)boardProvider->setProperty("PongFirmwareRevision",actualRevision);
    if(bbGate)IOLockUnlock(bbGate);
}
bool pong_baseband_transport_slots(const uint8_t *data,uint32_t bytes) {
    if(!data||bytes<9||data[8]>8)return false;
    uint8_t states[8]={},errors[8]={};const unsigned slots=data[8];unsigned at=9;
    // libqmi UIM CardStatus: four application indices, card count, then
    // bounded card records with variable AID data per application.
    for(unsigned n=0;n<slots;n++) {
        if(bytes-at<6)return false;
        states[n]=data[at];errors[n]=data[at+4];const unsigned apps=data[at+5];at+=6;
        if(states[n]>3||apps>16)return false;
        for(unsigned i=0;i<apps;i++) {
            if(bytes-at<7)return false;
            const unsigned aid=data[at+6];
            if(bytes-at<14u+aid)return false;
            at+=14u+aid;
        }
    }
    if(at!=bytes)return false;
    if(bbGate)IOLockLock(bbGate);
    actualSlots=slots;memcpy(actualSlotState,states,slots);memcpy(actualSlotError,errors,slots);
    if(!slots||states[0]!=1){haveIccid=haveImsi=false;bzero(simIccid,sizeof simIccid);bzero(simImsi,sizeof simImsi);
        bzero(actualMsisdn,sizeof actualMsisdn);if(boardProvider)boardProvider->removeProperty("PongModemMSISDN");}
    if(slots)publishSlots();
    else if(boardProvider){boardProvider->removeProperty("PongSimSlots");boardProvider->setProperty("PongSimSlotCount",uint64_t(0),32);}
    if(bbGate){activationChanged();IOLockUnlock(bbGate);}return true;
}
bool pong_baseband_transport_imei(const char *imei,uint32_t bytes) {
    if(!imei||!bytes||bytes>16)return false;
    if(bytes==16&&imei[15]==0)--bytes;
    if(bytes!=15)return false;
    bool nonzero=false;
    for(unsigned i=0;i<bytes;i++) {
        if(imei[i]<'0'||imei[i]>'9')return false;
        nonzero|=imei[i]!='0';
    }
    if(!nonzero)return false;
    if(bbGate)IOLockLock(bbGate);
    memcpy(actualImei,imei,15);actualImei[15]=0;
    if(boardProvider)boardProvider->setProperty("PongModemIMEI",actualImei);
    if(bbGate)IOLockUnlock(bbGate);
    return true;
}
bool pong_baseband_transport_msisdn(const char *number,uint32_t bytes) {
    if(bytes>32||(!number&&bytes))return false;
    if(bytes&&number[bytes-1]==0)--bytes;
    unsigned digits=0;
    for(unsigned i=0;i<bytes;i++) {
        if(i==0&&number[i]=='+')continue;
        if(number[i]<'0'||number[i]>'9')return false;
        ++digits;
    }
    if(bytes&&!digits)return false;
    if(bbGate)IOLockLock(bbGate);
    bzero(actualMsisdn,sizeof actualMsisdn);if(bytes)memcpy(actualMsisdn,number,bytes);
    if(boardProvider) {
        if(bytes)boardProvider->setProperty("PongModemMSISDN",actualMsisdn);
        else boardProvider->removeProperty("PongModemMSISDN");
    }
    if(bbGate)IOLockUnlock(bbGate);
    return true;
}
void pong_baseband_transport_ims(uint32_t registration,uint32_t technology,uint32_t voice,uint32_t sms,
    uint32_t voiceTechnology,uint32_t voiceEnabled,uint32_t registrationEnabled) {
    const uint32_t values[]={registration,technology,voice,sms,voiceTechnology,voiceEnabled,registrationEnabled};
    if(bbGate)IOLockLock(bbGate);
    memcpy(actualIms,values,sizeof actualIms);publishIms();
    if(bbGate)IOLockUnlock(bbGate);
}
bool pong_baseband_transport_sim_identity(uint16_t file,const uint8_t *content,uint32_t bytes) {
    uint8_t decoded[CBD_ICCID_BYTES]={};
    const bool iccid=file==CBD_EF_ICCID;
    if(file&&(!content||!(iccid?cbd_iccid_from_ef(content,bytes,decoded):
            file==CBD_EF_IMSI&&cbd_imsi_from_ef(content,bytes,decoded))))return false;
    if(bbGate)IOLockLock(bbGate);
    if(!file) {
        haveIccid=haveImsi=false;bzero(simIccid,sizeof simIccid);bzero(simImsi,sizeof simImsi);
    } else if(!actualSlots||actualSlotState[0]!=1) {
        if(bbGate)IOLockUnlock(bbGate);return false;
    } else {
        memcpy(iccid?simIccid:simImsi,decoded,iccid?sizeof simIccid:sizeof simImsi);
        if(iccid)haveIccid=true;else haveImsi=true;
    }
    if(bbGate){activationChanged();IOLockUnlock(bbGate);}return true;
}
bool pong_baseband_wan_backend(int (*send)(uint32_t,const uint8_t *,uint32_t),bool (*ready)(void)) {
    if(!send||!ready||pong_wan_sender)return false;
    pong_wan_sender=send;pong_wan_ready=ready;return true;
}
void pong_baseband_wan_receive(uint32_t mux,const uint8_t *ip,uint32_t bytes,uint32_t version) {
    if(pong_wan_ready&&pong_wan_ready()&&pong_wan_receive)pong_wan_receive(mux,ip,bytes,version);
}
extern "C" bool pong_modem_native_online_requested(void) {
    return __atomic_load_n(&nativeRadioIntent,__ATOMIC_ACQUIRE)==0;
}
