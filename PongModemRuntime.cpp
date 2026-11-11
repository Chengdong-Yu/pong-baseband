/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SM8475/cape MPSS PAS4 owner. Uses this Pong's signed ELF32 firmware and
 * SMEM/private partition; no SC7180 IPA registers or Apple firmware input.
 * Startup is optional and bounded, never blocks launchd or publishes a
 * successful AppleBaseband endpoint without the actual modem transport.
 */
#include "PongModemRuntime.h"
#include "PongModemControl.h"
#include "PongBasebandService.h"
#include "PongPlatformResources.h"
#include "PongLowDma.h"
#include "PongModemPdDomains.h"
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>
#include <sys/errno.h>
extern "C" {
#include "QcomMdt.h"
#include "QcomScm.h"
#include "QcomSmem.h"
#include "QcomRpmh.h"
int sheng_fw_open(const char *,void **,uint64_t *);
int sheng_fw_read(void *,uint64_t,void *,size_t);
void sheng_fw_close(void *);
kern_return_t clear_wait(thread_t,wait_result_t);
bool pong_baseband_service_classes_ready(void);
extern unsigned long gPhysBase,gPhysSize;
volatile int32_t native_modem_stats[16];
}
namespace {
constexpr uint64_t SmemBase=0x80900000,SmemBytes=0x200000,MutexBase=0x1f43000;
constexpr uint64_t ModemBase=0x8bc00000,ModemBytes=0x13200000;
constexpr unsigned FifoBytes=0x4000,PacketBytes=PongQrtrHeader+PongQrtrMaxPayload;
constexpr uint16_t ItemOut=428,ItemIn=435,ItemDesc=478,ItemTx=479,ItemRx=480;
constexpr uint32_t Ready=2,Fatal=1;
struct Window {
    IOMemoryMap *map=nullptr;volatile uint8_t *va=nullptr;
    bool open(uint64_t base,size_t size,IOOptionBits cache=kIOMapInhibitCache) {
        auto *memory=IODeviceMemory::withRange(base,size);
        map=memory?memory->map(kIOMapAnywhere|cache):nullptr;
        if(memory)memory->release();
        va=map?reinterpret_cast<volatile uint8_t *>(map->getVirtualAddress()):nullptr;
        return va;
    }
    void close(){if(map)map->release();map=nullptr;va=nullptr;}
};
Window smemWindow,mutexWindow;
QcomSmem smem;
QcomSmemPartition part;
PongModemControl control;
PongModemDoorbell doorbell;
QcomMdtImage image;
volatile uint32_t pending;
uint8_t *intentStorage,*qrtrStorage,*atStorage,*ssmStorage;
uint64_t loadedBytes;
bool pasStarted,controlInitialized;

uint64_t nowMs(){uint64_t ns=0;absolutetime_to_nanoseconds(mach_absolute_time(),&ns);return ns/1000000;}
void stage(int step){native_modem_stats[0]=step;IOLog("PongModem: stage=%d PAS4 SM8475\n",step);}
void fail(int step,int error) {
    native_modem_stats[0]=-step;native_modem_stats[1]=error;
    IOLog("PongModem: startup stopped stage=%d error=%d; normal boot retained, cellular backend not published\n",step,error);
}
void wake(void *,uint32_t events) {
    __atomic_fetch_or(&pending,events,__ATOMIC_RELEASE);
    thread_wakeup(static_cast<event_t>(const_cast<uint32_t *>(&pending)));
}
uint32_t waitEvents(unsigned ms) {
    uint32_t events=__atomic_exchange_n(&pending,0,__ATOMIC_ACQ_REL);if(events)return events;
    assert_wait_timeout(static_cast<event_t>(const_cast<uint32_t *>(&pending)),THREAD_UNINT,ms,kMillisecondScale);
    events=__atomic_exchange_n(&pending,0,__ATOMIC_ACQ_REL);
    if(events)clear_wait(current_thread(),THREAD_AWAKENED);else thread_block(THREAD_CONTINUE_NULL);
    return events|__atomic_exchange_n(&pending,0,__ATOMIC_ACQ_REL);
}
void kick(void *,uint32_t signal){(void)pong_modem_doorbell_send(signal);}
bool lockSmem() {
    if(!pong_smem_local_lock())return false;
    auto *lock=reinterpret_cast<volatile uint32_t *>(mutexWindow.va);
    for(unsigned n=0;n<1000;n++) {
        *lock=1;__asm__ volatile("dsb sy":::"memory");
        if(*lock==1)return true;IODelay(10);
    }
    pong_smem_local_unlock();return false;
}
void unlockSmem(){*reinterpret_cast<volatile uint32_t *>(mutexWindow.va)=0;__asm__ volatile("dsb sy":::"memory");pong_smem_local_unlock();}
int allocate(uint16_t id,uint32_t bytes) {
    if(!lockSmem())return EBUSY;
    int rc=qcom_smem_alloc(&smem,&part,id,bytes);unlockSmem();
    return rc==QcomSmemExists?0:rc;
}
volatile uint8_t *item(uint16_t id,uint32_t minimum,uint32_t *length=nullptr) {
    uint32_t offset=0,bytes=0;
    if(qcom_smem_find(&smem,&part,id,&offset,&bytes)||bytes<minimum||offset>SmemBytes||bytes>SmemBytes-offset)return nullptr;
    if(length)*length=bytes;return smemWindow.va+offset;
}
void crashReason() {
    QcomSmemPartition global{};uint32_t off=0,bytes=0;
    if(qcom_smem_partition(&smem,QCOM_SMEM_HOST_GLOBAL,QCOM_SMEM_HOST_GLOBAL,&global)||
       qcom_smem_find(&smem,&global,421,&off,&bytes)||!bytes)return;
    char text[128];size_t n=0;
    for(;n<sizeof(text)-1&&n<bytes;n++){char c=char(smemWindow.va[off+n]);if(!c)break;text[n]=c>=32&&c<127?c:'.';}
    text[n]=0;if(n)IOLog("PongModem: MPSS crash reason %s\n",text);
}
struct Result {int64_t status;uint64_t result;};
Result scmCall(uint32_t service,uint32_t command,uint32_t args,uint64_t a,uint64_t b,uint64_t c,uint64_t extra) {
    native_modem_stats[10]=int32_t(command);
    Result result{-1,0};if(!pong_scm_call_lock())return result;
    for(unsigned busy=0;busy<20;busy++) {
        uint64_t function=qcom_scm_fn(service,command),session=0;
        for(unsigned resumed=0;resumed<100000;resumed++) {
            register uint64_t x0 __asm__("x0")=function,x1 __asm__("x1")=args,x2 __asm__("x2")=a,
                x3 __asm__("x3")=b,x4 __asm__("x4")=c,x5 __asm__("x5")=extra,x6 __asm__("x6")=session,x7 __asm__("x7")=0;
            __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3),"+r"(x4),"+r"(x5),"+r"(x6),"+r"(x7)
                ::"x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","memory");
            result={int64_t(x0),x1};if(result.status!=QCOM_SCM_INTERRUPTED)break;
            function=QCOM_SCM_INTERRUPTED;session=x6;
        }
        if(result.status!=QCOM_SCM_V2_EBUSY)break;IOSleep(30);
    }
    pong_scm_call_unlock();native_modem_stats[2]=int32_t(result.status);native_modem_stats[3]=int32_t(result.result);
    return result;
}
Result scm(uint32_t command,uint32_t args,uint64_t a,uint64_t b=0,uint64_t c=0) {
    return scmCall(QCOM_SCM_SVC_PIL,command,args,a,b,c,0);
}
bool ok(Result r){return !r.status&&!r.result;}
#include "PongModemMemshare.h"
#include "PongModemRmtfs.h"
#include "PongModemSysmon.h"
#include "PongModemIpa.h"
#include "PongModemSim.h"
#include "PongModemPdc.h"
#include "PongModemDiag.h"
#include "PongModemFiles.h"
#include "PongModemStatus.h"
#include "PongModemIms.h"
#include "PongModemData.h"
#include "PongModemIpaDma.h"
#include "PongModemRules.h"
#include "PongIpaFilters.h"
#include "PongModemWan.h"
#include "PongImsDcm.h"
int read(void *file,uint64_t offset,void *to,size_t bytes){return sheng_fw_read(file,offset,to,bytes);}
bool rails() {
    Window db;if(!db.open(0x80860000,0x20000))return false;
    auto *copy=static_cast<uint8_t *>(IOMallocData(0x20000));if(!copy){db.close();return false;}
    for(unsigned i=0;i<0x20000;i+=4){uint32_t w=*reinterpret_cast<volatile uint32_t *>(db.va+i);memcpy(copy+i,&w,4);}
    db.close();bool ready=true;
    const char *resources[]={"cx.lvl","mss.lvl"};
    for(const char *name:resources) {
        QcomRpmhResource resource{};uint32_t level=0;
        if(qcom_cmd_db_find(copy,0x20000,name,&resource)||qcom_rpmh_level_index(&resource,384,&level)||
           !pong_rpmh_vote(resource.address,level)){ready=false;break;}
        IOLog("PongModem: actual proxy %s level=384 index=%u\n",name,level);
    }
    QcomRpmhResource xo{};
    if(ready)ready=!qcom_cmd_db_find(copy,0x20000,"xo.lvl",&xo)&&pong_rpmh_vote(xo.address,3);
    IOFreeData(copy,0x20000);return ready;
}
int load(void *file) {
    constexpr size_t chunk=256*1024;
    auto *bounce=static_cast<uint8_t *>(IOMallocData(chunk));if(!bounce)return ENOMEM;
    int result=0;
    for(unsigned i=0;!result&&i<image.count;i++) {
        const auto &s=image.segment[i];if(!s.load)continue;
        uint64_t offset=0;if(qcom_mdt_place(&image,i,ModemBase,ModemBytes,&offset)){result=EINVAL;break;}
        for(uint64_t done=0;done<s.memory_size&&!result;) {
            size_t n=size_t(s.memory_size-done<chunk?s.memory_size-done:chunk);
            size_t bytes=done<s.file_size?size_t(s.file_size-done<n?s.file_size-done:n):0;
            if(bytes&&read(file,s.file_offset+done,bounce,bytes)){result=EIO;break;}
            if(bytes<n)bzero(bounce+bytes,n-bytes);
            const uint64_t physical=ModemBase+offset+done,base=physical&~UINT64_C(4095);
            const size_t within=size_t(physical-base),span=(within+n+4095)&~size_t(4095);
            Window window;if(!window.open(base,span,kIOMapWriteCombineCache)){result=ENOMEM;break;}
            memcpy(const_cast<uint8_t *>(window.va)+within,bounce,n);__asm__ volatile("dsb sy":::"memory");window.close();
            done+=n;loadedBytes+=n;
        }
    }
    IOFreeData(bounce,chunk);return result;
}
void state(void *,uint32_t value,uint32_t changed) {
    native_modem_stats[4]=int32_t(value);
    IOLog("PongModem: actual slave-kernel=%x changed=%x\n",value,changed);
}
void server(void *,const PongQrtrServer *s,bool added) {
    pong_baseband_transport_server(s,added);
    modemStatusServer(s,added);
    modemIms.server(s,added);
    imsDcm.server(s,added);
    modemSimServer(s,added);
    modemPdc.server(s,added);
    modemDiag.server(s,added);
    modemDataServer(s,added);
    wan.server(s,added);
    sysmonModemServer(s,added);
    IOLog("PongModem: QRTR service %s id=%u version_instance=%x node=%u port=%u\n",added?"added":"removed",s->service,s->instance,s->node,s->port);
}
constexpr uint32_t LocatorPort=0x100;
struct LocatorReply {uint32_t local=0,node=0,port=0,bytes=0;bool request=false;uint8_t data[4096];};
LocatorReply locatorReplies[8];
uint8_t serviceRequest[4096];
uint32_t locatorHead,locatorCount,locatorAnswered;
bool receive(void *,uint32_t local,uint32_t node,uint32_t port,const void *data,uint32_t bytes) {
    if(pong_baseband_transport_receive(local,node,port,data,bytes))return true;
    if(local==ModemStatusPort)return modemStatusReceive(node,port,data,bytes);
    if(local>=ModemImsPort&&local<=ModemImsPort+1)return modemIms.receive(local,node,port,static_cast<const uint8_t *>(data),bytes);
    if(local==ImsDcmPort||local==ImsDcmPort+1)return imsDcm.receive(local,node,port,static_cast<const uint8_t *>(data),bytes);
    if(local==ModemSimPort)return modemSimReceive(node,port,data,bytes);
    if(local==ModemPdcPort)return modemPdc.receive(node,port,static_cast<const uint8_t *>(data),bytes);
    if(local>=ModemDiagControlPort&&local<=ModemDiagCommandPort)return modemDiag.receive(local,node,port,static_cast<const uint8_t *>(data),bytes);
    if(modemFiles.receive(local,node,port,static_cast<const uint8_t *>(data),bytes))return true;
    if(local==DataPorts[0]||local==DataPorts[1])return modemDataReceive(local,node,port,data,bytes);
    if(local==IpaHostPort||local==IpaClientPort)return wan.receive(local,node,port,static_cast<const uint8_t *>(data),bytes);
    if(local==SysmonPort)return sysmonModemReceive(node,port,data,bytes);
    if(local!=LocatorPort&&local!=MemsharePort&&local!=RmtfsPort)return false;
    if(locatorCount==8)return false;
    auto &reply=locatorReplies[(locatorHead+locatorCount)%8];
    reply.local=local;reply.request=local!=LocatorPort;
    if(reply.request) {
        if(bytes>sizeof serviceRequest)return false;
        memcpy(reply.data,data,bytes);reply.bytes=bytes;
    } else reply.bytes=qcom_servloc_answer(PongPdDomains,sizeof(PongPdDomains)/sizeof(*PongPdDomains),
            static_cast<const uint8_t *>(data),bytes,reply.data,sizeof reply.data);
    if(!reply.bytes)return false;
    reply.node=node;reply.port=port;++locatorCount;return true;
}
void locatorPoll() {
    while(locatorCount) {
        auto &reply=locatorReplies[locatorHead];
        if(reply.request) {
            const uint32_t bytes=reply.bytes;memcpy(serviceRequest,reply.data,bytes);
            reply.bytes=reply.local==MemsharePort?
                memshareAnswer(reply.node,reply.port,serviceRequest,bytes,reply.data,sizeof reply.data):
                rmtfsAnswer(reply.node,serviceRequest,bytes,reply.data,sizeof reply.data);
            reply.request=false;
        }
        if(reply.bytes&&pong_modem_qrtr_send(&control.qrtr,reply.local,reply.node,reply.port,reply.data,reply.bytes))return;
        locatorHead=(locatorHead+1)%8;--locatorCount;
        if(++locatorAnswered<=8)IOLog("PongModem: actual Pong domain-locator response=%u\n",locatorAnswered);
    }
}
void link(void *,bool up){
    if(!up){pong_baseband_transport_offline();modemDiag.offline();modemFiles.offline();imsDcm.offline();}
    IOLog("PongModem: actual QRTR link %s; ABM/data prerequisites pending\n",up?"up":"down");
}
void refreshRemote() {
    uint32_t bytes=0;auto *desc=item(ItemDesc,32),*rx=item(ItemRx,64,&bytes);
    auto *in=reinterpret_cast<volatile uint32_t *>(item(ItemIn,QCOM_SMP2P_ITEM_BYTES));
    if(in&&!qcom_smp2p_check_in(in,0,1))control.smp2p.in=in;
    if(!desc||!rx||!in)return;
    auto *d=reinterpret_cast<volatile uint32_t *>(desc);
    (void)pong_modem_control_remote(&control,{&d[3],&d[2],rx,bytes},in);
}
bool start() {
    if(!smemWindow.open(SmemBase,SmemBytes)||!mutexWindow.open(MutexBase,0x1000)){fail(1,ENOMEM);return false;}
    smem={smemWindow.va,uint32_t(SmemBytes)};
    int rc=qcom_smem_partition(&smem,0,1,&part);if(rc){fail(1,rc);return false;}
    // Original ipa_smmu_ap probe allocates SMEM_IPA_FILTER_TABLE497,
    // size0x9000 from this Pong DT, before modem/IPA table accesses.
    // Use the real partition allocator and HW lock, never a guessed PA.
    rc=allocate(497,0x9000);
    if(rc||!item(497,0x9000)){fail(1,rc?rc:ENOMEM);return false;}
    stage(1);
    void *file=nullptr;uint64_t size=0;
    for(unsigned n=0;n<90;n++){rc=sheng_fw_open("/pong/firmware/modem.mbn",&file,&size);if(!rc||rc!=ENOENT&&rc!=ENXIO&&rc!=EIO)break;IOSleep(1000);}
    if(rc){fail(2,rc);return false;}
    // Original cape remoteproc is not autobooted: userspace prepares RFS
    // before starting MPSS. RF initialization can request readwrite files
    // immediately, so do not authenticate/start it against an unmounted
    // native Data namespace. This bounded wait owns no AOP/UFS/QRTR lock
    // and runs only on the optional modem worker, never the boot thread.
    const uint64_t rfsDeadline=nowMs()+120000;
    while(!pong_rfs_ready()&&nowMs()<rfsDeadline)IOSleep(20);
    if(!pong_rfs_ready()){sheng_fw_close(file);fail(2,EAGAIN);return false;}
    IOLog("PongModem: actual native RFS storage ready before PAS4 start\n");
    rc=qcom_mdt_parse(&image,size,read,file);
    if(rc||image.elf64||image.min_address!=ModemBase||qcom_mdt_span(&image)>ModemBytes||
       (gPhysBase<ModemBase+ModemBytes&&ModemBase<gPhysBase+gPhysSize)) {
        sheng_fw_close(file);fail(2,rc?rc:EINVAL);return false;
    }
    // The actual metadata DMA contract is below4GiB for cape MPSS.
    uint64_t metadataPa=0;Window metadata;
    const size_t metadataBytes=size_t(qcom_mdt_metadata_size(&image));
    if(!metadataBytes||metadataBytes>65536||!PongLowDma::modemMetadataAddress(metadataPa)||
       !metadata.open(metadataPa,65536,kIOMapWriteCombineCache)) {
        sheng_fw_close(file);fail(2,ENOMEM);return false;
    }
    rc=qcom_mdt_metadata(&image,read,file,const_cast<uint8_t *>(metadata.va),65536);
    if(rc){metadata.close();sheng_fw_close(file);fail(2,rc);return false;}
    __asm__ volatile("dsb sy":::"memory");stage(2);
    // AOP request executes on ADSP's existing mailbox thread, not a second
    // reset/handshake owner. Wait only on this optional worker.
    rc=EAGAIN;
    for(unsigned n=0;n<1200&&rc==EAGAIN;n++){rc=pong_aop_modem_power_on();if(rc==EAGAIN)IOSleep(100);}
    if(rc||!rails()){metadata.close();sheng_fw_close(file);fail(3,rc?rc:EIO);return false;}
    if(!sysmonStart())IOLog("PongModem: ADSP SysMon link unavailable; no DSP lifecycle success assumed\n");
    (void)ipaClockPrepare();
    (void)ipaFirmwareStart(metadataPa,metadataBytes);
    (void)ipaResourcesPrepare();
    stage(3);
    // remoteproc cold-start authenticates INIT_IMAGE first; SHUTDOWN is a
    // stop operation for an owned, started PAS session. On cape an offline
    // PAS4 returns TZ -0x300048 to an unconditional shutdown. Do not discard
    // that error and pretend a stop succeeded. Establish a real new secure
    // session before touching the APPS FIFO descriptors instead.
    QcomSmp2p previous{};
    previous.in=reinterpret_cast<volatile uint32_t *>(item(ItemIn,QCOM_SMP2P_ITEM_BYTES));
    previous.local_pid=0;previous.remote_pid=1;
    const int entry=previous.in&&!qcom_smp2p_check_in(previous.in,0,1)?qcom_smp2p_find_in(&previous,"slave-kernel"):-1;
    const uint32_t oldState=entry>=0?qcom_smp2p_in_value(&previous,entry):0;
    if(oldState&Ready) {
        IOLog("PongModem: foreign ready state=%x; refusing FIFO reset without an owned stop\n",oldState);
        metadata.close();sheng_fw_close(file);fail(4,EBUSY);return false;
    }
    if(!ok(scm(QCOM_SCM_PAS_INIT_IMAGE,qcom_scm_args(2,QCOM_SCM_VAL,QCOM_SCM_RW,0),4,metadataPa))) {
        metadata.close();sheng_fw_close(file);fail(4,EIO);return false;
    }
    IOLog("PongModem: actual PAS4 INIT_IMAGE accepted before APPS descriptor initialization\n");
    rc=pong_modem_doorbell_init(&doorbell,wake,nullptr);
    if(!rc)rc=allocate(ItemOut,QCOM_SMP2P_ITEM_BYTES);
    if(!rc)rc=allocate(ItemDesc,32);
    if(!rc)rc=allocate(ItemTx,FifoBytes);
    auto *out=reinterpret_cast<volatile uint32_t *>(item(ItemOut,QCOM_SMP2P_ITEM_BYTES));
    auto *d=reinterpret_cast<volatile uint32_t *>(item(ItemDesc,32));
    uint32_t txBytes=0;auto *tx=item(ItemTx,64,&txBytes);
    if(rc||!out||!d||!tx){metadata.close();sheng_fw_close(file);fail(4,rc?rc:ENOENT);return false;}
    d[1]=0;d[2]=0;__asm__ volatile("dmb oshst":::"memory");
    intentStorage=static_cast<uint8_t *>(IOMallocData(2*PacketBytes));
    qrtrStorage=static_cast<uint8_t *>(IOMallocData(PacketBytes));
    PongModemControlOps ops{kick,state,{nullptr,server,receive,link},ipaClockQuery};
    if(!intentStorage||!qrtrStorage||!pong_modem_control_init(&control,{&d[1],&d[0],tx,txBytes},
       {&d[3],&d[2],nullptr,0},out,nullptr,1,intentStorage,2*PacketBytes,qrtrStorage,PacketBytes,&ops,nullptr)) {
        metadata.close();sheng_fw_close(file);fail(4,ENOMEM);return false;
    }
    controlInitialized=true;
    atStorage=static_cast<uint8_t *>(IOMallocData(2*0x4000));
    if(!atStorage||!pong_modem_control_attach_at(&control,atStorage,2*0x4000))
        IOLog("PongModem: DS AT channel allocation unavailable; actual QRTR owner retained\n");
    ssmStorage=static_cast<uint8_t *>(IOMallocData(512));
    if(!ssmStorage||!pong_modem_control_attach_ssm(&control,ssmStorage,512))
        IOLog("PongModem: SSM transport allocation unavailable; no mode response inferred\n");
    rc=pong_modem_qrtr_register(&control.qrtr,QCOM_SERVLOC_SERVICE,QCOM_SERVLOC_INSTANCE,LocatorPort);
    if(!rc)rc=pong_modem_qrtr_register(&control.qrtr,0x34,0x101,MemsharePort);
    if(!rc)rc=pong_modem_qrtr_register(&control.qrtr,14,1,RmtfsPort);
    if(!rc&&!modemDiag.registerServices())
        IOLog("PongModem: optional DIAG host registration unavailable; modem startup retained\n");
    if(!rc&&!modemFiles.start())
        IOLog("PongModem: actual RFS file service registration unavailable; no file access fabricated\n");
    if(!rc&&!imsDcm.start())IOLog("PongModem: IMS DCM control endpoint unavailable; no PDP success invented\n");
    if(rc){metadata.close();sheng_fw_close(file);fail(4,rc);return false;}
    stage(4);
    if(image.relocatable&&!ok(scm(QCOM_SCM_PAS_MEM_SETUP,qcom_scm_args(3,0,0,0),4,ModemBase,qcom_mdt_span(&image)))) {
        metadata.close();sheng_fw_close(file);fail(5,EIO);return false;
    }
    rc=load(file);sheng_fw_close(file);
    if(rc){metadata.close();fail(5,rc);return false;}
    native_modem_stats[5]=int32_t(loadedBytes>>10);stage(5);
    __atomic_store_n(&pending,0,__ATOMIC_RELEASE);
    __atomic_store_n(&pasStarted,ok(scm(QCOM_SCM_PAS_AUTH_AND_RESET,qcom_scm_args(1,0,0,0),4)),__ATOMIC_RELEASE);
    metadata.close();if(!pasStarted){fail(6,EIO);return false;}
    stage(6);
    bool freshEdge=false;const uint64_t deadline=nowMs()+10000;
    while(nowMs()<deadline) {
        uint32_t events=waitEvents(10);freshEdge|=bool(events&PongModemSmp2pEvent);
        refreshRemote();
        if(control.smp2p.in) {
            if(pong_modem_control_poll(&control)<0||control.slave_state&Fatal)break;
            locatorPoll();sysmonPoll();
            if(freshEdge&&(control.slave_state&Ready)){stage(7);return true;}
        }
    }
    crashReason();fail(7,ETIMEDOUT);return false;
}
void modemThread(void *,wait_result_t) {
    thread_set_thread_name(current_thread(),"pong_mpss");
    if(!start()) {
        if(controlInitialized)pong_modem_control_reset(&control);
        if(pasStarted)(void)scm(QCOM_SCM_PAS_SHUTDOWN,qcom_scm_args(1,0,0,0),4);
        return;
    }
    const bool nativeClasses=pong_baseband_service_classes_ready();
    if(!nativeClasses)IOLog("PongModem: optional native QMUX class registration failed; actual QRTR owner retained\n");
    uint64_t reportAt=nowMs()+10000;
    for(;;) {
        // IPCC wakes this owner immediately. A bounded1ms safety poll also
        // drains transport credit/GLINK intent work that has no new edge;
        // the former20ms timeout added delay to every such QMI round-trip.
        (void)waitEvents(1);refreshRemote();
        int result=pong_modem_control_poll(&control);locatorPoll();sysmonPoll();modemStatusPoll();modemIms.poll();imsDcm.poll();modemSimPoll();modemPdc.poll();modemDiag.poll();modemFiles.poll();modemDataPoll();ipaDmaPoll();wan.poll();
        if(nativeClasses&&control.qrtr.hello_received&&control.qrtr.server_count) {
            (void)pong_baseband_transport_start(&control.qrtr);
            pong_baseband_transport_poll();
        } else pong_baseband_transport_offline();
        native_modem_stats[6]=int32_t(control.qrtr.server_count);native_modem_stats[7]=int32_t(control.qrtr.rx);
        native_modem_stats[8]=int32_t(control.qrtr.tx);native_modem_stats[9]=int32_t(control.qrtr.invalid);
        if(result<0||control.failed){crashReason();wan.snapshotFault();fail(8,result);break;}
        if(control.qrtr.server_count&&native_modem_stats[0]<8)stage(8);
        if(nowMs()>=reportAt) {
            IOLog("PongModem: transport services=%u rx=%u tx=%u errors=%u slave=%x; rmtfs/IPA5.1/ABM pending\n",
                control.qrtr.server_count,control.qrtr.rx,control.qrtr.tx,control.errors,control.slave_state);
            reportAt=nowMs()+60000;
        }
    }
    pong_baseband_transport_offline();
    (void)scm(QCOM_SCM_PAS_SHUTDOWN,qcom_scm_args(1,0,0,0),4);
    __atomic_store_n(&pasStarted,false,__ATOMIC_RELEASE);
}
}
extern "C" bool pong_modem_is_powered(void){return __atomic_load_n(&pasStarted,__ATOMIC_ACQUIRE);}
extern "C" bool pong_modem_is_ready(void){
    const uint32_t state=__atomic_load_n(&native_modem_stats[4],__ATOMIC_ACQUIRE);
    return pong_modem_is_powered()&&(state&Ready)&&!(state&Fatal);
}
extern "C" bool pong_modem_request_online(void) {
    if(!pong_modem_is_ready())return false;
    __atomic_store_n(&modemOnlineQueued,1u,__ATOMIC_RELEASE);
    // Polling is bounded on the real owner thread; the USB worker never
    // sends QRTR or changes hardware/firmware itself.
    return true;
}
extern "C" void pong_modem_request_data_port(void){__atomic_store_n(&modemDataRequested,1u,__ATOMIC_RELEASE);}
extern "C" int pong_modem_data_port_status(void){return __atomic_load_n(&modemDataState,__ATOMIC_ACQUIRE);}
extern "C" void pong_modem_start_optional(void) {
    unsigned enabled=0;if(!PE_parse_boot_argn("pong_modem",&enabled,sizeof enabled)||enabled!=1)return;
    static uint32_t started;if(__atomic_exchange_n(&started,1,__ATOMIC_ACQ_REL))return;
    thread_t worker=nullptr;
    if(kernel_thread_start(modemThread,nullptr,&worker)!=KERN_SUCCESS){fail(1,ENOMEM);return;}
    thread_deallocate(worker);
}
extern "C" void pong_modem_report(void) {
    pong_baseband_transport_report();
    pong_modem_qrtr_report_registration(&control.qrtr);
    modemPdc.report();
    modemDiag.report();
    modemFiles.report();
    IOLog("PongModem snapshot: stage=%d error=%d SCMcmd=%d x0=%d x1=%d slave=%x loadedKiB=%d services=%d rx=%d tx=%d invalid=%d; rmtfs/IPA5.1/ABM pending\n",
        native_modem_stats[0],native_modem_stats[1],native_modem_stats[10],native_modem_stats[2],native_modem_stats[3],
        unsigned(native_modem_stats[4]),native_modem_stats[5],native_modem_stats[6],native_modem_stats[7],native_modem_stats[8],native_modem_stats[9]);
    IOLog("PongModem snapshot: DS_up=%u AT_sent=%u packets=%u bytes=%u GLINK_unknown=%u last=%s\n",
        control.at_up?1:0,control.at_ping_sent?1:0,control.at_packets,control.at_bytes,
        control.glink.unknown_opens,control.glink.last_unknown);
    IOLog("PongModem snapshot: actual GLINK unclaimed channels=%s QRTR_unrouted=%u missing_host_lookups=%u\n",control.glink.unknown_names,control.qrtr.unrouted,control.qrtr.missing_lookup_total);
    for(unsigned i=0;i<control.qrtr.missing_lookup_count;i++)
        IOLog("PongModem missing host endpoint: service=%u instance=%x\n",control.qrtr.missing_lookups[i].service,control.qrtr.missing_lookups[i].instance);
    IOLog("PongModem snapshot: actual IPCC client2 GIC261 GLINK_signal0=%u SMP2P_signal2=%u subscriptions=%u/%u; owned callback wakeups\n",
        __atomic_load_n(&doorbell.glink_events,__ATOMIC_RELAXED),__atomic_load_n(&doorbell.smp2p_events,__ATOMIC_RELAXED),doorbell.glink_registered,doorbell.smp2p_registered);
    IOLog("PongModem snapshot: SysMon_adsp=%u modem=%u actual_acks=%u errors=%u\n",
        adspSysmon.present?1:0,modemSysmon.present?1:0,sysmonAcks,sysmonErrors);
    IOLog("PongModem snapshot: SSM_up=%u packets=%u invalid=%u command=%u error=%u IPA_in=%x response=%u clock=%u\n",
        control.ssm_up,control.ssm_packets,control.ssm_invalid,control.ssm_last_command,control.ssm_last_error,
        control.ipa_state,control.ipa_clock_replied,ipaClock.held);
    IOLog("PongModem snapshot: IPA_PAS15=%u error=%d GSI3_status=%x\n",ipaClock.firmware,ipaClock.firmware_error,ipaClock.gsi_status);
    IOLog("PongModem snapshot: IPA AP-DMA stage=%u error=%d bank=%u command_channel12_state=%u completions=%u event_code=%u pending=%u; packet path separately qualified\n",ipaDma.stage,ipaDma.error,ipaDma.bank,ipaDma.channelState,ipaDma.completedCommands,ipaDma.lastEvent,ipaDma.pending);
    IOLog("PongModem snapshot: WAN rings=%u QMI_registered=%u driver=%u uC=%u subscribed=%u indicated=%u ready=%u error=%u tx=%llu rx=%llu dropped=%llu\n",
        wan.setup,wan.registered,wan.driverReady,wan.ucReady,wan.subscribed,wan.indicated,wan.ready(),wan.error,wan.txPackets,wan.rxPackets,wan.dropped);
    wan.snapshot();
    modemRules.snapshot();
    if(ipaDma.error)IOLog("PongModem snapshot: actual IPA failure RP=%x WP=%x fetchRP=%x fetchWP=%x QOS=%x ERR=%x GLOBAL=%x EVENT=%x FSR=%x FAR=%x\n",
        ipaDma.failureRegs[0],ipaDma.failureRegs[1],ipaDma.failureRegs[2],ipaDma.failureRegs[3],ipaDma.failureRegs[4],
        ipaDma.failureRegs[5],ipaDma.failureRegs[6],ipaDma.failureRegs[7],ipaDma.failureRegs[8],ipaDma.failureRegs[9]);
    if(ipaDma.error)IOLog("PongModem snapshot: actual IPA command endpoint CFG1=%x TLV=%x AOS=%x IRQ_TYPE=%x CTRL=%x EOB=%x; secure global configuration not overwritten\n",
        ipaDma.failureRegs[10],ipaDma.failureRegs[11],ipaDma.failureRegs[12],ipaDma.failureRegs[13],ipaDma.failureRegs[14],ipaDma.failureRegs[15]);
    IOLog("PongModem snapshot: QMI_status replies=%u errors=%u revision_present=%u NAS=%u CS=%u PS=%u cards=%u first_card_state=%u; iOS bridge/data pending\n",
        modemStatusReplies,modemStatusErrors,modemRevisionBytes!=0,modemRegistration,modemCsAttach,modemPsAttach,modemCards,modemFirstCard);
    IOLog("PongModem snapshot: actual operating_mode=%u first_card_error=%u; no online/SIM state inferred\n",modemOperatingMode,modemFirstCardError);
    IOLog("PongModem snapshot: physical initialization state=%u failure=%u; RF initialization gate retained\n",modemInitializationState,modemInitializationFailure);
    IOLog("PongModem snapshot: data_port requested=%u step=%u DPM_error=%u WDA_error=%u link=%u ul=%u dl=%u status=%d; GSI/PDP pending\n",
        modemData.requested,modemData.step,modemData.dpmError,modemData.wdaError,modemData.llp,modemData.ul,modemData.dl,pong_modem_data_port_status());
    for(const auto &query:modemStatusRequests)if(query.last_failure)
        IOLog("PongModem snapshot: service=%u request=%x failure_kind=%u error=%u attempts=%u\n",
            query.service,query.message,query.last_failure,query.last_error,query.attempts);
    modemIms.report();
    imsDcm.report();
}
