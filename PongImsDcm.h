/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * AP-owned IMS Data Connection Manager control endpoint. Wire reference:
 * Biktorgj/openimsd DCM protocol notes (service0x302), libqmi QRTR/QMI.
 * Original bounded implementation: no copied GLib/Linux service code.
 * Registration here registers a local software client; it never means
 * carrier IMS/SIP registration. PDP success requires a real IMS context.
 */
constexpr uint32_t ImsDcmPort=0x152;
struct PongImsDcm {
 struct Reply {uint32_t node=0,port=0,bytes=0;uint8_t data[128];} replies[8]{};
 struct Subscriber {bool used=false;uint32_t node=0,port=0;} subscribers[8]{};
 unsigned head=0,count=0,requests=0,answered=0,rejected=0,activated=0,lastMessage=0,lastError=0;
 bool published=false;
 PongQrtrServer wds{};bool haveWds=false,starting=false,wirePending=false,notifying=false;
 uint32_t peerNode=0,peerPort=0,pdpSequence=0,pdpInstance=0,handle=0;
 uint16_t originalTransaction=0,transaction=0,nextTransaction=0,wireMessage=0,profile=0xffff;
 unsigned step=0,attempts=0,family=4;uint64_t deadline=0,readyDeadline=0;
 char apn[101]{};uint8_t assigned[16]{};unsigned assignedBytes=0;
 void server(const PongQrtrServer *s,bool added) {
  if(s->service!=1)return;
  if(added&&(!haveWds||(s->instance>>8)<(wds.instance>>8))){wds=*s;haveWds=true;}
  else if(!added&&haveWds&&wds.node==s->node&&wds.port==s->port){haveWds=false;starting=wirePending=notifying=false;handle=assignedBytes=0;}
 }
 bool queueReply(uint32_t node,uint32_t port,uint16_t txn,unsigned message,unsigned error,bool indication=false) {
  if(count==8)return false;
  auto &reply=replies[(head+count)%8];reply={};reply.node=node;reply.port=port;
  reply.data[0]=indication?4:2;cbd_wr16(reply.data+1,txn);cbd_wr16(reply.data+3,message);
  const uint8_t result[]={uint8_t(error?1:0),0,uint8_t(error),uint8_t(error>>8)};
  unsigned n=7;n+=cbd_tlv(reply.data+n,sizeof reply.data-n,2,result,sizeof result);
  if(message==0x20&&!error) {
   const uint8_t id=1;uint8_t number[4];
   n+=cbd_tlv(reply.data+n,sizeof reply.data-n,indication?1:0x10,&id,1);
   cbd_wr32(number,pdpSequence);n+=cbd_tlv(reply.data+n,sizeof reply.data-n,0x11-(indication?1:0),number,4);
   cbd_wr32(number,pdpInstance);n+=cbd_tlv(reply.data+n,sizeof reply.data-n,0x12,number,4);
   if(indication) {
    uint8_t address[64]={};cbd_wr32(address,family==6?1:0);char text[48]={};unsigned length=0;
    if(family==4&&assignedBytes==4) {
     length=snprintf(text,sizeof text,"%u.%u.%u.%u",assigned[3],assigned[2],assigned[1],assigned[0]);
    }else if(family==6&&assignedBytes==16) {
     length=snprintf(text,sizeof text,"%x:%x:%x:%x:%x:%x:%x:%x",(assigned[0]<<8)|assigned[1],(assigned[2]<<8)|assigned[3],
      (assigned[4]<<8)|assigned[5],(assigned[6]<<8)|assigned[7],(assigned[8]<<8)|assigned[9],(assigned[10]<<8)|assigned[11],(assigned[12]<<8)|assigned[13],(assigned[14]<<8)|assigned[15]);
    }
    if(!length||length>=sizeof text)return false;
    address[4]=length;memcpy(address+5,text,length);n+=cbd_tlv(reply.data+n,sizeof reply.data-n,0x11,address,5+length);
   }
  }
  reply.bytes=n;cbd_wr16(reply.data+5,n-7);++count;return true;
 }
 void finish(unsigned error) {
  lastError=error;if(error)++rejected;
  if(queueReply(peerNode,peerPort,originalTransaction,0x20,error)) {
   starting=wirePending=false;
   if(!error){++activated;notifying=true;}
  }
 }
 bool wdsReceive(uint32_t node,uint32_t port,const uint8_t *sdu,unsigned bytes) {
  if(!haveWds||node!=wds.node||port!=wds.port||!cbd_sdu_ok(sdu,bytes))return true;
  if(!starting||!wirePending||sdu[0]!=2||cbd_rd16(sdu+1)!=transaction||cbd_rd16(sdu+3)!=wireMessage)return true;
  wirePending=false;const unsigned error=cbd_error(sdu,bytes);
  if(error){finish(error);return true;}
  if(wireMessage==0x20) {handle=cbd_u32(sdu,bytes,1);if(!handle||handle==~0u){finish(52);return true;}}
  if(wireMessage==0x2d) {
   unsigned length=0;const uint8_t *ip=cbd_find(sdu,bytes,family==4?0x1e:0x25,&length);
   if(!ip||length!=(family==4?4u:17u)){finish(52);return true;}
   unsigned nonzero=0;for(unsigned i=0;i<(family==4?4u:16u);i++)nonzero|=ip[i];
   if(!nonzero){finish(52);return true;}
   memcpy(assigned,ip,family==4?4:16);assignedBytes=family==4?4:16;finish(0);return true;
  }
  ++step;attempts=0;return true;
 }
 void sessionPoll() {
  if(notifying&&queueReply(peerNode,peerPort,0,0x20,0,true))notifying=false;
  if(!starting)return;
  if(!modemSim.ready||modemOperatingMode!=0||modemPsAttach!=1) {
   // The modem may request its IMS bearer before UIM application
   // selection/PS attachment finishes. Retain this real request rather
   // than permanently rejecting startup with SIM-not-initialized.
   if(nowMs()>=readyDeadline)finish(37);return;
  }
  if(!haveWds||!wan.ready()){if(nowMs()>=deadline)finish(52);return;}
  if(wirePending){if(nowMs()<deadline)return;wirePending=false;if(attempts>=2){finish(ETIMEDOUT);return;}}
  uint8_t sdu[192]={},v[8]={};unsigned n=7,message=0;
  if(step==0){message=0xaf;cbd_wr32(v,1);n+=cbd_tlv(sdu+n,sizeof sdu-n,1,v,4);} // WDS primary enum1
  else if(step==1){message=0x4d;v[0]=family;n+=cbd_tlv(sdu+n,sizeof sdu-n,1,v,1);}
  else if(step==2){message=0xa2;cbd_wr32(v,4);cbd_wr32(v+4,1);n+=cbd_tlv(sdu+n,sizeof sdu-n,0x10,v,8);v[0]=5;n+=cbd_tlv(sdu+n,sizeof sdu-n,0x11,v,1);}
  else if(step==3){message=0x20;n+=cbd_tlv(sdu+n,sizeof sdu-n,0x14,reinterpret_cast<const uint8_t *>(apn),unsigned(strlen(apn)));v[0]=family;n+=cbd_tlv(sdu+n,sizeof sdu-n,0x19,v,1);if(profile<=255){v[0]=profile;n+=cbd_tlv(sdu+n,sizeof sdu-n,0x31,v,1);}}
  else if(step==4){message=0x2d;cbd_wr32(v,0x2330);n+=cbd_tlv(sdu+n,sizeof sdu-n,0x10,v,4);}
  else {finish(52);return;}
  uint16_t txn=nextTransaction+1;if(!txn)txn=1;cbd_wr16(sdu+1,txn);cbd_wr16(sdu+3,message);cbd_wr16(sdu+5,n-7);
  if(!pong_modem_qrtr_send(&control.qrtr,ImsDcmPort+1,wds.node,wds.port,sdu,n)) {
   nextTransaction=transaction=txn;wireMessage=message;wirePending=true;++attempts;deadline=nowMs()+(message==0x20?60000:5000);
  }
 }
 bool start() {
  // Actual QRTR namespace: version1, instance1. This software endpoint
  // owns a bounded receive queue and replies through the real transport.
  published=!pong_modem_qrtr_register(&control.qrtr,0x302,0x101,ImsDcmPort);return published;
 }
 void offline() {
  head=count=0;starting=wirePending=notifying=false;handle=assignedBytes=0;for(auto &subscriber:subscribers)subscriber={};
 }
 bool receive(uint32_t local,uint32_t node,uint32_t port,const uint8_t *sdu,unsigned bytes) {
  if(local==ImsDcmPort+1)return wdsReceive(node,port,sdu,bytes);
  if(local!=ImsDcmPort)return false;
  if(!published||!cbd_sdu_ok(sdu,bytes)||sdu[0]!=0||bytes>512)return true;
  if(count==8){++rejected;return true;} // bounded receive overflow; never ACK unretained work
  unsigned error=94;const unsigned message=cbd_rd16(sdu+3);++requests;lastMessage=message;
  if(message==0x2e) {
   Subscriber *entry=nullptr;
   for(auto &subscriber:subscribers)if(subscriber.used&&subscriber.node==node&&subscriber.port==port){entry=&subscriber;break;}
   if(!entry)for(auto &subscriber:subscribers)if(!subscriber.used){entry=&subscriber;break;}
   if(entry){*entry={true,node,port};error=0;}else error=5;
  }else if(message==0x34) {
   // Report only whether this actual local software control service is
   // functioning. No radio/SIM/IP status is manufactured by this ACK.
   error=0;
  }else if(message==0x20) {
   unsigned length=0;const uint8_t *slot=cbd_find(sdu,bytes,0x12,&length);
   if(!slot||length!=4||cbd_rd32(slot)!=1)error=48;
   else {
    const uint8_t *apn=cbd_find(sdu,bytes,1,&length);
    if(!apn||length<17||apn[0]>100||length!=unsigned(apn[0])+17u)error=48;
    else if(starting&&peerNode==node&&peerPort==port&&originalTransaction==cbd_rd16(sdu+1))return true; // real pending retransmission
    else if(starting||handle)error=5; // existing owner, no duplicate dial
    else {
     const unsigned nameBytes=apn[0];
     bool valid=nameBytes>0;
     for(unsigned i=0;i<nameBytes;i++){const auto c=apn[1+i];valid&=(c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-';}
     if(!valid)error=48;
     else {
      unsigned bytes1=0,bytes2=0;const auto *sequence=cbd_find(sdu,bytes,0x10,&bytes1),*instance=cbd_find(sdu,bytes,0x13,&bytes2);
      if(!sequence||bytes1!=4||!instance||bytes2!=4)error=48;
      else {
       memcpy(this->apn,apn+1,nameBytes);this->apn[nameBytes]=0;
       const unsigned wireFamily=cbd_rd32(apn+1+nameBytes+8);
       if(wireFamily>1)error=48;
       else {
        family=wireFamily?6:4;profile=cbd_rd16(apn+1+nameBytes+12);
        peerNode=node;peerPort=port;originalTransaction=cbd_rd16(sdu+1);pdpSequence=cbd_rd32(sequence);pdpInstance=cbd_rd32(instance);
        starting=true;wirePending=false;step=attempts=0;readyDeadline=nowMs()+90000;deadline=readyDeadline;
        return true; // reply only after actual WDS activation and address
       }
      }
     }
    }
   }
   // Do not ACK activation or notify an IP address from the ordinary
   // Internet context. Those would falsely claim an IMS bearer.
  }else if(message==0x33) {
   // There is no active locally-owned IMS PDP to clear. Keep a real
   // no-effect error instead of claiming someone else's link was stopped.
   error=26;
  }
  auto &reply=replies[(head+count)%8];reply={};reply.node=node;reply.port=port;
  reply.data[0]=2;cbd_wr16(reply.data+1,cbd_rd16(sdu+1));cbd_wr16(reply.data+3,message);
  const uint8_t result[]={uint8_t(error?1:0),0,uint8_t(error),uint8_t(error>>8)};
  reply.bytes=7+cbd_tlv(reply.data+7,sizeof reply.data-7,2,result,sizeof result);cbd_wr16(reply.data+5,reply.bytes-7);
  ++count;lastError=error;if(error)++rejected;return true;
 }
 void poll() {
  sessionPoll();
  if(!count)return;auto &reply=replies[head];
  if(pong_modem_qrtr_send(&control.qrtr,ImsDcmPort,reply.node,reply.port,reply.data,reply.bytes))return;
  reply={};head=(head+1)%8;--count;++answered;
 }
 void report()const {
  unsigned clients=0;for(const auto &subscriber:subscribers)clients+=subscriber.used;
  IOLog("Pong IMS DCM: published=%u clients=%u requests=%u replies=%u rejected=%u queued=%u last_message=%x last_error=%u real_IMS_PDPs=%u\n",
   published,clients,requests,answered,rejected,count,lastMessage,lastError,activated);
 }
} imsDcm;
