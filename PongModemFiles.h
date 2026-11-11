/* SPDX-License-Identifier: BSD-3-Clause
 * Qualcomm TFTP-over-QRTR file service. Wire protocol follows
 * linux-msm/tqftpserv (Copyright2018 Linaro Ltd.), RFC1350/2347/2348/7440.
 * This owner-thread implementation uses actual native VFS files, bounded
 * sessions and one-block windows. It never exposes arbitrary host paths,
 * invents file data, or writes factory modem NV. Native Data backs writes.
 */
extern "C" {
int pong_rfs_open(const char *,bool,void **,uint64_t *);
int pong_rfs_read(void *,uint64_t,void *,uint32_t,uint32_t *);
int pong_rfs_write(void *,uint64_t,const void *,uint32_t,bool);
void pong_rfs_close(void *,bool);
bool pong_rfs_ready(void);
}
constexpr uint32_t ModemFilesPort=0x160,ModemFilesTransferPort=0x180;
struct ModemFiles {
    // Pong's16KiB GLINK FIFO accepts at most8KiB including its header,
    // QRTR and TFTP headers. An8KiB data block exceeds that real bound.
    static constexpr unsigned Sessions=8,BlockMax=4096,PacketMax=BlockMax+4;
    struct Transfer {
        bool used=false,write=false,pending=false,retiring=false,closeAfterSend=false;
        bool oack=false,terminal=false,done=false;
        uint32_t node=0,port=0,sequence=0,blockSize=512,timeout=1000,attempts=0;
        uint64_t offset=0,remaining=0,deadline=0,expires=0;
        void *file=nullptr;unsigned packetBytes=0,dataBytes=0;
        char name[160]{};uint8_t packet[PacketMax]{};
    } transfers[Sessions]{};
    struct Incoming {uint32_t local=0,node=0,port=0,bytes=0;uint8_t data[PacketMax];} inbox[16];
    unsigned head=0,count=0;bool registered=false,storageReady=false;uint64_t checkStorageAt=0;
    uint32_t reads=0,writes=0,completedReads=0,completedWrites=0,failures=0,dropped=0,lastError=0;
    uint32_t lastPhase=0,lastRequestBytes=0,lastOptions=0,lastPath=0;
    uint64_t readBytes=0,writeBytes=0;
    static uint16_t be16(const uint8_t *p){return unsigned(p[0])<<8|p[1];}
    static void put16(uint8_t *p,uint16_t v){p[0]=v>>8;p[1]=v;}
    bool start() {
        if(registered)return true;
        registered=!pong_modem_qrtr_register(&control.qrtr,4096,1,ModemFilesPort);
        return registered;
    }
    void closeFile(Transfer &t){if(t.file)pong_rfs_close(t.file,t.write);t.file=nullptr;}
    void offline() {
        for(auto &t:transfers){closeFile(t);bzero(&t,sizeof t);}head=count=0;
    }
    void queue(Transfer &t,unsigned bytes) {
        t.packetBytes=bytes;t.pending=true;t.deadline=0;t.attempts=0;
    }
    void error(Transfer &t,unsigned code,int cause) {
        closeFile(t);lastError=cause;++failures;
        static const char unavailable[]="File unavailable";
        put16(t.packet,5);put16(t.packet+2,code);
        memcpy(t.packet+4,unavailable,sizeof unavailable);t.closeAfterSend=true;
        queue(t,4+sizeof unavailable);
    }
    static bool string(const uint8_t *p,unsigned bytes,unsigned &at,char *out,unsigned cap) {
        unsigned used=0;
        while(at<bytes&&p[at]) {
            if(used+1>=cap||p[at]<32||p[at]>126)return false;
            out[used++]=p[at++];
        }
        if(at>=bytes)return false;++at;out[used]=0;return used!=0;
    }
    static bool number(const char *p,uint64_t &value) {
        if(!*p)return false;value=0;
        for(;*p;p++) {
            if(*p<'0'||*p>'9'||value>(UINT64_MAX-unsigned(*p-'0'))/10)return false;
            value=value*10+unsigned(*p-'0');
        }
        return true;
    }
    bool path(const char *input,char *out) {
        static const char *const prefixes[]={"/readonly/firmware/image/","/readonly/vendor/firmware_mnt/image/",
            "/readonly/vendor/firmware/","/readonly/firmware/"};
        if(!strncmp(input,"/readwrite/",11)) {
            return snprintf(out,160,"readwrite/%s",input+11)<160;
        }
        if(!strncmp(input,"readwrite/",10))return snprintf(out,160,"%s",input)<160;
        for(const char *prefix:prefixes) {
            const unsigned bytes=unsigned(strlen(prefix));
            if(!strncmp(input,prefix,bytes))return snprintf(out,160,"firmware/%s",input+bytes)<160;
            if(!strncmp(input,prefix+1,bytes-1))return snprintf(out,160,"firmware/%s",input+bytes-1)<160;
        }
        return false;
    }
    bool option(Transfer &t,unsigned &bytes,const char *key,uint64_t value) {
        const unsigned n=unsigned(strlen(key))+1;
        if(bytes+n+24>PacketMax)return false;
        memcpy(t.packet+bytes,key,n);bytes+=n;
        const int count=snprintf(reinterpret_cast<char *>(t.packet+bytes),24,"%llu",value);
        if(count<=0||count>=24)return false;bytes+=unsigned(count)+1;return true;
    }
    void data(Transfer &t) {
        const uint32_t wanted=uint32_t(t.remaining<t.blockSize?t.remaining:t.blockSize);
        uint32_t actual=0;const int result=wanted?pong_rfs_read(t.file,t.offset,t.packet+4,wanted,&actual):0;
        if(result||actual!=wanted){error(t,0,result?result:EIO);return;}
        put16(t.packet,3);put16(t.packet+2,uint16_t(t.sequence));
        t.dataBytes=actual;t.terminal=actual<t.blockSize;
        queue(t,actual+4);
    }
    void request(const Incoming &in) {
        // A duplicate initial request resends the same actual response;
        // it must not create a second file owner or truncate existing data.
        for(auto &t:transfers)if(t.used&&!t.retiring&&t.node==in.node&&t.port==in.port) {
            // A client may reuse its socket for the next file after the
            // final write ACK. Keep final-DATA duplicate handling on the
            // old transfer port, but do not answer a new RRQ/WRQ with it.
            if(t.done){t.retiring=true;continue;}
            if(t.packetBytes)t.pending=true;return;
        }
        Transfer *selected=nullptr;
        for(auto &t:transfers)if(!t.used){selected=&t;break;}
        if(!selected){++dropped;return;}
        auto &t=*selected;bzero(&t,sizeof t);t.blockSize=512;t.timeout=1000;
        t.used=true;t.node=in.node;t.port=in.port;t.expires=nowMs()+30000;
        lastPhase=1;lastRequestBytes=in.bytes;lastOptions=lastPath=0;
        t.write=be16(in.data)==2;
        unsigned at=2;char filename[160],mode[16];
        if(!string(in.data,in.bytes,at,filename,sizeof filename)||
           !string(in.data,in.bytes,at,mode,sizeof mode)||!path(filename,t.name)) {
            error(t,2,EINVAL);return;
        }
        for(char *p=mode;*p;p++)if(*p>='A'&&*p<='Z')*p+=32;
        lastPath=!strncmp(t.name,"readwrite/",10)?2:1;lastPhase=2;
        if(strcmp(mode,"octet")){error(t,4,EINVAL);return;}
        uint32_t options=0;uint64_t seek=0,readSize=0,declared=0;
        while(at<in.bytes) {
            // Legacy Qualcomm requests can carry zero-filled tail bytes.
            // They contain no further option; do not reject every file
            // before opening it merely because the tail is padded.
            if(!in.data[at]) {
                bool zero=true;for(unsigned i=at;i<in.bytes;i++)zero&=in.data[i]==0;
                if(zero)break;
            }
            lastPhase=3;
            char key[24],value[24];uint64_t n=0;
            if(!string(in.data,in.bytes,at,key,sizeof key)||!string(in.data,in.bytes,at,value,sizeof value)) {
                error(t,8,EINVAL);return;
            }
            for(char *p=key;*p;p++)if(*p>='A'&&*p<='Z')*p+=32;
            const bool known=!strcmp(key,"blksize")||!strcmp(key,"timeoutms")||!strcmp(key,"timeout")||
                !strcmp(key,"tsize")||!strcmp(key,"wsize")||!strcmp(key,"windowsize")||!strcmp(key,"rsize")||!strcmp(key,"seek");
            if(!known)continue;
            // Older Qualcomm TFTP uses -1/all-ones for an unspecified
            // seek and tsize; zero rsize means the complete actual file.
            if((!strcmp(key,"seek")||!strcmp(key,"tsize"))&&!strcmp(value,"-1"))continue;
            if(!number(value,n)){error(t,8,EINVAL);return;}
            unsigned bit=0;
            if(!strcmp(key,"blksize")) {
                bit=1;if(n<8||n>65464){error(t,8,EINVAL);return;}t.blockSize=n>BlockMax?BlockMax:uint32_t(n);
            } else if(!strcmp(key,"timeoutms")) {
                bit=2;if(!n||n>255000){error(t,8,EINVAL);return;}t.timeout=uint32_t(n);
            } else if(!strcmp(key,"timeout")) {
                bit=64;if(!n||n>255){error(t,8,EINVAL);return;}t.timeout=uint32_t(n*1000);
            } else if(!strcmp(key,"tsize")) {bit=4;declared=n;}
            else if(!strcmp(key,"wsize")||!strcmp(key,"windowsize")) {
                bit=!strcmp(key,"wsize")?8:128;if(!n||n>65535){error(t,8,EINVAL);return;}
            } else if(!strcmp(key,"rsize")) {bit=16;readSize=n;if(n>128ULL*1024*1024){error(t,8,EINVAL);return;}}
            else if(!strcmp(key,"seek")) {
                if(n==UINT32_MAX||n==UINT64_MAX)continue;
                bit=32;seek=n;
            }
            if(options&bit){error(t,8,EINVAL);return;}options|=bit;lastOptions=options;
        }
        lastPhase=4;
        if(t.write&&strncmp(t.name,"readwrite/",10)){error(t,2,EACCES);return;}
        for(const auto &other:transfers)if(&other!=&t&&other.used&&other.file&&!strcmp(other.name,t.name)&&(t.write||other.write)) {
            error(t,0,EBUSY);return;
        }
        uint64_t size=0;const int result=pong_rfs_open(t.name,t.write,&t.file,&size);
        if(result){error(t,result==ENOENT?1:2,result);return;}
        lastPhase=5;
        const uint64_t limit=t.write?8ULL*1024*1024:128ULL*1024*1024;
        if(seek>limit||(!t.write&&seek>size)||(t.write&&(declared>limit-seek))) {
            error(t,0,EINVAL);return;
        }
        t.offset=seek;t.remaining=t.write?0:size-seek;
        if(!t.write&&readSize&&t.remaining>readSize)t.remaining=readSize;
        if(t.write)++writes;else ++reads;
        if(options) {
            unsigned bytes=2;put16(t.packet,6);bool valid=true;
            if(options&1)valid&=option(t,bytes,"blksize",t.blockSize);
            if(options&2)valid&=option(t,bytes,"timeoutms",t.timeout);
            if(options&4)valid&=option(t,bytes,"tsize",t.write?declared:size);
            if(options&8)valid&=option(t,bytes,"wsize",1);
            if(options&16)valid&=option(t,bytes,"rsize",readSize);
            if(options&32)valid&=option(t,bytes,"seek",seek);
            if(options&64)valid&=option(t,bytes,"timeout",t.timeout/1000);
            if(options&128)valid&=option(t,bytes,"windowsize",1);
            if(!valid){error(t,8,EINVAL);return;}
            t.oack=!t.write;t.sequence=t.write?0:1;queue(t,bytes);
        } else if(t.write) {
            put16(t.packet,4);put16(t.packet+2,0);queue(t,4);
        } else {t.sequence=1;data(t);}
    }
    void handle(const Incoming &in) {
        if(in.bytes<2)return;
        const unsigned opcode=be16(in.data);
        if(in.local==ModemFilesPort) {
            if(opcode==1||opcode==2)request(in);else ++dropped;return;
        }
        const unsigned index=in.local-ModemFilesTransferPort;if(index>=Sessions)return;
        auto &t=transfers[index];
        if(!t.used||t.retiring||t.node!=in.node||t.port!=in.port)return;
        t.expires=nowMs()+30000;
        if(opcode==5){closeFile(t);t.retiring=true;++failures;return;}
        if(in.bytes<4)return;
        const uint16_t block=be16(in.data+2);
        if(!t.write&&opcode==4&&in.bytes==4&&!t.pending) {
            if(t.oack) {
                if(block)return;t.oack=false;data(t);
            } else if(block==uint16_t(t.sequence)) {
                readBytes+=t.dataBytes;t.offset+=t.dataBytes;t.remaining-=t.dataBytes;
                if(t.terminal){++completedReads;closeFile(t);t.retiring=true;}
                else {++t.sequence;data(t);}
            }
        } else if(t.write&&opcode==3&&in.bytes<=t.blockSize+4) {
            if(block==uint16_t(t.sequence)){t.pending=true;return;}
            if(t.done)return;
            if(block!=uint16_t(t.sequence+1)||t.pending)return;
            const unsigned length=in.bytes-4;const bool final=length<t.blockSize;
            const int result=pong_rfs_write(t.file,t.offset,in.data+4,length,final);
            if(result){error(t,3,result);return;}
            t.sequence++;t.offset+=length;writeBytes+=length;
            put16(t.packet,4);put16(t.packet+2,block);queue(t,4);
            if(final){closeFile(t);t.done=true;++completedWrites;}
        }
    }
    bool receive(uint32_t local,uint32_t node,uint32_t port,const uint8_t *p,unsigned bytes) {
        if(local!=ModemFilesPort&&(local<ModemFilesTransferPort||local>=ModemFilesTransferPort+Sessions))return false;
        if(node!=control.qrtr.remote_node||bytes>PacketMax||count==16){++dropped;return true;}
        auto &in=inbox[(head+count)%16];in.local=local;in.node=node;in.port=port;in.bytes=bytes;
        memcpy(in.data,p,bytes);++count;return true;
    }
    void poll() {
        if(!registered||!control.qrtr.hello_received)return;
        const uint64_t now=nowMs();
        if(!storageReady&&now>=checkStorageAt){storageReady=pong_rfs_ready();checkStorageAt=now+100;}
        if(count) {
            const auto &in=inbox[head];
            const bool needsData=in.local==ModemFilesPort&&in.bytes>=13&&
                (be16(in.data)==1||be16(in.data)==2)&&!memcmp(in.data+2,"/readwrite/",11);
            if(!needsData||storageReady){handle(in);head=(head+1)%16;--count;}
            else {
                // Native Data preparation may finish after firmware loads.
                // Retain that real request without blocking readonly files.
                auto &tail=inbox[(head+count)%16];
                if(&tail!=&in)memmove(&tail,&in,offsetof(Incoming,data)+in.bytes);
                head=(head+1)%16;
            }
        }
        for(unsigned index=0;index<Sessions;index++) {
            auto &t=transfers[index];if(!t.used)continue;
            if(now>=t.expires){closeFile(t);t.retiring=true;++failures;}
            if(t.retiring) {
                if(!pong_modem_qrtr_delete_client(&control.qrtr,ModemFilesTransferPort+index))bzero(&t,sizeof t);
                continue;
            }
            if(!t.pending&&t.deadline&&now>=t.deadline) {
                if(t.done){t.retiring=true;continue;}
                if(++t.attempts>=5){closeFile(t);t.retiring=true;++failures;continue;}
                t.pending=true;
            }
            if(t.pending&&!pong_modem_qrtr_send(&control.qrtr,ModemFilesTransferPort+index,t.node,t.port,t.packet,t.packetBytes)) {
                t.pending=false;t.deadline=now+t.timeout;
                if(t.closeAfterSend)t.retiring=true;
            }
        }
    }
    void report()const {
        unsigned active=0;for(const auto &t:transfers)active+=t.used;
        IOLog("PongModem RFS: service=%u native_Data=%u active=%u reads=%u writes=%u completed=%u/%u bytes=%llu/%llu errors=%u dropped=%u last_errno=%u phase=%u request_bytes=%u options=%x path_kind=%u; actual native files, no factory NV writes\n",
            registered,storageReady,active,reads,writes,completedReads,completedWrites,readBytes,writeBytes,failures,dropped,lastError,lastPhase,lastRequestBytes,lastOptions,lastPath);
    }
} modemFiles;
