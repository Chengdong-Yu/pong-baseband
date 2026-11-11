/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* QRTR v1 board transport, following UniXNU-sheng/package/QcomQrtr.
 * No SC7180 registers, fixed DMA, hardware identities or synthetic replies.
 * All methods run on the same actual GLINK owner thread. transmit queues a
 * copy before returning and must not recursively invoke receive.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

enum {PongQrtrHeader=32,PongQrtrMaxPayload=65536,PongQrtrMaxServers=128};
struct PongQrtrServer {uint32_t service,instance,node,port;};
struct PongQrtrTrace {
    uint32_t sequence,millis,local,node,port,result,operation;
    uint16_t message,transaction,bytes;
    uint8_t stage,type;
};
struct PongModemQrtrOps {
    int (*transmit)(void *,const void *,uint32_t);
    void (*server)(void *,const PongQrtrServer *,bool added);
    bool (*receive)(void *,uint32_t local_port,uint32_t source_node,uint32_t source_port,const void *,uint32_t);
    void (*link)(void *,bool up);
};
struct PongModemQrtr {
    PongModemQrtrOps ops;
    void *context;
    uint8_t *workspace;
    uint32_t capacity,local_node,remote_node;
    bool hello_sent,hello_received,lookup_sent;
    PongQrtrServer servers[PongQrtrMaxServers];
    struct {uint32_t node,port,destination,destination_port;} pending_resume[64];
    uint32_t resume_count;
    struct {uint32_t node,port,pending;bool used;uint32_t epoch;} tx_flow[128];
    struct {bool used;uint16_t transaction,message;uint32_t from,node,port,flow,epoch;} qmi_receipts[256];
    uint32_t flow_confirmed,flow_resumed,flow_blocked,flow_response_consumed;
    PongQrtrTrace registration_trace[64];uint32_t registration_sequence;
    struct {uint32_t service,instance;} missing_lookups[16];
    uint32_t missing_lookup_count,missing_lookup_total;
    PongQrtrServer local_servers[8];
    uint32_t local_count,local_dirty;
    uint32_t server_count,rx,tx,invalid,unrouted,tx_refused,resumes;
};
bool pong_modem_qrtr_init(PongModemQrtr *,uint32_t local_node,void *workspace,uint32_t bytes,const PongModemQrtrOps *,void *context);
int pong_modem_qrtr_start(PongModemQrtr *);
int pong_modem_qrtr_register(PongModemQrtr *,uint32_t service,uint32_t instance,uint32_t port);
int pong_modem_qrtr_receive(PongModemQrtr *,const void *,uint32_t bytes);
int pong_modem_qrtr_send(PongModemQrtr *,uint32_t local_port,uint32_t node,uint32_t port,const void *,uint32_t bytes);
int pong_modem_qrtr_delete_client(PongModemQrtr *,uint32_t local_port);
int pong_modem_qrtr_poll(PongModemQrtr *);
void pong_modem_qrtr_disconnect(PongModemQrtr *);
void pong_modem_qrtr_report_registration(const PongModemQrtr *);
