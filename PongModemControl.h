/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Pong MPSS control transport. The board owner supplies actual modem SMEM
 * FIFOs, SMP2P items and doorbells after PAS/power prerequisites are met.
 * No MMIO, allocation, polling thread, online service or hardware success is
 * fabricated here. All operations run on the one GLINK owner thread.
 */
#pragma once
#include "PongModemQrtr.h"
extern "C" {
#include "QcomGlink.h"
#include "QcomSmp2p.h"
}
struct PongModemControlOps {
    void (*kick)(void *,uint32_t signal);
    void (*state)(void *,uint32_t value,uint32_t changed);
    PongModemQrtrOps qrtr;
    bool (*ipa_clock)(void *);
};
struct PongModemControl {
    QcomGlink glink;
    QcomSmp2p smp2p;
    PongModemQrtr qrtr;
    PongModemControlOps ops;
    void *context;
    QcomGlinkChannel *ipcrtr;
    QcomGlinkChannel *at;
    QcomGlinkChannel *ssm;
    uint32_t at_packets,at_bytes;
    bool at_up,at_ping_sent;
    bool ssm_up,ipa_clock_replied,ipa_clock_on;
    uint32_t ssm_packets,ssm_invalid,ssm_last_command,ssm_last_error;
    int stop_entry,ipa_entry;
    uint32_t ipa_state,ipa_changed;
    uint32_t slave_state,slave_changed,errors;
    bool transport_up,failed;
};
/* External intent storage: two buffers of65568bytes; QRTR workspace65568.
 * SMP2P out is the board's SMEM428, in is remote435 and may be absent yet.
 * FIFO indices/data must come from the actual APPS/modem private partition.
 * RX indices are required even before remote RX data is allocated: the
 * GLINK initializer writes APPS' receive-tail word in that real descriptor.
 */
bool pong_modem_control_init(PongModemControl *,QcomGlinkFifo tx,QcomGlinkFifo rx,
    volatile uint32_t *smp_out,volatile uint32_t *smp_in,
    uint32_t qrtr_local_node,void *intents,uint32_t intent_bytes,void *qrtr_workspace,uint32_t qrtr_bytes,
    const PongModemControlOps *,void *context);
/* Late remote allocations are validated before being consumed. */
bool pong_modem_control_remote(PongModemControl *,QcomGlinkFifo rx,volatile uint32_t *smp_in);
/* Actual DT DS/at_mdm0 channel: two16KiB intents, boot-lifetime storage. */
bool pong_modem_control_attach_at(PongModemControl *,void *storage,uint32_t bytes);
// Bounded real SSM transport. Receive actual modem status; no fabricated
// secure-mode response and no SsmApp command without a secure backend.
bool pong_modem_control_attach_ssm(PongModemControl *,void *storage,uint32_t bytes);
int pong_modem_control_poll(PongModemControl *);
int pong_modem_control_request_stop(PongModemControl *,bool stop);
/* Caller invokes before reclaiming oldSMEM after an actual remote reset. */
void pong_modem_control_reset(PongModemControl *);

/* Actual Pong client2 doorbells, owned by the shared GIC261 receiver.
 * Zero-initialize once in boot-lifetime storage. wake runs in IRQ context
 * and must only signal the modem owner thread. Partial subscriptions remain
 * owned by this same object; retry with identical callback/context only.
 * Register before MPSS reset so its first SMP2P-ready edge is not lost.
 */
enum {PongModemGlinkEvent=1,PongModemSmp2pEvent=2};
struct PongModemDoorbell {
    void (*wake)(void *,uint32_t events);
    void *context;
    bool glink_registered,smp2p_registered;
    uint32_t glink_events,smp2p_events;
};
int pong_modem_doorbell_init(PongModemDoorbell *,void (*wake)(void *,uint32_t),void *context);
bool pong_modem_doorbell_send(uint32_t signal);
