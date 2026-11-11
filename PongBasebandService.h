/* SPDX-License-Identifier: BSD-2-Clause */
#pragma once
#include "PongModemQrtr.h"
/* The MPSS owner thread alone invokes these transport entry points. */
bool pong_baseband_transport_start(PongModemQrtr *);
void pong_baseband_transport_server(const PongQrtrServer *,bool added);
bool pong_baseband_transport_receive(uint32_t local,uint32_t node,uint32_t port,const void *,uint32_t);
void pong_baseband_transport_poll(void);
void pong_baseband_transport_offline(void);
void pong_baseband_transport_report(void);
/* Actual DMS GetRevision reply; never an Apple firmware/serial placeholder. */
void pong_baseband_transport_revision(const char *,uint32_t);
/* Read-only physical device identity from a matched, successful DMS reply. */
bool pong_baseband_transport_imei(const char *,uint32_t);
/* Matched DMS GetMSISDN response, including a legitimate empty value. */
bool pong_baseband_transport_msisdn(const char *,uint32_t);
/* Matched physical IMS/IMSA status; UINT32_MAX means unknown/absent. */
void pong_baseband_transport_ims(uint32_t registration,uint32_t technology,uint32_t voice,uint32_t sms,
    uint32_t voiceTechnology,uint32_t voiceEnabled,uint32_t registrationEnabled);
/* Actual NAS GetSupportedMessages bitmap; absence remains unknown. */
bool pong_baseband_transport_nas_messages(const uint8_t *,uint32_t);
/* Matched UIM GetCardStatus payload; states only, never ICCID/AID content. */
bool pong_baseband_transport_slots(const uint8_t *,uint32_t);
/* Matched physical UIM EF reply; file0 revokes cached subscriber identity. */
bool pong_baseband_transport_sim_identity(uint16_t,const uint8_t *,uint32_t);
/* Physical WAN owner registers these only with real ring/lifecycle methods.
 * Delivery executes on that owner thread; IP interfaces remain down until
 * actual ready(), matched WDS state and the hardware path agree. */
bool pong_baseband_wan_backend(int (*send)(uint32_t,const uint8_t *,uint32_t),bool (*ready)(void));
void pong_baseband_wan_receive(uint32_t mux,const uint8_t *,uint32_t bytes,uint32_t ip_version);
