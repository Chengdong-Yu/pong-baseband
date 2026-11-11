/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Boot-lifetime optional MPSS owner, separate from the iOS ABM service. */
void pong_modem_start_optional(void);
/* Read-only current owner snapshot, suitable for the USB command worker. */
void pong_modem_report(void);
/* Explicit USB/native development control, handled on the existing QRTR
 * owner thread. A queued request is not an ONLINE or network success. */
bool pong_modem_request_online(void);
/* Last actual native DMS radio intent; unknown is not an online request. */
bool pong_modem_native_online_requested(void);
/* Actual DPM/WDA setup, requested by a native WDS/QOS bind. */
void pong_modem_request_data_port(void);
int pong_modem_data_port_status(void);
/* Real PAS/ready state; never a cached Apple board GPIO approximation. */
bool pong_modem_is_powered(void);
bool pong_modem_is_ready(void);
/* Request is executed only on the existing AOP mailbox owner thread.
 * 0 acknowledged, EAGAIN pending, another errno is a real failure. */
int pong_aop_modem_power_on(void);
#ifdef __cplusplus
}
#endif
