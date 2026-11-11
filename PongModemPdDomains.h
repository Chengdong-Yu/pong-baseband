/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Service metadata from this Pong active modem_b, not firmware bytes.
 * Seven original *.jsn domains, captured2026-11-05 read-only. The locator
 * reports where firmware provides services, never that a PD is running.
 */
#pragma once
#include "QcomQrtr.h"
static const char *const PongPdServices1[]={"avs/audio",nullptr};
static const char *const PongPdServices4[]={"gps/gps_service",nullptr};
static const QcomPdDomain PongPdDomains[]={
    {"msm/adsp/root_pd",74,nullptr},
    {"msm/adsp/audio_pd",74,PongPdServices1},
    {"msm/adsp/charger_pd",74,nullptr},
    {"msm/cdsp/root_pd",76,nullptr},
    {"msm/modem/root_pd",180,PongPdServices4},
    {"msm/slpi/root_pd",90,nullptr},
    {"msm/slpi/sensor_pd",90,nullptr},
};
