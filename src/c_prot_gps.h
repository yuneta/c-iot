/****************************************************************************
 *          C_PROT_GPS.H
 *          Prot_gps GClass
 *
 *          Gps (NMEA) protocol
 *
 *          Copyright (c) 2021 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <ginsfsm.h>
#include "c_timer.h"
#include "c_serial.h"

#ifdef __cplusplus
extern "C"{
#endif


/*********************************************************************
 *      GClass
 *********************************************************************/
PUBLIC GCLASS *gclass_prot_gps(void);

#define GCLASS_PROT_GPS_NAME "Prot_gps"
#define GCLASS_PROT_GPS gclass_prot_gps()

#ifdef __cplusplus
}
#endif
