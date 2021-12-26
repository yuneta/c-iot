/****************************************************************************
 *              YUNETA_IOT.H
 *              Includes
 *              Copyright (c) 2022 Niyamaka.
 *              All Rights Reserved.
 ****************************************************************************/
#pragma once

#ifdef __cplusplus
extern "C"{
#endif

/*
 *  core
 */
#include <yuneta.h>
#include "yuneta_iot_version.h"
#include "yuneta_iot_register.h"

/*
 *  Services
 */

/*
 *  Gadgets
 */

/*
 *  Protocols
 */
#include "c_prot_modbus_master.h"
#include "c_prot_canopen.h"
#include "c_prot_gps.h"

/*
 *  Mixin uv-gobj
 */
#include "c_canbus0.h"


#ifdef __cplusplus
}
#endif
