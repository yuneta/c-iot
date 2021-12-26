/****************************************************************************
 *          C_CANBUS0.H
 *          Canbus0 GClass.
 *
 *          Canbus (socketcan CAN_RAW) uv-mixin for Yuneta
 *
 *          Copyright (c) 2021 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <ginsfsm.h>
#include "c_timer.h"

#ifdef __cplusplus
extern "C"{
#endif

/***************************************************************
 *              Constants
 ***************************************************************/
#define GCLASS_CANBUS0_NAME "Canbus0"
#define GCLASS_CANBUS0 gclass_canbus0()

/***************************************************************
 *              Prototypes
 ***************************************************************/
PUBLIC GCLASS *gclass_canbus0(void);

#ifdef __cplusplus
}
#endif
