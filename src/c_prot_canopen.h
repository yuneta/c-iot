/****************************************************************************
 *          C_PROT_CANOPEN.H
 *          Prot_canopen GClass
 *
 *          CanOpen protocol
 *
 *          Copyright (c) 2021 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <ginsfsm.h>
#include "c_timer.h"
#include "c_canbus0.h"

#ifdef __cplusplus
extern "C"{
#endif


/*********************************************************************
 *      GClass
 *********************************************************************/
PUBLIC GCLASS *gclass_prot_canopen(void);

#define GCLASS_PROT_CANOPEN_NAME "Prot_canopen"
#define GCLASS_PROT_CANOPEN gclass_prot_canopen()

#ifdef __cplusplus
}
#endif
