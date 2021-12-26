/****************************************************************************
 *          C_PROT_MODBUS_MASTER.H
 *          Prot_modbus_master GClass.
 *
 *          Modbus protocol (master side)
 *
 *          Copyright (c) 2021 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <ginsfsm.h>
#include "c_timer.h"
#include "c_connex.h"
#include "c_serial.h"

#ifdef __cplusplus
extern "C"{
#endif

/***************************************************************
 *              Constants
 ***************************************************************/
#define GCLASS_PROT_MODBUS_MASTER_NAME "Prot_modbus_master"
#define GCLASS_PROT_MODBUS_MASTER gclass_prot_modbus_master()

/***************************************************************
 *              Prototypes
 ***************************************************************/
PUBLIC GCLASS *gclass_prot_modbus_master(void);

#ifdef __cplusplus
}
#endif
