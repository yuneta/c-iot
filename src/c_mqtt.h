/****************************************************************************
 *          C_MQTT.H
 *          GClass of MQTT protocol.
 *
 *  Implementation of the MQTT protocol.
 *


    Input Events                                Output Events

                    ┌───────────────────────┐
        start   ━━━▷│●                      │
                    │-----------------------│
                    │                       │
                    │                       │====▷  EV_ON_OPEN
                    │                       │====▷  EV_ON_MESSAGE
                    │                       │====▷  EV_ON_CLOSE
                    │                       │
                    │-----------------------│
        stop    ━━━▷│■  ◁--(auto) in clisrv │====▷  EV_STOPPED
                    └───────────────────────┘


 *          Copyright (c) 2022 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <yuneta.h>
#include "msglog_iot.h"

#ifdef __cplusplus
extern "C"{
#endif


/*********************************************************************
 *      GClass
 *********************************************************************/
PUBLIC GCLASS *gclass_mqtt(void);

#define GCLASS_MQTT_NAME "Mqtt"
#define GCLASS_MQTT gclass_mqtt()

#ifdef __cplusplus
}
#endif
