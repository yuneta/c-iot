/****************************************************************************
 *          C_GPS_SIM7600.H
 *          Gps_sim7600 GClass
 *
 *          Gps SIM7600 protocol
 *
 *          Copyright (c) 2022 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <yuneta.h>

#ifdef __cplusplus
extern "C"{
#endif

/*

Example with Things Mobile provider

Create the file ``/etc/network/interfaces.d/wwan0`` with next content ::

    auto wwan0
    iface wwan0 inet manual
        pre-up qmicli -d /dev/cdc-wdm0 --dms-set-operating-mode='online'
        pre-up ifconfig wwan0 down
        pre-up echo Y > /sys/class/net/wwan0/qmi/raw_ip
        pre-up ifconfig wwan0 up
        pre-up for _ in $(seq 1 30); do /usr/bin/test -c /dev/cdc-wdm0 && break; /bin/sleep 2; done
        pre-up for _ in $(seq 1 30); do /usr/bin/qmicli -d /dev/cdc-wdm0 --nas-get-signal-strength && break; /bin/sleep 2; done
        pre-up qmicli -p -d /dev/cdc-wdm0 --device-open-net='net-raw-ip|net-no-qos-header' --wds-start-network="apn='TM',ip-type=4" --client-no-release-cid
        pre-up udhcpc -i wwan0


To interface up::

    sudo ifup wwan0

To interface down::

    sudo ifdown wwan0


*/

/*********************************************************************
 *      GClass
 *********************************************************************/
PUBLIC GCLASS *gclass_gps_sim7600(void);

#define GCLASS_GPS_SIM7600_NAME "Gps_sim7600"
#define GCLASS_GPS_SIM7600 gclass_gps_sim7600()

#ifdef __cplusplus
}
#endif
