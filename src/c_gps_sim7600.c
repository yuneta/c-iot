/***********************************************************************
 *          C_GPS_SIM7600.C
 *          Gps_sim7600 GClass
 *
 *          Gps SIM7600 protocol
 *
 *          Copyright (c) 2022 Niyamaka.
 *          All Rights Reserved.
***********************************************************************/
#include <string.h>
#include "c_gps_sim7600.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/
/*
    On power on of SIM7600 these messages arrived:
        "+CPIN: READY\r\n"
        "SMS DONE\r\n"
        "PB DONE\r\n"

    ATI
        Manufacturer: SIMCOM INCORPORATED
        Model: SIMCOM_SIM7600E-H
        Revision: SIM7600M22_V2.0.1
        IMEI: 860147051346169
        +GCAP: +CGSM,+DS,+ES

    AT+CGPSHOR=2

    AT+CGNSSINFO
        +CGNSSINFO: 2,04,01,00,4503.299486,N,00074.557903,E,281221,105825.0,33.3,0.0,,1.7,1.4,0.9

    AT+CGNSSINFO=2 (receive each 2 seconds gnss info)

    [<mode>],           Fix mode 2=2D fix 3=3D fix
    [<GPS-SVs>],        GPS satellite valid numbers, scope: 00-12
    [<GLONASS-SVs>],    GLONASS satellite valid numbers, scope: 00-12
    [BEIDOU-SVs],       BEIDOU satellite valid numbers, scope: 00-12
    [<lat>],            Latitude of current position. Output format is ddmm.mmmmmm
    [<N/S>],            N/S Indicator, N=north or S=south
    [<log>],            Longitude of current position. Output format is dddmm.mmmmmm
    [<E/W>],            E/W Indicator, E=east or W=west
    [<date>],           Date. Output format is ddmmyy
    [<UTC-time>],       UTC Time. Output format is hhmmss.s
    [<alt>],            MSL Altitude. Unit is meters.
    [<speed>],          Speed Over Ground. Unit is knots.
    [<course>],         Course. Degrees.
    [<PDOP>],           Position Dilution Of Precision.
    [HDOP],             Horizontal Dilution Of Precision.
    [VDOP]              Vertical Dilution Of Precision.

 */

typedef enum {
    WAIT_BOOT,              // Wait some time so power on messages arrived (10 seconds)
    WAIT_ATI,               // Get product information
    WAIT_CHECK_CGPS,        // Check if GPS is enabled
    WAIT_SET_CGPSAUTO,      // Set auto gps
    WAIT_SET_CGPS,          // Enable gps
    WAIT_SET_CGPSHOR,       // Configure positioning desired accuracy
    WAIT_CGNSSINFO          // Get GNSS information
} gps_state_t;

PRIVATE const char *gps_state_names[] = {
    "WAIT_BOOT",
    "WAIT_ATI",
    "WAIT_CHECK_CGPS",
    "WAIT_SET_CGPSAUTO",
    "WAIT_SET_CGPS",
    "WAIT_SET_CGPSHOR",
    "WAIT_CGNSSINFO",
    0
};

#define STATE_NAME(_st_) gps_state_names[_st_]

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE int reset_gps_machine(hgobj gobj);
PRIVATE int send_ati(hgobj gobj);
PRIVATE int process_ati(hgobj gobj, GBUFFER *gbuf);
PRIVATE int send_check_cgps(hgobj gobj);
PRIVATE int process_check_cgps(hgobj gobj, GBUFFER *gbuf);
PRIVATE int send_set_cgpsauto(hgobj gobj);
PRIVATE int process_set_cgpsauto(hgobj gobj, GBUFFER *gbuf);
PRIVATE int send_set_cgps(hgobj gobj);
PRIVATE int process_set_cgps(hgobj gobj, GBUFFER *gbuf);
PRIVATE int send_set_cgpshor(hgobj gobj);
PRIVATE int process_set_cgpshor(hgobj gobj, GBUFFER *gbuf);
PRIVATE int send_cgnssinfo(hgobj gobj);
PRIVATE int process_cgnssinfo(hgobj gobj, GBUFFER *gbuf);
PRIVATE int build_gps_message(hgobj gobj);

/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_authzs(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_send_message(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_set_gnss_interval(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_set_accuracy(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE sdata_desc_t pm_help[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "cmd",          0,              0,          "command about you want help."),
SDATAPM (ASN_UNSIGNED,  "level",        0,              0,          "command search level in childs"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_authzs[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "authz",        0,              0,          "permission to search"),
SDATAPM (ASN_OCTET_STR, "service",      0,              0,          "Service where to search the permission. If empty print all service's permissions"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_send_message[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "message",      0,              0,          "message (AT command) to send to gps"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_set_gnss_interval[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "gnss_interval", 0,             0,          "Interval in seconds of gnss data (0 to stop, 1-255 interval in seconds)"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_set_accuracy[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "accuracy",     0,              0,          "Accuracy (in meters 0-1800000)"),
SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD---type-----------name----------------alias---items-----------json_fn---------description---------- */
SDATACM (ASN_SCHEMA,    "help",             a_help, pm_help,        cmd_help,       "Command's help"),
SDATACM (ASN_SCHEMA,    "authzs",           0,      pm_authzs,      cmd_authzs,     "Authorization's help"),
SDATACM (ASN_SCHEMA,    "send-message",     0,      pm_send_message,cmd_send_message,"Send command to gps"),
SDATACM (ASN_SCHEMA,    "set-gnss-interval",0,      pm_set_gnss_interval,cmd_set_gnss_interval,"Set gnss data interval (in seconds 1-255)"),
SDATACM (ASN_SCHEMA,    "set-accuracy",     0,      pm_set_accuracy,cmd_set_accuracy,"Set gps accuracy (in meters 0-1800000)"),
SDATA_END()
};

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag----------------default-----description---------- */
SDATA (ASN_OCTET_STR,   "manufacturer",     SDF_RD,             "",         "Info of gps"),
SDATA (ASN_OCTET_STR,   "model",            SDF_RD,             "",         "Info of gps"),
SDATA (ASN_OCTET_STR,   "revision",         SDF_RD,             "",         "Info of gps"),
SDATA (ASN_OCTET_STR,   "imei",             SDF_RD,             "",         "Info of gps"),
SDATA (ASN_JSON,        "kw_serial",        SDF_RD,             0,          "Kw to create serial bottom gobj"),
SDATA (ASN_OCTET_STR,   "device",           SDF_RD,             "",         "interface device, ex: ttyUSB1"),
SDATA (ASN_BOOLEAN,     "connected",        SDF_RD|SDF_STATS,   0,          "Connection state. Important filter!"),
SDATA (ASN_INTEGER,     "timeout_boot",     SDF_RD,             10*1000,    "timeout waiting gps boot"),
SDATA (ASN_INTEGER,     "timeout_resp",     SDF_RD,             5*1000,     "timeout waiting gps response"),
SDATA (ASN_INTEGER,     "gnss_interval",    SDF_WR|SDF_PERSIST, 10,         "gps data periodic time interval"),
SDATA (ASN_UNSIGNED,    "accuracy",         SDF_WR|SDF_PERSIST, 2,          "gps accuracy"),

SDATA (ASN_POINTER,     "user_data",        0,  0, "user data"),
SDATA (ASN_POINTER,     "user_data2",       0,  0, "more user data"),
SDATA (ASN_POINTER,     "subscriber",       0,  0, "subscriber of output-events. Default if null is parent."),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_MESSAGES = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"messages",        "Trace messages"},
{0, 0},
};

/*---------------------------------------------*
 *      GClass authz levels
 *---------------------------------------------*/
PRIVATE sdata_desc_t pm_authz_sample[] = {
/*-PM-----type--------------name----------------flag--------authpath--------description-- */
SDATAPM0 (ASN_OCTET_STR,    "param sample",     0,          "",             "Param ..."),
SDATA_END()
};

PRIVATE sdata_desc_t authz_table[] = {
/*-AUTHZ-- type---------name------------flag----alias---items---------------description--*/
SDATAAUTHZ (ASN_SCHEMA, "sample",       0,      0,      pm_authz_sample,    "Permission to ..."),
SDATA_END()
};

/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    // Conf
    //int32_t timeout_base;

    GBUFFER *gbuf_rx;
    int gps_state;

    BOOL inform_on_close;

    hgobj gobj_bottom;
    hgobj timer;
} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    priv->timer = gobj_create(gobj_name(gobj), GCLASS_TIMER, 0, gobj);
    priv->gbuf_rx = gbuf_create(1024, 1024, 0, 0);

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    //SET_PRIV(timeout_base,          gobj_read_int32_attr)

    hgobj subscriber = (hgobj)gobj_read_pointer_attr(gobj, "subscriber");
    if(!subscriber)
        subscriber = gobj_parent(gobj);
    gobj_subscribe_event(gobj, NULL, NULL, subscriber);
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    priv->gobj_bottom = gobj_bottom_gobj(gobj);
    if(!priv->gobj_bottom) {
        // Manual serial configuration
        json_t *kw_serial = gobj_read_json_attr(gobj, "kw_serial");
        json_incref(kw_serial);
        priv->gobj_bottom = gobj_create(gobj_name(gobj), GCLASS_SERIAL, kw_serial, gobj);
        gobj_set_bottom_gobj(gobj, priv->gobj_bottom);
        gobj_write_str_attr(priv->gobj_bottom, "tx_ready_event_name", 0);
    }

    if(!gobj_is_running(priv->gobj_bottom)) {
        gobj_start(priv->gobj_bottom);
    }

    gobj_start(priv->timer);

    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    clear_timeout(priv->timer);
    gobj_stop(priv->timer);
    gobj_stop(priv->gobj_bottom);
    return 0;
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    GBUF_DESTROY(priv->gbuf_rx);
}




            /***************************
             *      Commands
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    KW_INCREF(kw);
    json_t *jn_resp = gobj_build_cmds_doc(gobj, kw);
    return msg_iev_build_webix(
        gobj,
        0,
        jn_resp,
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_authzs(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    return gobj_build_authzs_doc(gobj, cmd, kw, src);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_send_message(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *message = kw_get_str(kw, "message", "", 0);
    if(empty_string(message)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("What message (AT command)?"),
            0,
            0,
            kw  // owned
        );
    }

    GBUFFER *gbuf = gbuf_create(strlen(message)+2, strlen(message)+2, 0, 0);
    json_t *kw_send = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );
    gbuf_append_string(gbuf, message);
    gbuf_append_string(gbuf, "\r\n");

    int ret = gobj_send_event(gobj, "EV_SEND_MESSAGE", kw_send, gobj);

    return msg_iev_build_webix(
        gobj,
        ret,
        0,
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_set_gnss_interval(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    int interval = kw_get_int(kw, "gnss_interval", 10, KW_WILD_NUMBER);

    if(interval <= 0 || interval >= 255) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("What interval? (0 to stop, 1-255 interval in seconds"),
            0,
            0,
            kw  // owned
        );
    }

    gobj_write_int32_attr(gobj, "gnss_interval", interval);
    gobj_save_persistent_attrs(gobj, json_string("gnss_interval"));

    gobj_send_event(priv->gobj_bottom, "EV_DROP", 0, gobj);

    return msg_iev_build_webix(
        gobj,
        0,
        json_sprintf("Set gnss interval to %d seconds", interval),
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_set_accuracy(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    int accuracy = kw_get_int(kw, "accuracy", 2, KW_WILD_NUMBER);

    if(accuracy <= 0 || accuracy >= 1800000) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_sprintf("What accuracy? (in meters 0-1800000)"),
            0,
            0,
            kw  // owned
        );
    }

    gobj_write_int32_attr(gobj, "accuracy", accuracy);
    gobj_save_persistent_attrs(gobj, json_string("accuracy"));

    gobj_send_event(priv->gobj_bottom, "EV_DROP", 0, gobj);

    return msg_iev_build_webix(
        gobj,
        0,
        json_sprintf("Set accuracy to %d meters", accuracy),
        0,
        0,
        kw  // owned
    );
}




            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int reset_gps_machine(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    set_timeout(priv->timer, gobj_read_int32_attr(gobj, "timeout_boot"));
    priv->gps_state = WAIT_BOOT;

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int send_ati(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *message = "ATI";

    GBUFFER *gbuf = gbuf_create(strlen(message)+2, strlen(message)+2, 0, 0);
    json_t *kw_send = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );
    gbuf_append_string(gbuf, message);
    gbuf_append_string(gbuf, "\r\n");

    priv->gps_state = WAIT_ATI;

    return gobj_send_event(gobj, "EV_SEND_MESSAGE", kw_send, gobj);
}

/***************************************************************************
 *
    Manufacturer: SIMCOM INCORPORATED
    Model: SIMCOM_SIM7600E-H
    Revision: SIM7600M22_V2.0.1
    IMEI: 860147051346169
    +GCAP: +CGSM,+DS,+ES
 ***************************************************************************/
PRIVATE int process_ati(hgobj gobj, GBUFFER *gbuf)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    #define MANUFACTURER "Manufacturer: "
    #define MODEL "Model: "
    #define REVISION "Revision: "
    #define IMEI "IMEI: "

    char *p = gbuf_cur_rd_pointer(gbuf);
    int len = gbuf_leftbytes(gbuf);

    if(len > 6) {
        if(strncmp(p + len - 6, "\r\nOK\r\n", 6)==0) {
            char *line;
            while((line = gbuf_getline(gbuf, '\n'))) {
                if(strncmp(line, MANUFACTURER, strlen(MANUFACTURER))==0) {
                    char *v = line + strlen(MANUFACTURER);
                    left_justify(line);
                    gobj_write_str_attr(gobj, "manufacturer", v);

                } else if(strncmp(line, MODEL, strlen(MODEL))==0) {
                    char *v = line + strlen(MODEL);
                    left_justify(line);
                    gobj_write_str_attr(gobj, "model", v);

                } else if(strncmp(line, REVISION, strlen(REVISION))==0) {
                    char *v = line + strlen(REVISION);
                    left_justify(line);
                    gobj_write_str_attr(gobj, "revision", v);

                } else if(strncmp(line, IMEI, strlen(IMEI))==0) {
                    char *v = line + strlen(IMEI);
                    left_justify(line);
                    gobj_write_str_attr(gobj, "imei", v);
                }
            }

            if(!empty_string(gobj_read_str_attr(gobj, "imei"))) {
                clear_timeout(priv->timer);
                send_check_cgps(gobj);
            } else {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                    "msg",          "%s", "NO IMEI",
                    "state",        "%s", STATE_NAME(priv->gps_state),
                    NULL
                );
            }
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int send_check_cgps(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *message = "AT+CGPS?";

    GBUFFER *gbuf = gbuf_create(strlen(message)+2, strlen(message)+2, 0, 0);
    json_t *kw_send = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );
    gbuf_append_string(gbuf, message);
    gbuf_append_string(gbuf, "\r\n");

    priv->gps_state = WAIT_CHECK_CGPS;

    return gobj_send_event(gobj, "EV_SEND_MESSAGE", kw_send, gobj);
}

/***************************************************************************
 *
    +CGPS: 1,1

    OK
 ***************************************************************************/
PRIVATE int process_check_cgps(hgobj gobj, GBUFFER *gbuf)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    #define CGPS_ON  "+CGPS: 1"
    #define CGPS_OFF "+CGPS: 0"

    char *p = gbuf_cur_rd_pointer(gbuf);
    int len = gbuf_leftbytes(gbuf);

    if(len > 6) {
        if(strncmp(p + len - 6, "\r\nOK\r\n", 6)==0) {
            char *line;
            while((line = gbuf_getline(gbuf, '\n'))) {
                if(strncmp(line, CGPS_ON, strlen(CGPS_ON))==0) {
                    clear_timeout(priv->timer);
                    send_set_cgpshor(gobj);
                } else if(strncmp(line, CGPS_OFF, strlen(CGPS_OFF))==0) {
                    clear_timeout(priv->timer);
                    send_set_cgpsauto(gobj);
                }
            }
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int send_set_cgpsauto(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *message = "AT+CGPSAUTO=1";

    GBUFFER *gbuf = gbuf_create(strlen(message)+2, strlen(message)+2, 0, 0);
    json_t *kw_send = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );
    gbuf_append_string(gbuf, message);
    gbuf_append_string(gbuf, "\r\n");

    priv->gps_state = WAIT_SET_CGPSAUTO;

    return gobj_send_event(gobj, "EV_SEND_MESSAGE", kw_send, gobj);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int process_set_cgpsauto(hgobj gobj, GBUFFER *gbuf)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    char *p = gbuf_cur_rd_pointer(gbuf);
    int len = gbuf_leftbytes(gbuf);

    if(len > 6) {
        if(strncmp(p + len - 6, "\r\nOK\r\n", 6)==0) {
            clear_timeout(priv->timer);
            send_set_cgps(gobj);
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int send_set_cgps(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *message = "AT+CGPS=1,1";

    GBUFFER *gbuf = gbuf_create(strlen(message)+2, strlen(message)+2, 0, 0);
    json_t *kw_send = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );
    gbuf_append_string(gbuf, message);
    gbuf_append_string(gbuf, "\r\n");

    priv->gps_state = WAIT_SET_CGPS;

    return gobj_send_event(gobj, "EV_SEND_MESSAGE", kw_send, gobj);
}

/***************************************************************************
 *
    AT+CGPS=1,1
    OK
 ***************************************************************************/
PRIVATE int process_set_cgps(hgobj gobj, GBUFFER *gbuf)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    #define ATCGPS_ON  "AT+CGPS=1,1"

    char *p = gbuf_cur_rd_pointer(gbuf);
    int len = gbuf_leftbytes(gbuf);

    if(len > 6) {
        if(strncmp(p + len - 6, "\r\nOK\r\n", 6)==0) {
            char *line;
            while((line = gbuf_getline(gbuf, '\n'))) {
                if(strncmp(line, ATCGPS_ON, strlen(ATCGPS_ON))==0) {
                    clear_timeout(priv->timer);
                    send_set_cgpshor(gobj);
                }
            }
        }
    }
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int send_set_cgpshor(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    char message[80];

    snprintf(message, sizeof(message), "AT+CGPSHOR=%d", gobj_read_uint32_attr(gobj, "accuracy"));

    GBUFFER *gbuf = gbuf_create(strlen(message)+2, strlen(message)+2, 0, 0);
    json_t *kw_send = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );
    gbuf_append_string(gbuf, message);
    gbuf_append_string(gbuf, "\r\n");

    priv->gps_state = WAIT_SET_CGPSHOR;

    return gobj_send_event(gobj, "EV_SEND_MESSAGE", kw_send, gobj);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int process_set_cgpshor(hgobj gobj, GBUFFER *gbuf)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    char *p = gbuf_cur_rd_pointer(gbuf);
    int len = gbuf_leftbytes(gbuf);

    if(len > 6) {
        if(strncmp(p + len - 6, "\r\nOK\r\n", 6)==0) {
            clear_timeout(priv->timer);
            send_cgnssinfo(gobj);
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int send_cgnssinfo(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    char message[80];

    snprintf(message, sizeof(message), "AT+CGNSSINFO=%d", gobj_read_uint32_attr(gobj, "gnss_interval"));

    GBUFFER *gbuf = gbuf_create(strlen(message)+2, strlen(message)+2, 0, 0);
    json_t *kw_send = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );
    gbuf_append_string(gbuf, message);
    gbuf_append_string(gbuf, "\r\n");

    priv->gps_state = WAIT_CGNSSINFO;

    return gobj_send_event(gobj, "EV_SEND_MESSAGE", kw_send, gobj);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int process_cgnssinfo(hgobj gobj, GBUFFER *gbuf)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(!priv->inform_on_close) {
        gobj_write_bool_attr(gobj, "connected", TRUE);
        priv->inform_on_close = TRUE;
        gobj_publish_event(gobj, "EV_ON_OPEN", 0);
    }

    char *p = gbuf_cur_rd_pointer(gbuf);
    int len = gbuf_leftbytes(gbuf);

    if(len > 6) {
        if(strncmp(p + len - 6, "\r\nOK\r\n", 6)==0) {
            build_gps_message(gobj);
            clear_timeout(priv->timer);
            send_cgnssinfo(gobj);
        }
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int build_gps_message(hgobj gobj)
{
/*

    strncpy(LatDD,RecMessage,2);
    strncpy(LatMM,RecMessage+2,9);
    Lat = atoi(LatDD) + (atof(LatMM)/60);
    if(RecMessage[12] == 'N')
        printf("Latitude is %f N\n",Lat);
    else if(RecMessage[12] == 'S')
        printf("Latitude is %f S\n",Lat);
    else
        return false;

    strncpy(LogDD,RecMessage+14,3);
    strncpy(LogMM,RecMessage+17,9);
    Log = atoi(LogDD) + (atof(LogMM)/60);
    if(RecMessage[27] == 'E')
        printf("Longitude is %f E\n",Log);
    else if(RecMessage[27] == 'W')
        printf("Longitude is %f W\n",Log);
    else
        return false;

    strncpy(DdMmYy,RecMessage+29,6);
    DdMmYy[6] = '\0';
    printf("Day Month Year is %s\n",DdMmYy);

    strncpy(UTCTime,RecMessage+36,6);
    UTCTime[6] = '\0';
    printf("UTC time is %s\n",UTCTime);
*/

    json_t *jn_gps_mesage = json_object();

    /*----------------
     *  "gps_fixed"
     *----------------
     */

    /*----------------
     *  "latitude"
     *----------------
     */

    /*----------------
     *  "longitude"
     *----------------
     */

    /*----------------
     *  "accuracy"
     *----------------
     */

    /*----------------
     *  "altitude"
     *----------------
     */

    /*----------------
     *  "heading"
     *----------------
     */

    /*----------------
     *  "satellites"
     *----------------
     */

    /*----------------
     *  "speed"
     *----------------
     */

    return gobj_publish_event(gobj, "EV_ON_MESSAGE", jn_gps_mesage);
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_connected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    reset_gps_machine(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_disconnected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    clear_timeout(priv->timer);

    if(gobj_is_volatil(src)) {
        gobj_set_bottom_gobj(gobj, 0);
    }
    gobj_write_bool_attr(gobj, "connected", FALSE);

    if(priv->inform_on_close) {
        priv->inform_on_close = FALSE;
        gobj_publish_event(gobj, "EV_ON_CLOSE", 0);
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_rx_data(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    GBUFFER *gbuf = (GBUFFER *)(size_t)kw_get_int(kw, "gbuffer", 0, FALSE);

    if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
        char *p = gbuf_cur_rd_pointer(gbuf);
        trace_msg("<✅✅✅✅✅✅✅✅ %s %s %s", STATE_NAME(priv->gps_state), gobj_short_name(gobj), p);
    }

    gbuf_append_gbuf(priv->gbuf_rx, gbuf);

    switch(priv->gps_state) {
    case WAIT_BOOT:             // Wait some time so power on messages arrived (10 seconds)
        // Ignore +CPIN: READY, SMS DONE, PB DONE
        break;
    case WAIT_ATI:              // Get product information
        process_ati(gobj, priv->gbuf_rx);
        break;
    case WAIT_CHECK_CGPS:       // Check if GPS is enabled
        process_check_cgps(gobj, priv->gbuf_rx);
        break;
    case WAIT_SET_CGPSAUTO:     // Set auto gps
        process_set_cgpsauto(gobj, priv->gbuf_rx);
        break;
    case WAIT_SET_CGPS:         // Enable gps
        process_set_cgps(gobj, priv->gbuf_rx);
        break;
    case WAIT_SET_CGPSHOR:      // Configure positioning desired accuracy
        process_set_cgpshor(gobj, priv->gbuf_rx);
        break;
    case WAIT_CGNSSINFO:        // Get GNSS information
        process_cgnssinfo(gobj, priv->gbuf_rx);
        break;
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
        trace_msg("👉 %s %s -> timeout", STATE_NAME(priv->gps_state), gobj_short_name(gobj));
    }

    switch(priv->gps_state) {
    case WAIT_BOOT:             // Wait some time so power on messages arrived (10 seconds)
        send_ati(gobj);
        break;
    case WAIT_ATI:              // Get product information
    case WAIT_CHECK_CGPS:       // Check if GPS is enabled
    case WAIT_SET_CGPSAUTO:     // Set auto gps
    case WAIT_SET_CGPS:         // Enable gps
    case WAIT_SET_CGPSHOR:      // Configure positioning desired accuracy
    case WAIT_CGNSSINFO:        // Get GNSS information
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "timeout gps response",
            "state",        "%s", STATE_NAME(priv->gps_state),
            NULL
        );
        gobj_send_event(priv->gobj_bottom, "EV_DROP", 0, gobj);
        break;
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_send_message(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
        GBUFFER *gbuf = (GBUFFER *)(size_t)kw_get_int(kw, "gbuffer", 0, FALSE);
        char *p = gbuf_cur_rd_pointer(gbuf);
        trace_msg("👉👉👉👉👉👉👉👉> %s %s %s", STATE_NAME(priv->gps_state), gobj_short_name(gobj), p);
    }

    gbuf_clear(priv->gbuf_rx);
    set_timeout(priv->timer, gobj_read_int32_attr(gobj, "timeout_resp"));

    return gobj_send_event(priv->gobj_bottom, "EV_TX_DATA", kw, gobj);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_transmit_ready(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input
    // bottom input
    {"EV_RX_DATA",          0},
    {"EV_SEND_MESSAGE",     0},
    {"EV_CONNECTED",        0},
    {"EV_DISCONNECTED",     0},
    {"EV_TIMEOUT",          0},
    {"EV_TX_READY",         0},
    {"EV_STOPPED",          0},
    {NULL, 0}
};
PRIVATE const EVENT output_events[] = {
    {"EV_ON_OPEN",          0},
    {"EV_ON_CLOSE",         0},
    {"EV_ON_MESSAGE",       0},
    {NULL, 0}
};
PRIVATE const char *state_names[] = {
    "ST_DISCONNECTED",
    "ST_CONNECTED",
    NULL
};

PRIVATE EV_ACTION ST_DISCONNECTED[] = {
    {"EV_CONNECTED",        ac_connected,       "ST_CONNECTED"},
    {"EV_STOPPED",          0,                  0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_CONNECTED[] = {
    {"EV_RX_DATA",          ac_rx_data,         0},
    {"EV_SEND_MESSAGE",     ac_send_message,    0},
    {"EV_DISCONNECTED",     ac_disconnected,    "ST_DISCONNECTED"},
    {"EV_TX_READY",         ac_transmit_ready,  0},
    {"EV_TIMEOUT",          ac_timeout,         0},
    {"EV_STOPPED",          0,                  0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_DISCONNECTED,
    ST_CONNECTED,
    NULL
};

PRIVATE FSM fsm = {
    input_events,
    output_events,
    state_names,
    states,
};

/***************************************************************************
 *              GClass
 ***************************************************************************/
/*---------------------------------------------*
 *              Local methods table
 *---------------------------------------------*/
PRIVATE LMETHOD lmt[] = {
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_GPS_SIM7600_NAME,     // CHANGE WITH each gclass
    &fsm,
    {
        mt_create,
        0, //mt_create2,
        mt_destroy,
        mt_start,
        mt_stop,
        0, //mt_play,
        0, //mt_pause,
        mt_writing,
        0, //mt_reading,
        0, //mt_subscription_added,
        0, //mt_subscription_deleted,
        0, //mt_child_added,
        0, //mt_child_removed,
        0, //mt_stats,
        0, //mt_command,
        0, //mt_inject_event,
        0, //mt_create_resource,
        0, //mt_list_resource,
        0, //mt_update_resource,
        0, //mt_delete_resource,
        0, //mt_add_child_resource_link
        0, //mt_delete_child_resource_link
        0, //mt_get_resource
        0, //mt_authorization_parser,
        0, //mt_authenticate,
        0, //mt_list_childs,
        0, //mt_stats_updated,
        0, //mt_disable,
        0, //mt_enable,
        0, //mt_trace_on,
        0, //mt_trace_off,
        0, //mt_gobj_created,
        0, //mt_future33,
        0, //mt_future34,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_authz_checker,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_future44,
        0, //mt_unlink_nodes,
        0, //mt_topic_jtree,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_shoot_snap,
        0, //mt_activate_snap,
        0, //mt_list_snaps,
        0, //mt_treedbs,
        0, //mt_treedb_topics,
        0, //mt_topic_desc,
        0, //mt_topic_links,
        0, //mt_topic_hooks,
        0, //mt_node_parents,
        0, //mt_node_childs,
        0, //mt_list_instances,
        0, //mt_node_tree,
        0, //mt_topic_size,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    authz_table,
    s_user_trace_level,
    command_table,  // command_table
    0, // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_gps_sim7600(void)
{
    return &_gclass;
}
