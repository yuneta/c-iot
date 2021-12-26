/***********************************************************************
 *          C_PROT_CANOPEN.C
 *          Prot_canopen GClass
 *
 *          CanOpen protocol
 *
 *          Copyright (c) 2021 Niyamaka.
 *          All Rights Reserved.
***********************************************************************/
#include <string.h>
#include "c_prot_canopen.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/


/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
SDATA (ASN_OCTET_STR,   "device",           SDF_RD,             "",         "interface device, ex: can0"),
SDATA (ASN_BOOLEAN,     "connected",        SDF_RD|SDF_STATS,   0, "Connection state. Important filter!"),
SDATA (ASN_INTEGER,     "timeout_base",     SDF_RD,             5*1000, "timeout base"),
SDATA (ASN_POINTER,     "user_data",        0,  0, "user data"),
SDATA (ASN_POINTER,     "user_data2",       0,  0, "more user data"),
SDATA (ASN_POINTER,     "subscriber",       0,  0, "subscriber of output-events. Default if null is parent."),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_DEBUG = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"debug",        "Trace to debug"},
{0, 0},
};

/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    // Conf
    int32_t timeout_base;

    BOOL inform_on_close;

    hgobj gobj_canbus;
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

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(timeout_base,          gobj_read_int32_attr)

    json_t *kw_canbus = json_pack("{s:s}",
        "device", gobj_read_str_attr(gobj, "device")
    );
    priv->gobj_canbus = gobj_create(gobj_name(gobj), GCLASS_CANBUS0, kw_canbus, gobj);
    gobj_subscribe_event(priv->gobj_canbus, NULL, NULL, gobj);

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

    gobj_start(priv->timer);
    //set_timeout_periodic(priv->timer, priv->timeout_base);
    gobj_start(priv->gobj_canbus);
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
    gobj_stop(priv->gobj_canbus);
    return 0;
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
}




            /***************************
             *      Local Methods
             ***************************/




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_connected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_write_bool_attr(gobj, "connected", TRUE);

    priv->inform_on_close = TRUE;
    gobj_publish_event(gobj, "EV_ON_OPEN", 0);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_disconnected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

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
//     PRIVATE_DATA *priv = gobj_priv_data(gobj);
//     GBUFFER *gbuf = (GBUFFER *)(size_t)kw_get_int(kw, "gbuffer", 0, FALSE);

    // TODO
    return gobj_publish_event(gobj, "EV_ON_MESSAGE", kw);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_send_message(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
//     GBUFFER *gbuf = (GBUFFER *)(size_t)kw_get_int(kw, "gbuffer", 0, FALSE);
    // TODO
    return gobj_send_event(priv->gobj_canbus, "EV_TX_DATA", kw, gobj);
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
 *
 ***************************************************************************/
PRIVATE int ac_timeout(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    {"EV_RX_DATA",          0},
    {"EV_SEND_MESSAGE",     0},
    {"EV_CONNECTED",        0},
    {"EV_DISCONNECTED",     0},
    {"EV_TX_READY",         0},
    {"EV_TIMEOUT",          0},
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
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_RX_DATA",          ac_rx_data,         0},
    {"EV_SEND_MESSAGE",     ac_send_message,    0},
    {"EV_CONNECTED",        ac_connected,       0},
    {"EV_DISCONNECTED",     ac_disconnected,    0},
    {"EV_TX_READY",         ac_transmit_ready,  0},
    {"EV_TIMEOUT",          ac_timeout,         0},
    {"EV_STOPPED",          0,                  0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_IDLE,
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
    GCLASS_PROT_CANOPEN_NAME,     // CHANGE WITH each gclass
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
    0,  // acl
    s_user_trace_level,
    0, // cmds
    0, // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_prot_canopen(void)
{
    return &_gclass;
}
