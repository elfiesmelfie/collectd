/*
 * collectd - src/ovs_stats.c
 *
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *   Taras Chornyi <tarasx.chornyi@intel.com>
 *   Volodymyr Mytnyk <volodymyrx.mytnyk@intel.com>
 */

#include "common.h"

#include "utils_llist.h"
#include "utils_ovs.h" /* OvS helpers */

/* Plugin name */
static const char plugin_name[] = "ovs_stats";

typedef enum iface_counter {
  not_supported = -1,
  collisions,
  rx_bytes,
  rx_crc_err,
  rx_dropped,
  rx_errors,
  rx_frame_err,
  rx_over_err,
  rx_packets,
  tx_bytes,
  tx_dropped,
  tx_errors,
  tx_packets,
  rx_1_to_64_packets,
  rx_65_to_127_packets,
  rx_128_to_255_packets,
  rx_256_to_511_packets,
  rx_512_to_1023_packets,
  rx_1024_to_1522_packets,
  rx_1523_to_max_packets,
  tx_1_to_64_packets,
  tx_65_to_127_packets,
  tx_128_to_255_packets,
  tx_256_to_511_packets,
  tx_512_to_1023_packets,
  tx_1024_to_1522_packets,
  tx_1523_to_max_packets,
  tx_multicast_packets,
  rx_broadcast_packets,
  tx_broadcast_packets,
  rx_undersized_errors,
  rx_oversize_errors,
  rx_fragmented_errors,
  rx_jabber_errors,
  __iface_counter_max
} iface_counter;

#define OVS_STATS_DEFAULT_NODE "localhost" /* default OVS DB node */
#define OVS_STATS_DEFAULT_SERVICE "6640"   /* default OVS DB service */
#define IFACE_COUNTER_MAX (__iface_counter_max - 1)
#define IFACE_COUNTER_COUNT (__iface_counter_max)
#define PORT_NAME_SIZE_MAX 255
#define UUID_SIZE 64

typedef struct port_s {
  char name[PORT_NAME_SIZE_MAX];      /* Port name */
  char port_uuid[UUID_SIZE];          /* Port table _uuid */
  char iface_uuid[UUID_SIZE];         /* Interface table uuid */
  char ex_iface_id[UUID_SIZE];        /* External iface id */
  char ex_vm_id[UUID_SIZE];           /* External vm id */
  int64_t stats[IFACE_COUNTER_COUNT]; /* Port statistics */
  struct bridge_list_s *br;           /* Pointer to bridge */
  struct port_s *next;                /* Next port */
} port_list_t;

typedef struct bridge_list_s {
  char *name;                 /* Bridge name */
  struct bridge_list_s *next; /* Next bridge*/
} bridge_list_t;

static const char *const iface_counter_table[IFACE_COUNTER_COUNT] = {
        [collisions] = "collisions",
        [rx_bytes] = "rx_bytes",
        [rx_crc_err] = "rx_crc_err",
        [rx_dropped] = "rx_dropped",
        [rx_errors] = "rx_errors",
        [rx_frame_err] = "rx_frame_err",
        [rx_over_err] = "rx_over_err",
        [rx_packets] = "rx_packets",
        [tx_bytes] = "tx_bytes",
        [tx_dropped] = "tx_dropped",
        [tx_errors] = "tx_errors",
        [tx_packets] = "tx_packets",
        [rx_1_to_64_packets] = "rx_1_to_64_packets",
        [rx_65_to_127_packets] = "rx_65_to_127_packets",
        [rx_128_to_255_packets] = "rx_128_to_255_packets",
        [rx_256_to_511_packets] = "rx_256_to_511_packets",
        [rx_512_to_1023_packets] = "rx_512_to_1023_packets",
        [rx_1024_to_1522_packets] = "rx_1024_to_1518_packets",
        [rx_1523_to_max_packets] = "rx_1523_to_max_packets",
        [tx_1_to_64_packets] = "tx_1_to_64_packets",
        [tx_65_to_127_packets] = "tx_65_to_127_packets",
        [tx_128_to_255_packets] = "tx_128_to_255_packets",
        [tx_256_to_511_packets] = "tx_256_to_511_packets",
        [tx_512_to_1023_packets] = "tx_512_to_1023_packets",
        [tx_1024_to_1522_packets] = "tx_1024_to_1518_packets",
        [tx_1523_to_max_packets] = "tx_1523_to_max_packets",
        [tx_multicast_packets] = "tx_multicast_packets",
        [rx_broadcast_packets] = "rx_broadcast_packets",
        [tx_broadcast_packets] = "tx_broadcast_packets",
        [rx_undersized_errors] = "rx_undersized_errors",
        [rx_oversize_errors] = "rx_oversize_errors",
        [rx_fragmented_errors] = "rx_fragmented_errors",
        [rx_jabber_errors] = "rx_jabber_errors",
};

/* OVS stats configuration data */
struct ovs_stats_config_s {
  char ovs_db_node[OVS_DB_ADDR_NODE_SIZE];    /* OVS DB node */
  char ovs_db_serv[OVS_DB_ADDR_SERVICE_SIZE]; /* OVS DB service */
  char ovs_db_unix[OVS_DB_ADDR_UNIX_SIZE];    /* OVS DB unix socket path */
  bridge_list_t
      *monitored_bridge_list_head; /* List of monitored network bridges */
};
typedef struct ovs_stats_config_s ovs_stats_config_t;

/* OvS instance */
struct ovs_stats_inst_s {
  /* Entry into the list of network bridges */
  bridge_list_t *bridge_list_head;

  /* Entry into the list of bridge ports */
  port_list_t *port_list_head;

  /* lock for statistics cache */
  pthread_mutex_t stats_lock;

  /* pointer to OVS DB instance */
  ovs_db_t *ovs_db;

  /* OvS plugin configuration */
  ovs_stats_config_t config;

  /* Instance name */
  char name[DATA_MAX_NAME_LEN];
};
typedef struct ovs_stats_inst_s ovs_stats_inst_t;

/* OvS stats context type */
struct ovs_stats_ctx_s {
  ovs_t *ovs_obj;     /* pointer to OVS object */
  llist_t *list_inst; /* List of configured OVS instances */
};
typedef struct ovs_stats_ctx_s ovs_stats_ctx_t;

/* OvS stats context */
static ovs_stats_ctx_t ovs_stats_ctx;

static iface_counter ovs_stats_counter_name_to_type(const char *counter) {
  iface_counter index = not_supported;

  if (counter == NULL)
    return not_supported;

  for (int i = 0; i < IFACE_COUNTER_COUNT; i++) {
    if (strncmp(iface_counter_table[i], counter,
                strlen(iface_counter_table[i])) == 0) {
      index = i;
      break;
    }
  }
  return index;
}

static void ovs_stats_submit_one(const char *hostname, const char *dev,
                                 const char *type, const char *type_instance,
                                 derive_t value, meta_data_t *meta) {
  /* if counter is less than 0 - skip it*/
  if (value < 0)
    return;
  value_list_t vl = VALUE_LIST_INIT;

  vl.values = &(value_t){.derive = value};
  vl.values_len = 1;
  vl.meta = meta;

  sstrncpy(vl.host, hostname, sizeof(vl.host));
  sstrncpy(vl.plugin, plugin_name, sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, dev, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));

  if (type_instance != NULL)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
}

static void ovs_stats_submit_two(const char *hostname, const char *dev,
                                 const char *type, const char *type_instance,
                                 derive_t rx, derive_t tx, meta_data_t *meta) {
  /* if counter is less than 0 - skip it*/
  if (rx < 0 || tx < 0)
    return;
  value_list_t vl = VALUE_LIST_INIT;
  value_t values[] = {{.derive = rx}, {.derive = tx}};

  vl.values = values;
  vl.values_len = STATIC_ARRAY_SIZE(values);
  vl.meta = meta;

  sstrncpy(vl.host, hostname, sizeof(vl.host));
  sstrncpy(vl.plugin, plugin_name, sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, dev, sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));

  if (type_instance != NULL)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
}

static port_list_t *ovs_stats_get_port(ovs_stats_inst_t *inst,
                                       const char *uuid) {
  if (inst == NULL || uuid == NULL)
    return NULL;

  for (port_list_t *port = inst->port_list_head; port != NULL;
       port = port->next) {
    if (strncmp(port->port_uuid, uuid, strlen(port->port_uuid)) == 0)
      return port;
  }
  return NULL;
}

static port_list_t *ovs_stats_get_port_by_name(ovs_stats_inst_t *inst,
                                               const char *name) {
  if (inst == NULL || name == NULL)
    return NULL;

  for (port_list_t *port = inst->port_list_head; port != NULL;
       port = port->next)
    if ((strncmp(port->name, name, strlen(port->name)) == 0) &&
        strlen(name) == strlen(port->name))
      return port;
  return NULL;
}

/* Create or get port by port uuid */
static port_list_t *ovs_stats_new_port(ovs_stats_inst_t *inst,
                                       bridge_list_t *bridge,
                                       const char *uuid) {
  port_list_t *port = ovs_stats_get_port(inst, uuid);

  if (port == NULL) {
    port = calloc(1, sizeof(*port));
    if (!port) {
      ERROR("%s: Error allocating port", plugin_name);
      return NULL;
    }
    memset(port->stats, -1, sizeof(int64_t[IFACE_COUNTER_COUNT]));
    sstrncpy(port->port_uuid, uuid, sizeof(port->port_uuid));
    pthread_mutex_lock(&inst->stats_lock);
    port->next = inst->port_list_head;
    inst->port_list_head = port;
    pthread_mutex_unlock(&inst->stats_lock);
  }
  if (bridge != NULL) {
    pthread_mutex_lock(&inst->stats_lock);
    port->br = bridge;
    pthread_mutex_unlock(&inst->stats_lock);
  }
  return port;
}

/* Get bridge by name*/
static bridge_list_t *ovs_stats_get_bridge(bridge_list_t *head,
                                           const char *name) {
  if (name == NULL)
    return NULL;

  for (bridge_list_t *bridge = head; bridge != NULL; bridge = bridge->next) {
    if ((strncmp(bridge->name, name, strlen(bridge->name)) == 0) &&
        strlen(name) == strlen(bridge->name))
      return bridge;
  }
  return NULL;
}

/* Delete bridge */
static int ovs_stats_del_bridge(ovs_stats_inst_t *inst, yajl_val bridge) {
  const char *old[] = {"old", NULL};
  const char *name[] = {"name", NULL};

  yajl_val row;

  if (bridge && YAJL_IS_OBJECT(bridge)) {
    row = yajl_tree_get(bridge, old, yajl_t_object);
    if (row && YAJL_IS_OBJECT(row)) {
      yajl_val br_name = yajl_tree_get(row, name, yajl_t_string);
      if (br_name && YAJL_IS_STRING(br_name)) {
        bridge_list_t *prev_br = inst->bridge_list_head;
        for (bridge_list_t *br = inst->bridge_list_head; br != NULL;
             prev_br = br, br = br->next) {
          if ((strncmp(br->name, br_name->u.string, strlen(br->name)) == 0) &&
              strlen(br->name) == strlen(br_name->u.string)) {
            if (br == inst->bridge_list_head)
              inst->bridge_list_head = br->next;
            else
              prev_br->next = br->next;
            sfree(br->name);
            sfree(br);
            break;
          }
        }
      }
    }
  } else
    WARNING("%s: Incorrect data for deleting bridge", plugin_name);
  return 0;
}

/* Update Bridge. Create bridge ports*/
static int ovs_stats_update_bridge(ovs_stats_inst_t *inst, yajl_val bridge) {
  const char *new[] = {"new", NULL};
  const char *name[] = {"name", NULL};
  const char *ports[] = {"ports", NULL};
  bridge_list_t *br = NULL;

  if (bridge && YAJL_IS_OBJECT(bridge)) {
    yajl_val row = yajl_tree_get(bridge, new, yajl_t_object);
    if (row && YAJL_IS_OBJECT(row)) {
      yajl_val br_name = yajl_tree_get(row, name, yajl_t_string);
      yajl_val br_ports = yajl_tree_get(row, ports, yajl_t_array);
      if (br_name && YAJL_IS_STRING(br_name)) {
        br = ovs_stats_get_bridge(inst->bridge_list_head,
                                  YAJL_GET_STRING(br_name));
        pthread_mutex_lock(&inst->stats_lock);
        if (br == NULL) {
          br = calloc(1, sizeof(*br));
          if (!br) {
            ERROR("%s: Error allocating memory for bridge", plugin_name);
            return -1;
          }
          char *tmp = YAJL_GET_STRING(br_name);

          if (tmp != NULL)
            br->name = strdup(tmp);
          if (br->name == NULL) {
            sfree(br);
            pthread_mutex_unlock(&inst->stats_lock);
            return -1;
          }
          br->next = inst->bridge_list_head;
          inst->bridge_list_head = br;
        }
        pthread_mutex_unlock(&inst->stats_lock);
      }
      if (br_ports && YAJL_IS_ARRAY(br_ports)) {
        char *tmp = YAJL_GET_STRING(br_ports->u.array.values[0]);
        if (tmp != NULL && strcmp("set", tmp) == 0) {
          yajl_val *array = YAJL_GET_ARRAY(br_ports)->values;
          size_t array_len = YAJL_GET_ARRAY(br_ports)->len;
          if (array != NULL && array_len > 0 && YAJL_IS_ARRAY(array[1])) {
            yajl_val *ports_arr = YAJL_GET_ARRAY(array[1])->values;
            size_t ports_num = YAJL_GET_ARRAY(array[1])->len;
            for (size_t i = 0; i < ports_num && ports_arr != NULL; i++)
              ovs_stats_new_port(
                  inst, br, YAJL_GET_STRING(ports_arr[i]->u.array.values[1]));
          }
        } else
          ovs_stats_new_port(inst, br,
                             YAJL_GET_STRING(br_ports->u.array.values[1]));
      }
    }
  } else {
    ERROR("Incorrect JSON Bridge data");
    return -1;
  }
  return 0;
}

/* Handle JSON with Bridge Table change event */
static void ovs_stats_bridge_table_change_cb(yajl_val jupdates,
                                             void *user_data) {
  /* Bridge Table update example JSON data
    {
      "Bridge": {
        "bb1f8965-5775-46d9-b820-236ca8edbedc": {
          "new": {
            "name": "br0",
            "ports": [
              "set",
              [
                [
                  "uuid",
                  "117f1a07-7ef0-458a-865c-ec7fbb85bc01"
                ],
                [
                  "uuid",
                  "12fd8bdc-e950-4281-aaa9-46e185658f79"
                ]
              ]
            ]
          }
        }
      }
    }
   */
  const char *path[] = {"Bridge", NULL};

  yajl_val bridges = yajl_tree_get(jupdates, path, yajl_t_object);

  if (bridges && YAJL_IS_OBJECT(bridges)) {
    for (size_t i = 0; i < YAJL_GET_OBJECT(bridges)->len; i++) {
      yajl_val bridge = YAJL_GET_OBJECT(bridges)->values[i];
      ovs_stats_inst_t *inst = user_data;
      ovs_stats_update_bridge(inst, bridge);
    }
  }
}

/* Handle Bridge Table delete event */
static void ovs_stats_bridge_table_delete_cb(yajl_val jupdates,
                                             void *user_data) {
  const char *path[] = {"Bridge", NULL};
  yajl_val bridges = yajl_tree_get(jupdates, path, yajl_t_object);
  yajl_val bridge;
  if (bridges && YAJL_IS_OBJECT(bridges)) {
    ovs_stats_inst_t *inst = user_data;
    pthread_mutex_lock(&inst->stats_lock);
    for (size_t i = 0; i < YAJL_GET_OBJECT(bridges)->len; i++) {
      bridge = YAJL_GET_OBJECT(bridges)->values[i];
      ovs_stats_del_bridge(inst, bridge);
    }
    pthread_mutex_unlock(&inst->stats_lock);
  }
  return;
}

/* Handle JSON with Bridge table initial values */
static void ovs_stats_bridge_table_result_cb(yajl_val jresult, yajl_val jerror,
                                             void *user_data) {
  if (YAJL_IS_NULL(jerror))
    ovs_stats_bridge_table_change_cb(jresult, user_data);
  else
    ERROR("%s: Error received from OvSDB. Table: Bridge", plugin_name);
  return;
}

/* Update port name */
static int ovs_stats_update_port(ovs_stats_inst_t *inst, const char *uuid,
                                 yajl_val port) {
  const char *new[] = {"new", NULL};
  const char *name[] = {"name", NULL};
  yajl_val row;
  port_list_t *portentry = NULL;
  if (port && YAJL_IS_OBJECT(port)) {
    row = yajl_tree_get(port, new, yajl_t_object);
    if (row && YAJL_IS_OBJECT(row)) {
      yajl_val port_name = yajl_tree_get(row, name, yajl_t_string);
      if (port_name && YAJL_IS_STRING(port_name)) {
        portentry = ovs_stats_get_port(inst, uuid);
        if (portentry == NULL)
          portentry = ovs_stats_new_port(inst, NULL, uuid);
        if (portentry) {
          pthread_mutex_lock(&inst->stats_lock);
          sstrncpy(portentry->name, YAJL_GET_STRING(port_name),
                   sizeof(portentry->name));
          pthread_mutex_unlock(&inst->stats_lock);
        }
      }
    }
  } else {
    ERROR("Incorrect JSON Port data");
    return -1;
  }
  return 0;
}

/* Delete port from global port list */
static int ovs_stats_del_port(ovs_stats_inst_t *inst, const char *uuid) {
  port_list_t *prev_port = inst->port_list_head;
  for (port_list_t *port = inst->port_list_head; port != NULL;
       prev_port = port, port = port->next) {
    if (strncmp(port->port_uuid, uuid, strlen(port->port_uuid)) == 0) {
      if (port == inst->port_list_head)
        inst->port_list_head = port->next;
      else
        prev_port->next = port->next;
      sfree(port);
      break;
    }
  }
  return 0;
}

/* Handle JSON with Port Table change event */
static void ovs_stats_port_table_change_cb(yajl_val jupdates, void *user_data) {
  /* Port Table update example JSON data
    {
      "Port": {
        "ab107d6f-28a1-4257-b1cc-5b742821db8a": {
          "new": {
            "name": "br1",
            "interfaces": [
              "uuid",
              "33a289a0-1d34-4e46-a3c2-3e4066fbecc6"
            ]
          }
        }
      }
    }
   */
  const char *path[] = {"Port", NULL};
  yajl_val ports = yajl_tree_get(jupdates, path, yajl_t_object);
  yajl_val port;
  if (ports && YAJL_IS_OBJECT(ports)) {
    for (size_t i = 0; i < YAJL_GET_OBJECT(ports)->len; i++) {
      port = YAJL_GET_OBJECT(ports)->values[i];
      ovs_stats_inst_t *inst = user_data;
      ovs_stats_update_port(inst, YAJL_GET_OBJECT(ports)->keys[i], port);
    }
  }
  return;
}

/* Handle JSON with Port table initial values */
static void ovs_stats_port_table_result_cb(yajl_val jresult, yajl_val jerror,
                                           void *user_data) {
  if (YAJL_IS_NULL(jerror))
    ovs_stats_port_table_change_cb(jresult, user_data);
  else
    ERROR("%s: Error received from OvSDB. Table: Port", plugin_name);
  return;
}

/* Handle Port Table delete event */
static void ovs_stats_port_table_delete_cb(yajl_val jupdates, void *user_data) {
  const char *path[] = {"Port", NULL};
  yajl_val ports = yajl_tree_get(jupdates, path, yajl_t_object);
  ovs_stats_inst_t *inst = user_data;
  pthread_mutex_lock(&inst->stats_lock);
  if (ports && YAJL_IS_OBJECT(ports))
    for (size_t i = 0; i < YAJL_GET_OBJECT(ports)->len; i++) {
      ovs_stats_del_port(inst, YAJL_GET_OBJECT(ports)->keys[i]);
    }
  pthread_mutex_unlock(&inst->stats_lock);
  return;
}

/* Update interface statistics */
static int ovs_stats_update_iface_stats(port_list_t *port, yajl_val stats) {
  yajl_val stat;
  iface_counter counter_index = 0;
  char *counter_name = NULL;
  int64_t counter_value = 0;
  if (stats && YAJL_IS_ARRAY(stats))
    for (size_t i = 0; i < YAJL_GET_ARRAY(stats)->len; i++) {
      stat = YAJL_GET_ARRAY(stats)->values[i];
      if (!YAJL_IS_ARRAY(stat))
        return -1;
      counter_name = YAJL_GET_STRING(YAJL_GET_ARRAY(stat)->values[0]);
      counter_index = ovs_stats_counter_name_to_type(counter_name);
      counter_value = YAJL_GET_INTEGER(YAJL_GET_ARRAY(stat)->values[1]);
      if (counter_index == not_supported)
        continue;
      port->stats[counter_index] = counter_value;
    }

  return 0;
}

/* Update interface external_ids */
static int ovs_stats_update_iface_ext_ids(port_list_t *port, yajl_val ext_ids) {
  yajl_val ext_id;
  char *key;
  char *value;

  if (ext_ids && YAJL_IS_ARRAY(ext_ids))
    for (size_t i = 0; i < YAJL_GET_ARRAY(ext_ids)->len; i++) {
      ext_id = YAJL_GET_ARRAY(ext_ids)->values[i];
      if (!YAJL_IS_ARRAY(ext_id))
        return -1;
      key = YAJL_GET_STRING(YAJL_GET_ARRAY(ext_id)->values[0]);
      value = YAJL_GET_STRING(YAJL_GET_ARRAY(ext_id)->values[1]);
      if (key && value) {
        if (strncmp(key, "iface-id", strlen(key)) == 0)
          sstrncpy(port->ex_iface_id, value, sizeof(port->ex_iface_id));
        else if (strncmp(key, "vm-uuid", strlen(key)) == 0)
          sstrncpy(port->ex_vm_id, value, sizeof(port->ex_vm_id));
      }
    }

  return 0;
}

/* Get interface statistic and external_ids */
static int ovs_stats_update_iface(ovs_stats_inst_t *inst, yajl_val iface) {
  yajl_val row;
  port_list_t *port = NULL;
  if (iface && YAJL_IS_OBJECT(iface)) {
    row = ovs_utils_get_value_by_key(iface, "new");
    if (row && YAJL_IS_OBJECT(row)) {
      yajl_val iface_name = ovs_utils_get_value_by_key(row, "name");
      yajl_val iface_stats = ovs_utils_get_value_by_key(row, "statistics");
      yajl_val iface_ext_ids = ovs_utils_get_value_by_key(row, "external_ids");
      yajl_val iface_uuid = ovs_utils_get_value_by_key(row, "_uuid");
      if (iface_name && YAJL_IS_STRING(iface_name)) {
        port = ovs_stats_get_port_by_name(inst, YAJL_GET_STRING(iface_name));
        if (port == NULL)
          return 0;
      }
      /*
       * {
            "statistics": [
              "map",
              [
                [
                  "collisions",
                  0
                ],
                . . .
                [
                  "tx_packets",
                  0
                ]
              ]
            ]
          }
       Check that statistics is an array with 2 elements
       */
      if (iface_stats && YAJL_IS_ARRAY(iface_stats) &&
          YAJL_GET_ARRAY(iface_stats)->len == 2)
        ovs_stats_update_iface_stats(port,
                                     YAJL_GET_ARRAY(iface_stats)->values[1]);
      if (iface_ext_ids && YAJL_IS_ARRAY(iface_ext_ids))
        ovs_stats_update_iface_ext_ids(
            port, YAJL_GET_ARRAY(iface_ext_ids)->values[1]);
      if (iface_uuid && YAJL_IS_ARRAY(iface_uuid) &&
          YAJL_GET_ARRAY(iface_uuid)->len == 2)
        sstrncpy(port->iface_uuid,
                 YAJL_GET_STRING(YAJL_GET_ARRAY(iface_uuid)->values[1]),
                 sizeof(port->iface_uuid));
    }
  } else {
    ERROR("Incorrect JSON Port data");
    return -1;
  }
  return 0;
}

/* Handle JSON with Interface Table change event */
static void ovs_stats_interface_table_change_cb(yajl_val jupdates,
                                                void *user_data) {
  /* Interface Table update example JSON data
    {
      "Interface": {
        "33a289a0-1d34-4e46-a3c2-3e4066fbecc6": {
          "new": {
            "name": "br1",
            "statistics": [
              "map",
              [
                [
                  "collisions",
                  0
                ],
                [
                  "rx_bytes",
                  0
                ],
               . . .
                [
                  "tx_packets",
                  12617
                ]
              ]
            ],
            "_uuid": [
              "uuid",
              "33a289a0-1d34-4e46-a3c2-3e4066fbecc6"
            ]
            "external_ids": [
                "map",
                [
                  [
                    "attached-mac",
                    "fa:16:3e:7c:1c:4b"
                  ],
                  [
                    "iface-id",
                    "a61b7e2b-6951-488a-b4c6-6e91343960b2"
                  ],
                  [
                    "iface-status",
                    "active"
                  ]
                ]
              ]
          }
        }
      }
    }
   */
  const char *path[] = {"Interface", NULL};
  ovs_stats_inst_t *inst = user_data;
  yajl_val ports = yajl_tree_get(jupdates, path, yajl_t_object);
  pthread_mutex_lock(&inst->stats_lock);
  if (ports && YAJL_IS_OBJECT(ports))
    for (size_t i = 0; i < YAJL_GET_OBJECT(ports)->len; i++)
      ovs_stats_update_iface(inst, YAJL_GET_OBJECT(ports)->values[i]);
  pthread_mutex_unlock(&inst->stats_lock);
  return;
}

/* Handle JSON with Interface table initial values */
static void ovs_stats_interface_table_result_cb(yajl_val jresult,
                                                yajl_val jerror,
                                                void *user_data) {
  if (YAJL_IS_NULL(jerror))
    ovs_stats_interface_table_change_cb(jresult, user_data);
  else
    ERROR("%s: Error received from OvSDB. Table: Interface", plugin_name);
  return;
}

/* Setup OVS DB table callbacks  */
static void ovs_stats_conn_initialize(ovs_db_t *pdb, void *user_data) {
  const char *bridge_columns[] = {"name", "ports", NULL};
  const char *port_columns[] = {"name", "interfaces", NULL};
  const char *interface_columns[] = {"name", "statistics", "_uuid",
                                     "external_ids", NULL};

  /* subscribe to a tables */
  if (ovs_db_table_cb_register(
          pdb, "Bridge", bridge_columns, ovs_stats_bridge_table_change_cb,
          ovs_stats_bridge_table_result_cb,
          OVS_DB_TABLE_CB_FLAG_INITIAL | OVS_DB_TABLE_CB_FLAG_INSERT |
              OVS_DB_TABLE_CB_FLAG_MODIFY) != 0) {
    ERROR("%s: Register \"Bridge\" table update callback failed", plugin_name);
    return;
  }

  if (ovs_db_table_cb_register(pdb, "Bridge", bridge_columns,
                               ovs_stats_bridge_table_delete_cb, NULL,
                               OVS_DB_TABLE_CB_FLAG_DELETE) != 0) {
    ERROR("%s: Register \"Bridge\" table delete callback failed", plugin_name);
    return;
  }

  if (ovs_db_table_cb_register(
          pdb, "Port", port_columns, ovs_stats_port_table_change_cb,
          ovs_stats_port_table_result_cb,
          OVS_DB_TABLE_CB_FLAG_INITIAL | OVS_DB_TABLE_CB_FLAG_INSERT |
              OVS_DB_TABLE_CB_FLAG_MODIFY) != 0) {
    ERROR("%s: Register \"Port\" table update callback failed", plugin_name);
    return;
  }

  if (ovs_db_table_cb_register(pdb, "Port", port_columns,
                               ovs_stats_port_table_delete_cb, NULL,
                               OVS_DB_TABLE_CB_FLAG_DELETE) != 0) {
    ERROR("%s: Register \"Port\" table delete callback failed", plugin_name);
    return;
  }

  if (ovs_db_table_cb_register(pdb, "Interface", interface_columns,
                               ovs_stats_interface_table_change_cb,
                               ovs_stats_interface_table_result_cb,
                               OVS_DB_TABLE_CB_FLAG_INITIAL |
                                   OVS_DB_TABLE_CB_FLAG_INSERT |
                                   OVS_DB_TABLE_CB_FLAG_MODIFY) != 0) {
    ERROR("%s: Register \"Interface\" table update callback failed",
          plugin_name);
    return;
  }
}

/* Check if bridge is configured to be monitored in config file */
static int ovs_stats_is_monitored_bridge(ovs_stats_inst_t *inst,
                                         const char *br_name) {
  /* if no bridges are configured, return true */
  if (inst->config.monitored_bridge_list_head == NULL)
    return 1;

  /* check if given bridge exists */
  if (ovs_stats_get_bridge(inst->config.monitored_bridge_list_head, br_name) !=
      NULL)
    return 1;

  return 0;
}

/* Delete all ports from port list */
static void ovs_stats_free_port_list(port_list_t *head) {
  for (port_list_t *i = head; i != NULL;) {
    port_list_t *del = i;
    i = i->next;
    sfree(del);
  }
}

/* Delete all bridges from bridge list */
static void ovs_stats_free_bridge_list(bridge_list_t *head) {
  for (bridge_list_t *i = head; i != NULL;) {
    bridge_list_t *del = i;
    i = i->next;
    sfree(del->name);
    sfree(del);
  }
}

/* Handle OVSDB lost connection callback */
static void ovs_stats_conn_terminate(ovs_db_t *pdb, void *user_data) {
  WARNING("Lost connection to OVSDB server");
  ovs_stats_inst_t *inst = user_data;
  pthread_mutex_lock(&inst->stats_lock);
  ovs_stats_free_bridge_list(inst->bridge_list_head);
  inst->bridge_list_head = NULL;
  ovs_stats_free_port_list(inst->port_list_head);
  inst->port_list_head = NULL;
  pthread_mutex_unlock(&inst->stats_lock);
}

/* Create a new instance and add it to the plugin context */
static ovs_stats_inst_t *ovs_stats_instance_add(const char *name) {

  /* check for duplicate instance */
  if (ovs_stats_ctx.list_inst != NULL &&
      llist_search(ovs_stats_ctx.list_inst, name) != NULL)
    return NULL;

  /* create new OVS DB instances */
  ovs_stats_inst_t *inst = calloc(1, sizeof(*inst));
  if (inst == NULL)
    return NULL;

  /* add new OVS DB instance to the list */
  llentry_t *new_le = llentry_create(strdup(name), inst);
  if (new_le == NULL) {
    sfree(inst);
    return NULL;
  }
  if (ovs_stats_ctx.list_inst == NULL) {
    /* create OVS DB instances list */
    if ((ovs_stats_ctx.list_inst = llist_create()) == NULL) {
      sfree(new_le->key);
      sfree(inst);
      return NULL;
    }
  }
  llist_append(ovs_stats_ctx.list_inst, new_le);
  return inst;
}

/* Post initialization of OVS DB configuration */
static int ovs_stats_inst_post_init(ovs_stats_config_t *config) {
  if (config == NULL)
    return -1;

  /* set default configuration */
  if (config->ovs_db_node[0] == '\0')
    sstrncpy(config->ovs_db_node, OVS_STATS_DEFAULT_NODE,
             sizeof(config->ovs_db_node));
  if (config->ovs_db_serv[0] == '\0')
    sstrncpy(config->ovs_db_serv, OVS_STATS_DEFAULT_SERVICE,
             sizeof(config->ovs_db_serv));

  return 0;
}

/* Parse plugin configuration file and store the config
 * in allocated memory. Returns negative value in case of error.
 */
static int ovs_stats_get_instance_config(oconfig_item_t *ci,
                                         ovs_stats_config_t *config) {
  ovs_stats_config_t inst_conf = {{0}};
  bridge_list_t *bridge;
  char *br_name;

  /* sanity check */
  if (ci == NULL || config == NULL)
    return -1;

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("Address", child->key) == 0) {
      if (cf_util_get_string_buffer(child, inst_conf.ovs_db_node,
                                    OVS_DB_ADDR_NODE_SIZE) != 0) {
        ovs_stats_free_bridge_list(inst_conf.monitored_bridge_list_head);
        return -1;
      }
    } else if (strcasecmp("Port", child->key) == 0) {
      char *service = NULL;
      if (cf_util_get_service(child, &service) != 0) {
        ovs_stats_free_bridge_list(inst_conf.monitored_bridge_list_head);
        return -1;
      }
      strncpy(inst_conf.ovs_db_serv, service, sizeof(inst_conf.ovs_db_serv));
      sfree(service);
    } else if (strcasecmp("Socket", child->key) == 0) {
      if (cf_util_get_string_buffer(child, inst_conf.ovs_db_unix,
                                    OVS_DB_ADDR_UNIX_SIZE) != 0) {
        ovs_stats_free_bridge_list(inst_conf.monitored_bridge_list_head);
        return -1;
      }
    } else if (strcasecmp("Bridges", child->key) == 0) {
      for (int j = 0; j < child->values_num; j++) {
        /* check value type */
        if (child->values[j].type != OCONFIG_TYPE_STRING) {
          ERROR("%s: Wrong bridge name [idx=%d]. "
                "Bridge name should be string",
                plugin_name, j);
          ovs_stats_free_bridge_list(inst_conf.monitored_bridge_list_head);
          return -1;
        }
        /* get value */
        if ((br_name = strdup(child->values[j].value.string)) == NULL) {
          ERROR("%s: strdup() copy bridge name fail", plugin_name);
          ovs_stats_free_bridge_list(inst_conf.monitored_bridge_list_head);
          return -1;
        }
        if ((bridge = ovs_stats_get_bridge(inst_conf.monitored_bridge_list_head,
                                           br_name)) == NULL) {
          if ((bridge = calloc(1, sizeof(*bridge))) == NULL) {
            ERROR("%s: Error allocating memory for bridge", plugin_name);
            ovs_stats_free_bridge_list(inst_conf.monitored_bridge_list_head);
            return -1;
          } else {
            /* store bridge name */
            bridge->name = br_name;
            bridge->next = inst_conf.monitored_bridge_list_head;
            inst_conf.monitored_bridge_list_head = bridge;
            DEBUG("%s: found monitored interface \"%s\"", plugin_name, br_name);
          }
        }
      }
    } else {
      WARNING("%s: option '%s' not allowed here", plugin_name, child->key);
      ovs_stats_free_bridge_list(inst_conf.monitored_bridge_list_head);
      return -1;
    }
  }
  /* set default configuration */
  if (ovs_stats_inst_post_init(&inst_conf) < 0) {
    ovs_stats_free_bridge_list(inst_conf.monitored_bridge_list_head);
    ERROR("%s: Error to set default configuration", plugin_name);
    return -1;
  }
  *config = inst_conf;
  return 0;
}

/* Release memory allocated for OvS context */
static void ovs_stats_context_free() {
  for (llentry_t *inst_le = llist_head(ovs_stats_ctx.list_inst);
       inst_le != NULL; inst_le = inst_le->next) {
    ovs_stats_inst_t *inst = inst_le->value;
    ovs_stats_free_bridge_list(inst->bridge_list_head);
    ovs_stats_free_bridge_list(inst->config.monitored_bridge_list_head);
    ovs_stats_free_port_list(inst->port_list_head);
    pthread_mutex_destroy(&inst->stats_lock);
    sfree(inst_le->key);
    sfree(inst);
  }
  llist_destroy(ovs_stats_ctx.list_inst);
  ovs_stats_ctx.list_inst = NULL;
}

/* Parse plugin configuration file and store the config
 * in allocated memory. Returns negative value in case of error.
 */
static int ovs_stats_plugin_config(oconfig_item_t *ci) {
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("Instance", child->key) == 0) {
      char inst_name[DATA_MAX_NAME_LEN];
      /* get the instance name */
      if (cf_util_get_string_buffer(child, inst_name, sizeof(inst_name)) != 0) {
        ERROR("%s: parse OVS DB instance name failed", plugin_name);
        ovs_stats_context_free();
        return -1;
      }
      /* create new instance */
      ovs_stats_inst_t *inst = ovs_stats_instance_add(inst_name);
      if (inst == NULL) {
        ERROR("%s: %s: Create new OVS DB instance failed "
              "or the instance already exists",
              plugin_name, inst_name);
        ovs_stats_context_free();
        return -1;
      }
      /* parse OVS instance configuration */
      if (ovs_stats_get_instance_config(child, &inst->config)) {
        ERROR("%s: parse OVS DB instance failed", plugin_name);
        ovs_stats_context_free();
        return -1;
      }
      strncpy(inst->name, inst_name, sizeof(inst->name));
    } else {
      WARNING("%s: option '%s' not allowed here", plugin_name, child->key);
      ovs_stats_context_free();
      return -1;
    }
  }
  return 0;
}

/* Add default OVS DB instance configuration */
static int ovs_stats_inst_add_default() {

  /* create new instance */
  ovs_stats_inst_t *inst = ovs_stats_instance_add(hostname_g);
  if (inst == NULL)
    return -1;

  /* set default configuration */
  if (ovs_stats_inst_post_init(&inst->config) < 0)
    return -1;

  /* set instance and read register callback names */
  strncpy(inst->name, hostname_g, sizeof(inst->name));
  return 0;
}

/* Initialize OvS Stats plugin*/
static int ovs_stats_plugin_init(void) {
  size_t inst_num = llist_size(ovs_stats_ctx.list_inst);
  ovs_db_inst_t insts[inst_num ? inst_num : 1];

  /* if no instance configuration is provided, add default one */
  if (!inst_num) {
    DEBUG("Adding default OVS DB configuration");
    if (ovs_stats_inst_add_default() < 0) {
      ERROR("%s: add default OVS DB instance configuration failed",
            plugin_name);
      ovs_stats_context_free();
      return -1;
    }
  }
  /* fill the OVS DB information */
  size_t index = 0;
  for (llentry_t *le = llist_head(ovs_stats_ctx.list_inst); le != NULL;
       le = le->next, index++) {
    ovs_stats_inst_t *inst = le->value;
    INFO("%s: Connecting to OVS DB using instance=%s, address=%s, service=%s, "
         "unix=%s",
         plugin_name, le->key, inst->config.ovs_db_node,
         inst->config.ovs_db_serv, inst->config.ovs_db_unix);
    /* init OVS DB instance lock */
    int err = pthread_mutex_init(&inst->stats_lock, NULL);
    if (err < 0) {
      ERROR("%s: plugin: failed to initialize cache lock", plugin_name);
      ovs_stats_context_free();
      return -1;
    }
    /* prepare arguments for OVS DB instance */
    strncpy(insts[index].unix_path, inst->config.ovs_db_unix,
            sizeof(insts[index].unix_path));
    strncpy(insts[index].service, inst->config.ovs_db_serv,
            sizeof(insts[index].service));
    strncpy(insts[index].node, inst->config.ovs_db_node,
            sizeof(insts[index].node));

    insts[index].cb.post_conn_init = ovs_stats_conn_initialize;
    insts[index].cb.post_conn_terminate = ovs_stats_conn_terminate;
    insts[index].user_data.free_func = NULL;
    insts[index].user_data.data = inst;
  }
  /* connect to OvS DB */
  ovs_t *ovs_obj = ovs_init(insts, STATIC_ARRAY_SIZE(insts));
  if (ovs_obj == NULL) {
    ERROR("%s: plugin: failed to connect to OvS DB server", plugin_name);
    ovs_stats_context_free();
    return -1;
  }
  ovs_stats_ctx.ovs_obj = ovs_obj;
  return 0;
}

/* Read OvS stats from specified instance.
 * Read bridge/port information and submit it */
static int ovs_stats_inst_read(ovs_stats_inst_t *inst) {
  bridge_list_t *bridge;
  port_list_t *port;
  char devname[PORT_NAME_SIZE_MAX * 2];

  pthread_mutex_lock(&inst->stats_lock);
  for (bridge = inst->bridge_list_head; bridge != NULL; bridge = bridge->next) {
    if (ovs_stats_is_monitored_bridge(inst, bridge->name)) {
      for (port = inst->port_list_head; port != NULL; port = port->next)
        if (port->br == bridge) {
          if (strlen(port->name) == 0)
            /* Skip port w/o name. This is possible when read callback
             * is called after Interface Table update callback but before
             * Port table Update callback. Will add this port on next read */
            continue;
          meta_data_t *meta = meta_data_create();
          if (meta != NULL) {
            meta_data_add_string(meta, "uuid", port->iface_uuid);
            if (strlen(port->ex_vm_id))
              meta_data_add_string(meta, "vm-uuid", port->ex_vm_id);
            if (strlen(port->ex_iface_id))
              meta_data_add_string(meta, "iface-id", port->ex_iface_id);
          }
          snprintf(devname, sizeof(devname), "%s.%s", bridge->name, port->name);
          ovs_stats_submit_one(inst->name, devname, "if_collisions", NULL,
                               port->stats[collisions], meta);
          ovs_stats_submit_two(inst->name, devname, "if_dropped", NULL,
                               port->stats[rx_dropped], port->stats[tx_dropped],
                               meta);
          ovs_stats_submit_two(inst->name, devname, "if_errors", NULL,
                               port->stats[rx_errors], port->stats[tx_errors],
                               meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets", NULL,
                               port->stats[rx_packets], port->stats[tx_packets],
                               meta);
          ovs_stats_submit_one(inst->name, devname, "if_rx_errors", "crc",
                               port->stats[rx_crc_err], meta);
          ovs_stats_submit_one(inst->name, devname, "if_rx_errors", "frame",
                               port->stats[rx_frame_err], meta);
          ovs_stats_submit_one(inst->name, devname, "if_rx_errors", "over",
                               port->stats[rx_over_err], meta);
          ovs_stats_submit_one(inst->name, devname, "if_rx_octets", NULL,
                               port->stats[rx_bytes], meta);
          ovs_stats_submit_one(inst->name, devname, "if_tx_octets", NULL,
                               port->stats[tx_bytes], meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets",
                               "1_to_64_packets",
                               port->stats[rx_1_to_64_packets],
                               port->stats[tx_1_to_64_packets], meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets",
                               "65_to_127_packets",
                               port->stats[rx_65_to_127_packets],
                               port->stats[tx_65_to_127_packets], meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets",
                               "128_to_255_packets",
                               port->stats[rx_128_to_255_packets],
                               port->stats[tx_128_to_255_packets], meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets",
                               "256_to_511_packets",
                               port->stats[rx_256_to_511_packets],
                               port->stats[tx_256_to_511_packets], meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets",
                               "512_to_1023_packets",
                               port->stats[rx_512_to_1023_packets],
                               port->stats[tx_512_to_1023_packets], meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets",
                               "1024_to_1518_packets",
                               port->stats[rx_1024_to_1522_packets],
                               port->stats[tx_1024_to_1522_packets], meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets",
                               "1523_to_max_packets",
                               port->stats[rx_1523_to_max_packets],
                               port->stats[tx_1523_to_max_packets], meta);
          ovs_stats_submit_two(inst->name, devname, "if_packets",
                               "broadcast_packets",
                               port->stats[rx_broadcast_packets],
                               port->stats[tx_broadcast_packets], meta);
          ovs_stats_submit_one(inst->name, devname, "if_multicast",
                               "tx_multicast_packets",
                               port->stats[tx_multicast_packets], meta);
          ovs_stats_submit_one(inst->name, devname, "if_rx_errors",
                               "rx_undersized_errors",
                               port->stats[rx_undersized_errors], meta);
          ovs_stats_submit_one(inst->name, devname, "if_rx_errors",
                               "rx_oversize_errors",
                               port->stats[rx_oversize_errors], meta);
          ovs_stats_submit_one(inst->name, devname, "if_rx_errors",
                               "rx_fragmented_errors",
                               port->stats[rx_fragmented_errors], meta);
          ovs_stats_submit_one(inst->name, devname, "if_rx_errors",
                               "rx_jabber_errors",
                               port->stats[rx_jabber_errors], meta);

          meta_data_destroy(meta);
        }
    } else
      continue;
  }
  pthread_mutex_unlock(&inst->stats_lock);
  return 0;
}

/* OvS stats read callback. Read bridge/port information and submit it*/
static int ovs_stats_plugin_read(__attribute__((unused)) user_data_t *ud) {
  for (llentry_t *inst_le = llist_head(ovs_stats_ctx.list_inst);
       inst_le != NULL; inst_le = inst_le->next) {
    ovs_stats_inst_t *inst = inst_le->value;
    ovs_stats_inst_read(inst);
  }
  return 0;
}

/* Shutdown OvS Stats plugin */
static int ovs_stats_plugin_shutdown(void) {
  DEBUG("OvS Statistics plugin shutting down");
  ovs_destroy(ovs_stats_ctx.ovs_obj);
  ovs_stats_context_free();
  return 0;
}

/* Register OvS Stats plugin callbacks */
void module_register(void) {
  plugin_register_complex_config(plugin_name, ovs_stats_plugin_config);
  plugin_register_init(plugin_name, ovs_stats_plugin_init);
  plugin_register_complex_read(NULL, plugin_name, ovs_stats_plugin_read, 0,
                               NULL);
  plugin_register_shutdown(plugin_name, ovs_stats_plugin_shutdown);
}
