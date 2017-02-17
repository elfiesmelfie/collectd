/*
 * collectd - src/mcelog.c
 * MIT License
 *
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.

 * Authors:
 *   Maryam Tahhan <maryam.tahhan@intel.com>
 *   Volodymyr Mytnyk <volodymyrx.mytnyk@intel.com>
 *   Taras Chornyi <tarasx.chornyi@intel.com>
 *   Krzysztof Matczak <krzysztofx.matczak@intel.com>
 */

#include "collectd.h"
#include "common.h"
#include "utils_message_parser.h"

#include <poll.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MCELOG_PLUGIN "mcelog"
#define MCELOG_BUFF_SIZE 1024
#define MCELOG_POLL_TIMEOUT 1000 /* ms */

#define MCELOG_SOCKET_STR "SOCKET"
#define MCELOG_SOCKET_DIMM_NAME "DMI_NAME"
#define MCELOG_SOCKET_CORR_ERR "corrected memory errors"
#define MCELOG_SOCKET_UNCORR_ERR "uncorrected memory errors"

#define MCELOG_LOG_CORR_ERR "Corrected error"
#define MCELOG_LOG_UNCORR_ERR "Uncorrected error"
#define MCELOG_LOG_TIME "TIME"
#define MCELOG_LOG_ORIGIN "ORIGIN"

typedef struct mcelog_config_s {
  char logfile[PATH_MAX]; /* mcelog logfile */
  pthread_t tid;          /* poll thread id */
  message_pattern *msg_patterns;
  unsigned int msg_patterns_len;
  _Bool full_read_done;
  _Bool read_socket;
  _Bool read_log;
} mcelog_config_t;

typedef struct socket_adapter_s socket_adapter_t;

struct socket_adapter_s {
  int sock_fd;                  /* mcelog server socket fd */
  struct sockaddr_un unix_sock; /* mcelog client socket */
  pthread_rwlock_t lock;
  /* function pointers for socket operations */
  int (*write)(socket_adapter_t *self, const char *msg, const size_t len);
  int (*reinit)(socket_adapter_t *self);
  int (*receive)(socket_adapter_t *self, FILE **p_file);
  int (*close)(socket_adapter_t *self);
};

typedef struct mcelog_memory_rec_s {
  int corrected_err_total; /* x total*/
  int corrected_err_timed; /* x in 24h*/
  char corrected_err_timed_period[DATA_MAX_NAME_LEN];
  int uncorrected_err_total; /* x total*/
  int uncorrected_err_timed; /* x in 24h*/
  char uncorrected_err_timed_period[DATA_MAX_NAME_LEN];
  char location[DATA_MAX_NAME_LEN];  /* SOCKET x CHANNEL x DIMM x*/
  char dimm_name[DATA_MAX_NAME_LEN]; /* DMI_NAME "DIMM_F1" */
} mcelog_memory_rec_t;

static int socket_close(socket_adapter_t *self);
static int socket_write(socket_adapter_t *self, const char *msg,
                        const size_t len);
static int socket_reinit(socket_adapter_t *self);
static int socket_receive(socket_adapter_t *self, FILE **p_file);

static mcelog_config_t g_mcelog_config = {0};

static socket_adapter_t socket_adapter = {
    .sock_fd = -1,
    .unix_sock =
        {
            .sun_family = AF_UNIX, .sun_path = "",
        },
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .close = socket_close,
    .write = socket_write,
    .reinit = socket_reinit,
    .receive = socket_receive,
};

static _Bool mcelog_thread_running;

static parser_job_data *parser_job = NULL;

static int mcelog_config_msg_patterns(oconfig_item_t *match_opt, int num) {

  for (unsigned int n = 0; n < num; n++) {

    if (strcasecmp("Match", match_opt[n].key) == 0) {
      /* set default submatch index to 1 since single submatch is the most
       * common use case */
      g_mcelog_config.msg_patterns[n].submatch_idx = 1;
      for (int i = 0; i < match_opt[n].children_num; i++) {
        int status = 0;
        oconfig_item_t *regex_opt = match_opt[n].children + i;
        if (strcasecmp("Name", regex_opt->key) == 0)
          status = cf_util_get_string(regex_opt,
                                      &(g_mcelog_config.msg_patterns[n].name));
        else if (strcasecmp("Regex", regex_opt->key) == 0)
          status = cf_util_get_string(regex_opt,
                                      &(g_mcelog_config.msg_patterns[n].regex));
        else if (strcasecmp("SubmatchIdx", regex_opt->key) == 0)
          status = cf_util_get_int(
              regex_opt, &(g_mcelog_config.msg_patterns[n].submatch_idx));
        else if (strcasecmp("Excluderegex", regex_opt->key) == 0)
          status = cf_util_get_string(
              regex_opt, &(g_mcelog_config.msg_patterns[n].excluderegex));
        else if (strcasecmp("IsMandatory", regex_opt->key) == 0)
          status = cf_util_get_boolean(
              regex_opt, &(g_mcelog_config.msg_patterns[n].is_mandatory));

        if (status != 0) {
          ERROR(MCELOG_PLUGIN ": Error setting regex option %s",
                regex_opt->key);
          return (-1);
        }
      }
    } else {
      ERROR(MCELOG_PLUGIN ": option `%s' not allowed here.", match_opt[n].key);
      return (-1);
    }
  }

  return (0);
}

static int mcelog_config(oconfig_item_t *ci) {
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("McelogClientSocket", child->key) == 0) {
      if (cf_util_get_string_buffer(child, socket_adapter.unix_sock.sun_path,
                                    sizeof(socket_adapter.unix_sock.sun_path)) <
          0) {
        ERROR(MCELOG_PLUGIN ": Invalid configuration option: \"%s\".",
              child->key);
        return (-1);
      }
      g_mcelog_config.read_socket = 1;
    } else if (strcasecmp("McelogLogfile", child->key) == 0) {
      if (cf_util_get_string_buffer(child, g_mcelog_config.logfile,
                                    sizeof(g_mcelog_config.logfile)) < 0) {
        ERROR(MCELOG_PLUGIN ": Invalid configuration option: \"%s\".",
              child->key);
        return (-1);
      }
      g_mcelog_config.msg_patterns_len = child->children_num;
      g_mcelog_config.msg_patterns =
          calloc(g_mcelog_config.msg_patterns_len,
                 sizeof(*(g_mcelog_config.msg_patterns)));
      if (g_mcelog_config.msg_patterns == NULL) {
        ERROR(MCELOG_PLUGIN ": Error allocating message_patterns");
        return (-1);
      }
      if (mcelog_config_msg_patterns(child->children, child->children_num)) {
        ERROR(MCELOG_PLUGIN ": Failed to parse 'Match' configuration element");
        return (-1);
      }

      g_mcelog_config.read_log = 1;
    } else {
      ERROR(MCELOG_PLUGIN ": Invalid configuration option: \"%s\".",
            child->key);
      return (-1);
    }
  }
  return (0);
}

static int socket_close(socket_adapter_t *self) {
  int ret = 0;
  pthread_rwlock_rdlock(&self->lock);
  if (fcntl(self->sock_fd, F_GETFL) != -1) {
    char errbuf[MCELOG_BUFF_SIZE];
    if (shutdown(self->sock_fd, SHUT_RDWR) != 0) {
      ERROR(MCELOG_PLUGIN ": Socket shutdown failed: %s",
            sstrerror(errno, errbuf, sizeof(errbuf)));
      ret = -1;
    }
    if (close(self->sock_fd) != 0) {
      ERROR(MCELOG_PLUGIN ": Socket close failed: %s",
            sstrerror(errno, errbuf, sizeof(errbuf)));
      ret = -1;
    }
  }
  pthread_rwlock_unlock(&self->lock);
  return (ret);
}

static int socket_write(socket_adapter_t *self, const char *msg,
                        const size_t len) {
  int ret = 0;
  pthread_rwlock_rdlock(&self->lock);
  if (swrite(self->sock_fd, msg, len) < 0)
    ret = -1;
  pthread_rwlock_unlock(&self->lock);
  return (ret);
}

static void mcelog_dispatch_notification(notification_t *n) {
  if (!n) {
    ERROR(MCELOG_PLUGIN ": %s: NULL pointer", __FUNCTION__);
    return;
  }

  sstrncpy(n->host, hostname_g, sizeof(n->host));
  sstrncpy(n->type, "gauge", sizeof(n->type));
  plugin_dispatch_notification(n);
  if (n->meta)
    plugin_notification_meta_free(n->meta);
}

static int socket_reinit(socket_adapter_t *self) {
  char errbuff[MCELOG_BUFF_SIZE];
  int ret = -1;
  cdtime_t interval = plugin_get_interval();
  struct timeval socket_timeout = CDTIME_T_TO_TIMEVAL(interval);

  /* synchronization via write lock since sock_fd may be changed here */
  pthread_rwlock_wrlock(&self->lock);
  self->sock_fd =
      socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (self->sock_fd < 0) {
    ERROR(MCELOG_PLUGIN ": Could not create a socket. %s",
          sstrerror(errno, errbuff, sizeof(errbuff)));
    pthread_rwlock_unlock(&self->lock);
    return (ret);
  }

  /* Set socket timeout option */
  if (setsockopt(self->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &socket_timeout,
                 sizeof(socket_timeout)) < 0)
    ERROR(MCELOG_PLUGIN ": Failed to set the socket timeout option.");

  /* downgrading to read lock due to possible recursive read locks
   * in self->close(self) call */
  pthread_rwlock_unlock(&self->lock);
  pthread_rwlock_rdlock(&self->lock);
  if (connect(self->sock_fd, (struct sockaddr *)&(self->unix_sock),
              sizeof(self->unix_sock)) < 0) {
    ERROR(MCELOG_PLUGIN ": Failed to connect to mcelog server. %s",
          sstrerror(errno, errbuff, sizeof(errbuff)));
    self->close(self);
    ret = -1;
  } else {
    ret = 0;
    mcelog_dispatch_notification(
        &(notification_t){.severity = NOTIF_OKAY,
                          .time = cdtime(),
                          .message = "Connected to mcelog server",
                          .plugin = MCELOG_PLUGIN,
                          .type_instance = "mcelog_status"});
  }
  pthread_rwlock_unlock(&self->lock);
  return (ret);
}

static int mcelog_mem_rec_to_notif(notification_t *n,
                                   const mcelog_memory_rec_t *mr) {
  if (n == NULL || mr == NULL)
    return (-1);

  if ((mr->location[0] != '\0') &&
      (plugin_notification_meta_add_string(n, MCELOG_SOCKET_STR, mr->location) <
       0)) {
    ERROR(MCELOG_PLUGIN ": add memory location meta data failed");
    return (-1);
  }
  if ((mr->dimm_name[0] != '\0') &&
      (plugin_notification_meta_add_string(n, MCELOG_SOCKET_DIMM_NAME,
                                           mr->dimm_name) < 0)) {
    ERROR(MCELOG_PLUGIN ": add DIMM name meta data failed");
    plugin_notification_meta_free(n->meta);
    return (-1);
  }
  if (plugin_notification_meta_add_signed_int(n, MCELOG_SOCKET_CORR_ERR,
                                              mr->corrected_err_total) < 0) {
    ERROR(MCELOG_PLUGIN ": add corrected errors meta data failed");
    plugin_notification_meta_free(n->meta);
    return (-1);
  }
  if (plugin_notification_meta_add_signed_int(
          n, "corrected memory timed errors", mr->corrected_err_timed) < 0) {
    ERROR(MCELOG_PLUGIN ": add corrected timed errors meta data failed");
    plugin_notification_meta_free(n->meta);
    return (-1);
  }
  if ((mr->corrected_err_timed_period[0] != '\0') &&
      (plugin_notification_meta_add_string(n, "corrected errors time period",
                                           mr->corrected_err_timed_period) <
       0)) {
    ERROR(MCELOG_PLUGIN ": add corrected errors period meta data failed");
    plugin_notification_meta_free(n->meta);
    return (-1);
  }
  if (plugin_notification_meta_add_signed_int(n, MCELOG_SOCKET_UNCORR_ERR,
                                              mr->uncorrected_err_total) < 0) {
    ERROR(MCELOG_PLUGIN ": add uncorrected errors meta data failed");
    plugin_notification_meta_free(n->meta);
    return (-1);
  }
  if (plugin_notification_meta_add_signed_int(n,
                                              "uncorrected memory timed errors",
                                              mr->uncorrected_err_timed) < 0) {
    ERROR(MCELOG_PLUGIN ": add uncorrected timed errors meta data failed");
    plugin_notification_meta_free(n->meta);
    return (-1);
  }
  if ((mr->uncorrected_err_timed_period[0] != '\0') &&
      (plugin_notification_meta_add_string(n, "uncorrected errors time period",
                                           mr->uncorrected_err_timed_period) <
       0)) {
    ERROR(MCELOG_PLUGIN ": add corrected errors period meta data failed");
    plugin_notification_meta_free(n->meta);
    return (-1);
  }
  return (0);
}

static int mcelog_submit(const mcelog_memory_rec_t *mr) {

  if (!mr) {
    ERROR(MCELOG_PLUGIN ": %s: NULL pointer", __FUNCTION__);
    return (-1);
  }

  value_list_t vl = {
      .values_len = 1,
      .values = &(value_t){.derive = (derive_t)mr->corrected_err_total},
      .time = cdtime(),
      .plugin = MCELOG_PLUGIN,
      .type = "errors",
      .type_instance = "corrected_memory_errors"};

  if (mr->dimm_name[0] != '\0')
    ssnprintf(vl.plugin_instance, sizeof(vl.plugin_instance), "%s_%s",
              mr->location, mr->dimm_name);
  else
    sstrncpy(vl.plugin_instance, mr->location, sizeof(vl.plugin_instance));

  plugin_dispatch_values(&vl);

  ssnprintf(vl.type_instance, sizeof(vl.type_instance),
            "corrected_memory_errors_in_%s", mr->corrected_err_timed_period);
  vl.values = &(value_t){.derive = (derive_t)mr->corrected_err_timed};
  plugin_dispatch_values(&vl);

  sstrncpy(vl.type_instance, "uncorrected_memory_errors",
           sizeof(vl.type_instance));
  vl.values = &(value_t){.derive = (derive_t)mr->uncorrected_err_total};
  plugin_dispatch_values(&vl);

  ssnprintf(vl.type_instance, sizeof(vl.type_instance),
            "uncorrected_memory_errors_in_%s",
            mr->uncorrected_err_timed_period);
  vl.values = &(value_t){.derive = (derive_t)mr->uncorrected_err_timed};
  plugin_dispatch_values(&vl);

  return (0);
}

static int parse_memory_info(FILE *p_file, mcelog_memory_rec_t *memory_record) {
  char buf[DATA_MAX_NAME_LEN] = {0};
  while (fgets(buf, sizeof(buf), p_file)) {
    /* Got empty line or "done" */
    if ((!strncmp("\n", buf, strlen(buf))) ||
        (!strncmp(buf, "done\n", strlen(buf))))
      return (1);
    if (strlen(buf) < 5)
      continue;
    if (!strncmp(buf, MCELOG_SOCKET_STR, strlen(MCELOG_SOCKET_STR))) {
      sstrncpy(memory_record->location, buf, strlen(buf));
      /* replace spaces with '_' */
      for (size_t i = 0; i < strlen(memory_record->location); i++)
        if (memory_record->location[i] == ' ')
          memory_record->location[i] = '_';
      DEBUG(MCELOG_PLUGIN ": Got SOCKET INFO %s", memory_record->location);
    }
    if (!strncmp(buf, MCELOG_SOCKET_DIMM_NAME,
                 strlen(MCELOG_SOCKET_DIMM_NAME))) {
      char *name = NULL;
      char *saveptr = NULL;
      name = strtok_r(buf, "\"", &saveptr);
      if (name != NULL && saveptr != NULL) {
        name = strtok_r(NULL, "\"", &saveptr);
        if (name != NULL) {
          sstrncpy(memory_record->dimm_name, name,
                   sizeof(memory_record->dimm_name));
          DEBUG(MCELOG_PLUGIN ": Got DIMM NAME %s", memory_record->dimm_name);
        }
      }
    }
    if (!strncmp(buf, MCELOG_SOCKET_CORR_ERR, strlen(MCELOG_SOCKET_CORR_ERR))) {
      /* Get next line*/
      if (fgets(buf, sizeof(buf), p_file) != NULL) {
        sscanf(buf, "\t%d total", &(memory_record->corrected_err_total));
        DEBUG(MCELOG_PLUGIN ": Got corrected error total %d",
              memory_record->corrected_err_total);
      }
      if (fgets(buf, sizeof(buf), p_file) != NULL) {
        sscanf(buf, "\t%d in %s", &(memory_record->corrected_err_timed),
               memory_record->corrected_err_timed_period);
        DEBUG(MCELOG_PLUGIN ": Got timed corrected errors %d in %s",
              memory_record->corrected_err_total,
              memory_record->corrected_err_timed_period);
      }
    }
    if (!strncmp(buf, MCELOG_SOCKET_UNCORR_ERR,
                 strlen(MCELOG_SOCKET_UNCORR_ERR))) {
      if (fgets(buf, sizeof(buf), p_file) != NULL) {
        sscanf(buf, "\t%d total", &(memory_record->uncorrected_err_total));
        DEBUG(MCELOG_PLUGIN ": Got uncorrected error total %d",
              memory_record->uncorrected_err_total);
      }
      if (fgets(buf, sizeof(buf), p_file) != NULL) {
        sscanf(buf, "\t%d in %s", &(memory_record->uncorrected_err_timed),
               memory_record->uncorrected_err_timed_period);
        DEBUG(MCELOG_PLUGIN ": Got timed uncorrected errors %d in %s",
              memory_record->uncorrected_err_total,
              memory_record->uncorrected_err_timed_period);
      }
    }
    memset(buf, 0, sizeof(buf));
  }
  /* parsing definitely finished */
  return (0);
}

static void poll_worker_cleanup(void *arg) {
  mcelog_thread_running = 0;
  FILE *p_file = *((FILE **)arg);
  if (p_file != NULL)
    fclose(p_file);
  free(arg);
}

static int socket_receive(socket_adapter_t *self, FILE **pp_file) {
  int res = -1;
  pthread_rwlock_rdlock(&self->lock);
  struct pollfd poll_fd = {
      .fd = self->sock_fd, .events = POLLIN | POLLPRI,
  };

  if ((res = poll(&poll_fd, 1, MCELOG_POLL_TIMEOUT)) <= 0) {
    if (res != 0 && errno != EINTR) {
      char errbuf[MCELOG_BUFF_SIZE];
      ERROR(MCELOG_PLUGIN ": poll failed: %s",
            sstrerror(errno, errbuf, sizeof(errbuf)));
    }
    pthread_rwlock_unlock(&self->lock);
    return (res);
  }

  if (poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
    /* connection is broken */
    ERROR(MCELOG_PLUGIN ": Connection to socket is broken");
    if (poll_fd.revents & (POLLERR | POLLHUP)) {
      mcelog_dispatch_notification(
          &(notification_t){.severity = NOTIF_FAILURE,
                            .time = cdtime(),
                            .message = "Connection to mcelog socket is broken.",
                            .plugin = MCELOG_PLUGIN,
                            .type_instance = "mcelog_status"});
    }
    pthread_rwlock_unlock(&self->lock);
    return (-1);
  }

  if (!(poll_fd.revents & (POLLIN | POLLPRI))) {
    INFO(MCELOG_PLUGIN ": No data to read");
    pthread_rwlock_unlock(&self->lock);
    return (0);
  }

  if ((*pp_file = fdopen(dup(self->sock_fd), "r")) == NULL)
    res = -1;

  pthread_rwlock_unlock(&self->lock);
  return (res);
}

static void *poll_worker(__attribute__((unused)) void *arg) {
  char errbuf[MCELOG_BUFF_SIZE];
  mcelog_thread_running = 1;
  FILE **pp_file = calloc(1, sizeof(FILE *));
  if (pp_file == NULL) {
    ERROR(MCELOG_PLUGIN ": memory allocation failed: %s",
          sstrerror(errno, errbuf, sizeof(errbuf)));
    pthread_exit((void *)1);
  }

  pthread_cleanup_push(poll_worker_cleanup, pp_file);

  while (1) {
    /* blocking call */
    int res = socket_adapter.receive(&socket_adapter, pp_file);
    if (res < 0) {
      socket_adapter.close(&socket_adapter);
      while (socket_adapter.reinit(&socket_adapter) != 0) {
        nanosleep(&CDTIME_T_TO_TIMESPEC(MS_TO_CDTIME_T(MCELOG_POLL_TIMEOUT)),
                  NULL);
      }
      continue;
    }
    /* timeout or no data to read */
    else if (res == 0)
      continue;

    if (*pp_file == NULL)
      continue;

    mcelog_memory_rec_t memory_record = {0};
    while (parse_memory_info(*pp_file, &memory_record)) {
      /* Check if location was successfully parsed */
      if (memory_record.location[0] == '\0') {
        memset(&memory_record, 0, sizeof(memory_record));
        continue;
      }

      notification_t n = {.severity = NOTIF_OKAY,
                          .time = cdtime(),
                          .message = "Got memory errors info.",
                          .plugin = MCELOG_PLUGIN,
                          .type_instance = "memory_errors"};

      if (mcelog_mem_rec_to_notif(&n, &memory_record) == 0)
        mcelog_dispatch_notification(&n);
      if (mcelog_submit(&memory_record) != 0)
        ERROR(MCELOG_PLUGIN ": Failed to submit memory errors");
      memset(&memory_record, 0, sizeof(memory_record));
    }

    fclose(*pp_file);
    *pp_file = NULL;
  }

  mcelog_thread_running = 0;
  pthread_cleanup_pop(1);
  return (NULL);
}

static int mcelog_init(void) {
  if (g_mcelog_config.read_log) {
    parser_job = message_parser_init(
        g_mcelog_config.logfile, 0, g_mcelog_config.msg_patterns_len - 1,
        g_mcelog_config.msg_patterns, g_mcelog_config.msg_patterns_len);
    if (parser_job == NULL) {
      ERROR(MCELOG_PLUGIN ": Failed to initialize message parser");
      return (-1);
    }
  }
  /* parse memory related aggregated MCE from mcelog socket */
  if (g_mcelog_config.read_socket) {
    if (socket_adapter.reinit(&socket_adapter) != 0) {
      ERROR(MCELOG_PLUGIN ": Cannot connect to client socket");
      return (-1);
    }
    if (plugin_thread_create(&g_mcelog_config.tid, NULL, poll_worker, NULL,
                             NULL) != 0) {
      ERROR(MCELOG_PLUGIN ": Error creating poll thread.");
      return (-1);
    }
  }
  return (0);
}

static int get_memory_machine_checks(void) {
  static const char dump[] = "dump all bios\n";
  int ret = socket_adapter.write(&socket_adapter, dump, sizeof(dump));
  if (ret != 0)
    ERROR(MCELOG_PLUGIN ": SENT DUMP REQUEST FAILED");
  else
    DEBUG(MCELOG_PLUGIN ": SENT DUMP REQUEST OK");
  return (ret);
}

static int mcelog_process_msg_item(const message_item *item,
                                   notification_t *n) {
  /* set plugin_instance to origin if available */
  if (strncmp(item->name, MCELOG_LOG_ORIGIN, strlen(MCELOG_LOG_ORIGIN)) == 0) {
    sstrncpy(n->plugin_instance, item->value, sizeof(n->plugin_instance));
    char *c;
    while ((c = strchr(n->plugin_instance, ' ')) != NULL)
      *c = '_';

    return (0);
  }

  /* replace collectd timestamp with MCE provided one if available */
  if (strncmp(item->name, MCELOG_LOG_TIME, strlen(MCELOG_LOG_TIME)) == 0) {
    unsigned long tm = strtoull(item->value, NULL, 0);
    n->time = MS_TO_CDTIME_T(tm * 1000);
    return (0);
  }

  /* decrease severity and set relevant type_instance for corrected errors */
  if (strncmp(item->value, MCELOG_LOG_CORR_ERR, strlen(MCELOG_LOG_CORR_ERR)) ==
      0) {
    n->severity = NOTIF_WARNING;
    sstrncpy(n->type_instance, MCELOG_LOG_CORR_ERR, sizeof(n->type_instance));
  }

  if (plugin_notification_meta_add_string(n, item->name, item->value) < 0) {
    ERROR(MCELOG_PLUGIN ": Failure while adding notification meta data %s:%s",
          item->name, item->value);
    return (-1);
  }

  return (0);
}

static int mcelog_message_to_notif(notification_t *n, int max_item_no,
                                   const message *msg) {
  if (msg == NULL) {
    ERROR(MCELOG_PLUGIN ": Invalid message pointer");
    return (-1);
  }

  for (int j = 0; j < max_item_no; j++) {
    if (!(msg->message_items[j].value[0]))
      break;

    if (mcelog_process_msg_item(&msg->message_items[j], n) != 0) {
      ERROR(MCELOG_PLUGIN ": Failed to process message item");
      if (n->meta)
        plugin_notification_meta_free(n->meta);
      return (-1);
    }
  }

  /* Check if MCE origin was found */
  if (n->plugin_instance[0] == '\0')
    sstrncpy(n->plugin_instance, "other", sizeof(n->plugin_instance));

  return (0);
}

static int mcelog_read(__attribute__((unused)) user_data_t *ud) {
  if (g_mcelog_config.read_log) {
    message *messages_storage;
    if (!g_mcelog_config.full_read_done) {
      INFO(MCELOG_PLUGIN ": First read of %s. Starting full scan",
           g_mcelog_config.logfile);
    }
    int no_of_mce = message_parser_read(parser_job, &messages_storage,
                                        !g_mcelog_config.full_read_done);
    g_mcelog_config.full_read_done = 1;
    DEBUG(MCELOG_PLUGIN ": No of parsed MCE:%d", no_of_mce);
    unsigned int max_item_no =
        STATIC_ARRAY_SIZE(messages_storage[0].message_items);
    for (int i = 0; i < no_of_mce; i++) {
      /* dispatching  MCE's only as notifictions */
      notification_t n = {.severity = NOTIF_FAILURE,
                          .time = cdtime(),
                          .message = "Got Machine Check Exception.",
                          .plugin = MCELOG_PLUGIN,
                          .type_instance = MCELOG_LOG_UNCORR_ERR};
      if (mcelog_message_to_notif(&n, max_item_no, &(messages_storage[i])) == 0)
        mcelog_dispatch_notification(&n);
    }
  }

  if (g_mcelog_config.read_socket) {
    if (get_memory_machine_checks() != 0)
      ERROR(MCELOG_PLUGIN ": MACHINE CHECK INFO NOT AVAILABLE");
  }
  return (0);
}

static int mcelog_shutdown(void) {
  int ret = 0;

  if (parser_job)
    message_parser_cleanup(parser_job);
  parser_job = NULL;

  if (g_mcelog_config.msg_patterns)
    sfree(g_mcelog_config.msg_patterns);

  if (mcelog_thread_running) {
    pthread_cancel(g_mcelog_config.tid);
    if (pthread_join(g_mcelog_config.tid, NULL) != 0) {
      ERROR(MCELOG_PLUGIN ": Stopping thread failed.");
      ret = -1;
    }
  }

  ret = socket_adapter.close(&socket_adapter) || ret;
  pthread_rwlock_destroy(&(socket_adapter.lock));
  return (-ret);
}

void module_register(void) {
  plugin_register_complex_config(MCELOG_PLUGIN, mcelog_config);
  plugin_register_init(MCELOG_PLUGIN, mcelog_init);
  plugin_register_complex_read(NULL, MCELOG_PLUGIN, mcelog_read, 0, NULL);
  plugin_register_shutdown(MCELOG_PLUGIN, mcelog_shutdown);
}
