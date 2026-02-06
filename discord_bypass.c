#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "sockmgr.h"

#define DISCORD_PACKET_SIZE 74
#define CUSTOM_PACKET_SIZE 100

static inline int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec <= 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

static inline int get_int_from_env(
    const char *var_name,
    int default_value,
    int min_value,
    int max_value
) {
    const char *env_val = getenv(var_name);
    int value = default_value;

    if (env_val) {
        value = atoi(env_val);
        if (value < min_value) value = min_value;
        if (value > max_value) value = max_value;
    }

    return value;
}

static int delay;
static int fake_packets;

__attribute__((constructor))
static void init_lib(void) {
    delay = get_int_from_env("BYPASS_DELAY", 50, 0, 1000);
    fake_packets = get_int_from_env("BYPASS_FAKE_PACKETS", 2, 0, 20);
}

// used in custom clients
static ssize_t (*real_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t) = NULL;
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!real_sendto) {
        real_sendto = dlsym(RTLD_NEXT, "sendto");
        if (!real_sendto) {
            fprintf(stderr, "dlsym error: %s\n", dlerror());
            return -1;
        }
    }

    socket_entry_t *sock_entry = NULL;
    if (!sm_was_sent(sockfd, &sock_entry) && sock_entry != NULL) {
        if (len == CUSTOM_PACKET_SIZE) {
            for (int i = 0; i < fake_packets; i++) {
                char payload = i % 2;
                real_sendto(sockfd, &payload, 1, 0, dest_addr, addrlen);
            }

            msleep(delay);
        }
    }
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}



// used in official Discord app
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    if (!real_sendmsg) {
        real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
        if (!real_sendmsg) {
            fprintf(stderr, "dlsym error: %s\n", dlerror());
            return -1;
        }
    }

    size_t total_len = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        total_len += msg->msg_iov[i].iov_len;
    }

    socket_entry_t *sock_entry = NULL;
    if (!sm_was_sent(sockfd, &sock_entry) && sock_entry != NULL) {
        if (total_len == DISCORD_PACKET_SIZE) {
            struct msghdr new_msg;
            memset(&new_msg, 0, sizeof(new_msg));

            new_msg.msg_name = msg->msg_name;
            new_msg.msg_namelen = msg->msg_namelen;
            new_msg.msg_control = NULL;
            new_msg.msg_controllen = 0;
            new_msg.msg_flags = 0;
            new_msg.msg_iovlen = 1;

            for (int i = 0; i < fake_packets; i++) {
                char payload = i % 2;
                struct iovec iov = { .iov_base = &payload, .iov_len = 1 };

                new_msg.msg_iov = &iov;
                real_sendmsg(sockfd, &new_msg, flags);
            }

            msleep(delay);
        }
    }

    return real_sendmsg(sockfd, msg, flags);
}

static inline int is_udp_socket(int domain, int type, int protocol) {
    return ( (type & 0xF) == SOCK_DGRAM );
}

static int (*real_socket)(int, int, int) = NULL;
int socket(int domain, int type, int protocol) {
    if (!real_socket) {
        real_socket = dlsym(RTLD_NEXT, "socket");
        if (!real_socket) {
            fprintf(stderr, "dlsym error: %s\n", dlerror());
            return -1;
        }
    }

    int fd = real_socket(domain, type, protocol);

    if (fd >= 0 && is_udp_socket(domain, type, protocol)) {
        sm_add_fd(fd);
    }

    return fd;
}
