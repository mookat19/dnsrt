#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* DNS flags and fields. */
#define DNS_UDP_PORT            53

#define DNS_CLASS_IN            0x0001
#define DNS_CLASS_ANY           0x00ff    /* query only */
#define DNS_CLASS_UNICAST       0x8000  

#define DNS_FLAG_QR             0x8000
#define DNS_FLAG_OPCODE         0x7800
#define DNS_FLAG_AA             0x0400  /* authoritative answer */
#define DNS_FLAG_TC             0x0200  /* truncation */
#define DNS_FLAG_RD             0x0100  /* recursion desired */
#define DNS_FLAG_RA             0x0080  /* recursion available */
#define DNS_FLAG_Z              0x0070  /* zero - unused bits */
#define DNS_FLAG_RCODE          0x000f

#define DNS_OPCODE_QUERY        0x0000
#define DNS_OPCODE_IQUERY       0x0800
#define DNS_OPCODE_STATUS       0x1000

#define DNS_RCODE_NO_ERR        0x0000
#define DNS_RCODE_FORMAT_ERR    0x0001
#define DNS_RCODE_SERVER_ERR    0x0002
#define DNS_RCODE_NAME_ERR      0x0003
#define DNS_RCODE_NOT_IMPL      0x0004
#define DNS_RCODE_REFUSED       0x0005

#define DNS_MAX_STRING          256
#define DNS_MAX_QNAME           255
#define DNS_MAX_LABEL           63

#define DNS_TYPE_A              0x01
#define DNS_TYPE_NS             0x02
#define DNS_TYPE_CNAME          0x05
#define DNS_TYPE_SOA            0x06
#define DNS_TYPE_WKS            0x0b
#define DNS_TYPE_PTR            0x0c
#define DNS_TYPE_HINFO          0x0d
#define DNS_TYPE_MINFO          0x0e
#define DNS_TYPE_MX             0x0f
#define DNS_TYPE_TXT            0x10
#define DNS_TYPE_AAAA           0x1c
#define DNS_TYPE_SRV            0x21
#define DNS_QTYPE_AXFR          0xfc    /* query only */
#define DNS_QTYPE_MAILB         0xfd    /* query only */
#define DNS_TYPE_ANY            0xff

/* The IPv4 header structure. */
/* Ignored, we're only interested in snooping DNS. */
struct ip_hdr {
    uint8_t     version;
    uint8_t     qos;
    uint16_t    length;
    uint16_t    id;
    uint8_t     flags;
    uint8_t     frag;
    uint8_t     ttl;
    uint8_t     proto;
    uint16_t    checksum;
    uint32_t    source;
    uint32_t    dest;
};

/* The UDP header structure. */
struct udp_hdr {
    uint16_t    sport;
    uint16_t    dport;
    uint16_t    length;
    uint16_t    checksum;
};

/* The DNS header structure. */
struct dns_hdr {
    uint16_t    id;
    uint16_t    flags;
    uint16_t    qdcount;
    uint16_t    ancount;
    uint16_t    nscount;
    uint16_t    arcount;
};

/* List of domains to filter (whitelist), sorted by decreasing length. */
struct filter_list {
    struct filter_list *next;
    int                 length;
    uint8_t             domain[DNS_MAX_QNAME];
};
static struct filter_list *filters;

static int
dns_filter_cmp(const uint8_t *domain)
{
    struct filter_list  *f = filters;
    const uint8_t       *p;
    int                 length;
    
    /* Always true if no filters provided. */
    if (!filters) return 0;
    
    /* Compute the length of the target domain. */
    for (p = domain; p < (domain + DNS_MAX_QNAME); p += *p + 1) if (!*p) break;
    if (*p) return -1; /* domain too long */
    length = (p - domain + 1);
    
    /* Iterate through the labels until we find that matches in the filter list. */
    for (p = domain; *p;) {
        /* skip filters that are longer than our domain. */
        while (f->length > length) { if (!(f = f->next)) return -1; } /* no match */
        /* compare filters of equal length. */
        while (f->length == length) {
            if (!memcmp(f->domain, p, length)) return 0; /* match found */
            if (!(f = f->next)) return -1; /* no match */
        } /* while */
        /* compare the next label */
        length -= (*p + 1);
        p += *p + 1;
    } /* for */
    
    /* No Match */
    return -1;
} /* dns_filter_cmp */

/* What to do with matching records. */
static unsigned int match_nlseqno = 0;
static int32_t match_ifindex = 0;           /* Add a route to A records via this device. */
static struct in_addr match_route;   /* Add a route to A records via this address. */
static const char *match_script = NULL;     /* Path of script to execute with the record. */

#define NLMSG_TAIL(nmsg) ( (void *)((char *)(nmsg) + NLMSG_ALIGN((nmsg)->nlmsg_len)) )
unsigned int
rnl_addattr(struct nlmsghdr *nh, int maxlen, int type, const void *data, int alen)
{
    struct rtattr *attr;
    int len = RTA_LENGTH(alen);
    int nlen = NLMSG_ALIGN(nh->nlmsg_len) + RTA_SPACE(alen);
    if (nlen > maxlen) return nlen;
    attr = NLMSG_TAIL(nh);
    attr->rta_type = type;
    attr->rta_len = len;
    if (data) memcpy(RTA_DATA(attr), data, alen);
    nh->nlmsg_len = nlen;
    return nlen;
} /* rnl_addattr */

static char *
dns_decode_name(uint8_t *p)
{
    uint8_t *end = (p + DNS_MAX_QNAME);
    uint8_t *start = p;
    if (!*p) return strcpy(p, "."); /* special case. */
    do {
        int len = *p;
        if (len & 0xc0) return NULL; /* Should not encounter compression. */
        if ((p + len) > (end - 2)) return NULL; /* too long. */
        memmove(p, p+1, len);
        p += len;
        *p++ = '.';
    } while (*p);
    return start;
} /* dns_decode_name */

static int
dns_encode_name(const char *name, uint8_t *buf)
{
    int len;
    
    /* Sanity */
    if (!name) return -1;
    if (*name == '\0') {
        *buf = 0;
        return 1;
    }
    
    /* Split the name into labels */
    for (len = 0;;) {
        /* Get the length of the next token. */
        int i = strcspn(name, ".");
        if (i > DNS_MAX_LABEL) return -1;
        if ((len + i) > (DNS_MAX_QNAME - 2)) return -1; /* too long */
        /* Write this label into the buffer. */
        buf[len++] = i;
        memcpy(&buf[len], name, i);
        len += i;
        name += i;
        /* Check for the end of the string. */
        if (*name == '.') name++;
        if (*name == '\0') break;
    }

    /* Done. */
    buf[len++] = 0;
    return len;
} /* dns_encode_name */

/* Simple helper to safely deference pointers. */
static const uint8_t *
dns_name_ptr(const struct dns_hdr *hdr, const uint8_t *p)
{
    const uint8_t *target;
    /* Dereference the pointer. */
    if (!hdr) return NULL;
    if ((p[0] & 0xc0) != 0xc0) return NULL;
    target = (const uint8_t *)hdr + ((p[0] & 0x3f)<<8) + (p[1] & 0xff);
    /* Pointers must point to a label within the packet. */
    if ((target >= p) || (target[0] & 0xc0)) return NULL;
    return target;
} /* dns_name_ptr */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dns_decomp_name
 *  DESCRIPTION
 *      Decompresses a domain name.
 *  PARAMETERS
 *      hdr             ; DNS Header structure.
 *      in              ; Label-encoded, compressed name.
 *      out             ; Label-encoded, decompressed name.
 *      len             ; Length of the DNS header.
 *  RETURNS
 *      const void *    ; Pointer to the end of the compressed label.
 *---------------------------------------------------------------
 */
static const void *
dns_decomp_name(const struct dns_hdr *hdr, const void *in, uint8_t *out, size_t len)
{
    const uint8_t   *end = (const uint8_t *)hdr + len;
    const uint8_t   *max = out + DNS_MAX_QNAME;
    const uint8_t   *p = in;
    int             i;
    
    /* Parse labels until we find a compressed label. */
    while (!(*p & 0xc0)) {
        if (!*p) {
            *out = 0;
            return p+1;
        }
        i = (*p + 1);
        if ((out + i) > (max - 1)) return NULL;
        memcpy(out, p, i);
        out += i;
        p += i;
    } /* while */
    
    /* Mark the end, so that we know what to return. */
    end = p+2;
    while (*p) {
        if (*p & 0xc0) {
            if (!(p = dns_name_ptr(hdr, p))) return NULL;
        }
        /* normal label */
        i = (*p + 1);
        len += i;
        if ((out + i) > (max - 1)) return NULL;
        memcpy(out, p, i);
        out += i;
        p += i;
    } /* for */
    *out = 0;
    return end;
} /* dns_decomp_name */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dns_input_query
 *  DESCRIPTION
 *      Handles a query within a DNS packet.
 *  PARAMETERS
 *      hdr             ; Pointer to the begging of the DNS packet.
 *      query           ; Pointer to the beginning of the query.
 *      len             ; DNS packet length.
 *  RETURNS
 *      cosnt void *    ; Pointer to the end of the query.
 *---------------------------------------------------------------
 */
const void *
dns_input_query(const struct dns_hdr *hdr, const void *query, size_t len)
{
    const uint8_t   *p = query;
    const uint8_t   *end = (const uint8_t *)hdr + len;
    
    /*
     * Get the length of the length of the QNAME, which will be a string of
     * *stuff* terminted with either a null, or a byte beginning with 0xc0.
     */
    while (p < end) {
        /* end label */
        if (*p == 0) { p++; break; }
        /* pointer label */
        if ((*p & 0xc0) == 0xc0) { p += 2; break; }
        /* invalid label */
        if ((*p & 0xc0) != 0x00) return NULL;
        /* normal label */
        p += (*p & ~0xc0) + 1;
    } /* for */
    /* Skip the QTYPE and QCLASS fields and return the end of the query. */
    p += 4;
    return (p < end) ? p : NULL;
} /* dns_input_query */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dns_input_record
 *  DESCRIPTION
 *      Handles a resource record within a DNS packet.
 *  PARAMETERS
 *      hdr             ; Pointer to the begging of the DNS packet.
 *      record          ; Pointer to the beginning of the record.
 *      len             ; DNS packet length.
 *  RETURNS
 *      cosnt void *    ; Pointer to the end of the record.
 *---------------------------------------------------------------
 */
const void *
dns_input_record(const struct dns_hdr *hdr, const void *record, size_t len)
{
    enum {
        argv_script = 0,
        argv_dname,
        argv_ttl,
        argv_class,
        argv_type,
        argv_data,
        argv_null,
    };
    uint8_t         name[DNS_MAX_STRING];
    const uint8_t   *p = record;
    const uint8_t   *end = (const uint8_t *)hdr + len;
    uint16_t        type, rclass, rlength;
    uint32_t        ttl;
    /* Script args. */
    char            strttl[sizeof(uint32_t)*3 + 1];
    char            data[512];  /* how big is big enough? */
    const char *    argv[argv_null + 1];
    
    /* Decompress the DNS name. */
    if (!(p = dns_decomp_name(hdr, record, name, len))) return NULL;
    if ((p + 10) >= end) return NULL; /* record too short */
        
    /* Parse the type, class, TTL and rdlength, they probably won't be word
     * aligned, so do it byte-by-byte. */
    type = *p++ << 8;
    type |= *p++;
    rclass = *p++ << 8;
    rclass |= *p++;
    ttl = *p++ << 24;
    ttl |= *p++ << 16;
    ttl |= *p++ << 8;
    ttl |= *p++;
    rlength = *p++ << 8;
    rlength |= *p++;
    /* Update the end pointer for this record. */
    if ((p + rlength) >= end) return NULL; /* RDATA too long. */
    end = p + rlength;
    
    /* If there were any filters specified, only evaluate matching domains. */
    if (dns_filter_cmp(name)) return end;
    
    /* Ignore non-internet class records. */
    if (rclass != DNS_CLASS_IN) return end;
    
    /* Prepare the script arguments. */
    memset(argv, 0, sizeof(argv));
    argv[argv_script] = match_script;
    argv[argv_dname] = dns_decode_name(name);
    sprintf(strttl, "%d", ttl);
    argv[argv_ttl] = strttl;
    argv[argv_class] = "IN";
    
    /* Parse the record data. */
    switch (type) {
    case DNS_TYPE_A:{
        if (rlength < sizeof(struct in_addr)) return NULL; /* malformed A record. */
        argv[argv_type] = "A";
        argv[argv_data] = inet_ntop(AF_INET, p, data, sizeof(data));
        if (!argv[argv_data]) return NULL; /* malformed A record. */
        break;
    }
    case DNS_TYPE_AAAA:{
        if (rlength < sizeof(struct in6_addr)) return NULL; /* malformed AAAA record. */
        argv[argv_type] = "AAAA";
        argv[argv_data] = inet_ntop(AF_INET6, p, data, sizeof(data));
        if (!argv[argv_data]) return NULL; /* malformed AAAA record. */
        break;
    }
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_SOA:
    case DNS_TYPE_WKS:
    case DNS_TYPE_PTR:
    case DNS_TYPE_HINFO:
    case DNS_TYPE_MINFO:
    case DNS_TYPE_MX:
    case DNS_TYPE_TXT:
    case DNS_TYPE_SRV:
    default:
        return end;
    } /* switch */
    
    /* Fork and execute the script. Do not wait for the child. */
    if (argv[argv_script]) {
        if (fork() == 0) {
            /* We are the child - execute the script. */
            execv(argv[argv_script], argv);
            /* We should not get here, bad things have happened if we do. */
            abort();
        } else {
            /* We are the parent, wait for the child to complete. */
            /* Or do we continue? and let the child reap itself when done? */
            wait(NULL);
            /* TODO: Don't update the routes if the script returns an erorr. */
        }
    }
    /* If a router and/or interface was specified, update the routing table */
    if (type != DNS_TYPE_A) return end;
    if ((match_route.s_addr != htonl(INADDR_ANY)) || match_ifindex) {
        int sock;
        /*
         * TODO: We need to keep a list of records and manage the TTL so that
         * we're not filling the kernel's table with zombie routes. It would
         * be nice if we could set the rta_expires timer from userspace.
         */
        struct sockaddr_nl  sa;
        struct nlmsghdr     *nh = (struct nlmsghdr *)data;
        struct rtmsg        *rtm = NLMSG_DATA(nh);
        memset(nh, 0, NLMSG_SPACE(sizeof(struct rtmsg)));
        nh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
        nh->nlmsg_type = RTM_NEWROUTE;
        nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
        nh->nlmsg_pid = 0;
        nh->nlmsg_seq = ++match_nlseqno;
        rtm->rtm_family = AF_INET;
        rtm->rtm_dst_len = 32;
        rtm->rtm_protocol = RTPROT_REDIRECT; /* TODO: Will any of these trigger the expires timer? */
        rtm->rtm_type = RTN_UNICAST; 
        rtm->rtm_scope = RT_SCOPE_UNIVERSE;
        rtm->rtm_table = RT_TABLE_UNSPEC;
        rnl_addattr(nh, sizeof(data), RTA_DST, p, sizeof(struct in_addr));
        if (match_route.s_addr != htonl(INADDR_ANY)) {
            rnl_addattr(nh, sizeof(data), RTA_GATEWAY, &match_route, sizeof(struct in_addr));
        }
        if (match_ifindex > 0) {
            rnl_addattr(nh, sizeof(data), RTA_OIF, &match_ifindex, sizeof(int32_t));
        }
        
        /* Send RTM_NEWROUTE to the kernel. */
        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
        if (sock < 0) return end;
        if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
            fprintf(stderr, "bind failed on netlink socket (%s)\n", strerror(errno));
            close(sock);
            return end;
        }
        sa.nl_pid = 0; /* sending to the kernel. */
        len = sendto(sock, nh, nh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
        if (len != nh->nlmsg_len) {
            fprintf(stderr, "RTM_NEWROUTE failed (%s)\n", strerror(errno));
        }
        close(sock);
    }
    return end;
} /* dns_input_record */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dns_input
 *  DESCRIPTION
 *      Handles an incoming DNS packet.
 *  PARAMETERS
 *      hdr             ; DNS header structure.
 *      len             ; Length of the DNS packet.
 *  RETURNS
 *      void            ;
 *---------------------------------------------------------------
 */
static void
dns_input(const struct dns_hdr *hdr, size_t len)
{
    uint16_t    flags = htons(hdr->flags);
    uint16_t    count;
    const void *p = hdr+1;
    
    if (!(flags & DNS_FLAG_QR)) return;     /* Ignore queries. */
    if ((flags & DNS_FLAG_TC)) return;   /* Ignore truncated responses. */
    if ((flags & DNS_FLAG_RCODE) != DNS_RCODE_NO_ERR) return; /* Ignore error responses. */
    
    /* Ignore the queries for now, we're only interested in the answers. */
    for (count = ntohs(hdr->qdcount); count; count--) {
        p = dns_input_query(hdr, p, len);
        if (!p) return; /* Malformed query. */
    } /* for */
    
    /* Parse the answers for useful records. */
    for (count = ntohs(hdr->ancount); count; count--) {
        p = dns_input_record(hdr, p, len);
        if (!p) return; /* Malformed answer. */
    } /* for */
    for (count = ntohs(hdr->nscount); count; count--) {
        p = dns_input_record(hdr, p, len);
        if (!p) return; /* Malformed nameserver. */
    } /* for */
    for (count = ntohs(hdr->arcount); count; count--) {
        p = dns_input_record(hdr, p, len);
        if (!p) return; /* Malformed additional record. */
    } /* for */
} /* dns_input */

static void
usage(int argc, char **argv)
{
    /* TODO: */
} /* usage */

int
main(int argc, char **argv)
{
    static const char   *shortopts = "d:r:s:vh";
    static struct option longopts[] = {
        /* Command-line only options. */
        {"dev",     required_argument,  0, 'd'},
        {"route",   required_argument,  0, 'r'},
        {"script",  required_argument,  0, 's'},
        {"help",    no_argument,        0, 'h'},
        {"version", no_argument,        0, 'v'},
        {0, 0, 0, 0}
    };
    int         c;
    int         sock;
    
    /* Parse the options */
    optind = 0;
    while ((c = getopt_long(argc, argv, shortopts, longopts, 0)) != -1) {
        switch (c) {
        case 'h':
            usage(argc, argv);
            return EXIT_SUCCESS;
        case 's':
            match_script = optarg;
            continue;
        case 'r':
            /* Parse the IPv4 router address to use for matching records. */
            if (inet_pton(AF_INET, optarg, &match_route) <= 0) {
                fprintf(stderr, "Failed to parse IPv4 router address: %s\n", optarg);
                break;
            }
            if (match_route.s_addr == htonl(INADDR_ANY)) {
                fprintf(stderr, "Invalid IPv4 router address: %s\n", optarg);
                break;
            }
            continue;
        case 'd':
            if (!(match_ifindex = if_nametoindex(optarg))) {
                fprintf(stderr, "Unknown interface: %s\n", optarg);
                break;
            }
            continue;
        default:
        case '?':
            break;
        } /* switch */
        /* We should only get here on a bad argument. */
        usage(argc, argv);
        return EXIT_FAILURE;
    } /* while */
    
    /* Parse the remaining options (if any) as a list of domains to match. */
    while (optind < argc) {
        struct filter_list *f, *p; 
        /* Allocate memory for the filter list entry. */
        if (!(f = malloc(sizeof(struct filter_list)))) {
            fprintf(stderr, "Out of memory!\n");
            return EXIT_FAILURE;
        }
        /* Parse the filter domain. */
        f->next = NULL;
        f->length = dns_encode_name(argv[optind++], f->domain);
        if (f->length < 0) {
            fprintf(stderr, "Malformed DNS domain: %s\n", argv[optind-1]);
            return EXIT_FAILURE;
        }
        /* Insert this domain into the filter list, and keep it sorted by length */
        if (!filters || (filters->length < f->length)) {
            f->next = filters;
            filters = f;
            continue;
        }
        for (p = filters; p->next; p = p->next) if (p->next->length <= f->length) break;
        f->next = p->next;
        p->next = f;
    } /* while */
    
    /* Open a raw socket to sniff on all DNS traffic. */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("Failed to open raw socket:");
        return;
    }
    
    /* Listen for DNS packets.  */
    for (;;) {
        struct sockaddr_storage sas;
        uint8_t         buff[2048];
        struct ip_hdr   *ip = (struct ip_hdr *)buff;
        struct udp_hdr  *udp = (struct udp_hdr *)(ip+1);
        struct dns_hdr  *dns = (struct dns_hdr *)(udp+1);
        int             len, i;
        
        /* Receive incoming UDP datagrams. */
        len = recv(sock, buff, sizeof(buff), 0);
        if (len < 0) {
            if (errno != EINTR) perror("Failed to read from socket:");
            break;
        }
        
        /* Ignore everything that isn't a DNS response. */
        /* TODO: Should we worry about the checksum, or can we expect the kernel to filter for us? */
        len -= (sizeof(struct ip_hdr) + sizeof(struct udp_hdr));
        if (len < sizeof(struct dns_hdr)) continue;
        if (ip->proto != IPPROTO_UDP) continue;
        if (htons(udp->sport) != DNS_UDP_PORT) continue;
        dns_input(dns, len);
    } /* for */
    
    close(sock);
    return 0;
} /* main */

