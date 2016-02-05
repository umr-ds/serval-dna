/* copied from config.log created by ./configure... */

#define PACKAGE_NAME "servald"
#define PACKAGE_TARNAME "servald"
#define PACKAGE_VERSION "0.9"
#define PACKAGE_STRING "servald 0.9"
#define PACKAGE_BUGREPORT ""
#define PACKAGE_URL ""
#define HAVE_FUNC_ATTRIBUTE_ALIGNED 1
#define HAVE_FUNC_ATTRIBUTE_FORMAT 1
#define HAVE_FUNC_ATTRIBUTE_MALLOC 1
#define HAVE_FUNC_ATTRIBUTE_UNUSED 1
#define HAVE_FUNC_ATTRIBUTE_USED 1
#define HAVE_VAR_ATTRIBUTE_SECTION_SEG 1
#define STDC_HEADERS 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_MEMORY_H 1
#define HAVE_STRINGS_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_STDINT_H 1
#define HAVE_UNISTD_H 1
#define HAVE_MATH_H 1
#define HAVE_FLOAT_H 1
#define HAVE_LIBC 1
#define HAVE_GETPEEREID 1
#define HAVE_BCOPY 1
#define HAVE_BZERO 1
#define HAVE_BCMP 1
#define SIZEOF_OFF_T 8
#define HAVE_STDIO_H 1
#define HAVE_ERRNO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_UNISTD_H 1
#define HAVE_STRING_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_MMAN_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_UCRED_H 1
#define HAVE_SYS_STATVFS_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_POLL_H 1
#define HAVE_NETDB_H 1
#define HAVE_NET_IF_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_IFADDRS_H 1
#define HAVE_SIGNAL_H 1
#define HAVE_SYS_FILIO_H 1
#define HAVE_SYS_SOCKIO_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SINF 1
#define HAVE_COSF 1
#define HAVE_TANF 1
#define HAVE_ASINF 1
#define HAVE_ACOSF 1
#define HAVE_ATANF 1
#define HAVE_ATAN2F 1
#define HAVE_CEILF 1
#define HAVE_FLOORF 1
#define HAVE_POWF 1
#define HAVE_EXPF 1
#define HAVE_LOGF 1
#define HAVE_LOG10F 1
#define HAVE_STRLCPY 1

// rename this function, as it's already used by apples libs
#define uuid_generate_random serval_uuid_generate_random

// one may overwrite those variables, but building the lib for ios we need this sandbox path
#ifndef SYSCONFDIR
#define SYSCONFDIR getenv("HOME")
#endif

#ifndef LOCALSTATEDIR
#define LOCALSTATEDIR getenv("HOME")
#endif