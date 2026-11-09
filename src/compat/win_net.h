/*
 * Windows 下强制包含的兼容头（由 binding.gyp 的 ForcedIncludeFiles 注入，
 * 对所有翻译单元生效，所以这里放的内容必须全局一致、不能依赖包含顺序）。
 *
 * 解决两类问题：
 *
 * 1) 网络符号缺失
 *    libdcerpc 的部分 .c（如 dcerpc-epm.c）只用 HAVE_ARPA_INET_H /
 *    HAVE_NETINET_IN_H / HAVE_SYS_SOCKET_H 引入网络头，这些宏在 Windows 上
 *    都为 0（见 scripts/gen_config.js），导致 AF_INET / INET_ADDRSTRLEN /
 *    inet_ntop 全部未声明。Winsock 本身都有，直接补上即可。
 *
 * 2) MS-DTYP 类型与 winnt.h 同名冲突
 *    libdcerpc/include/dcerpc/dcerpc-dtyp.h 按 MS-DTYP 定义了 ACCESS_MASK、
 *    ACE_HEADER、ACL、SECURITY_DESCRIPTOR 等，Windows SDK 的 winnt.h 里也有
 *    同名定义（struct tag 带前导下划线），同一编译单元内会出现 C2371/C2011。
 *    处理办法是把 dcerpc 侧的这些标识符统一改名到 dce_ 前缀。改名宏在整个
 *    翻译单元内保持有效、且不还原，因此 dcerpc-dtyp.h 的结构体定义与
 *    dcerpc-dtyp.c / srvsvc.h 里的引用指向同一个类型，语义一致；
 *    winnt.h 的定义不受影响，照常可用。
 *
 * 注意：本头必须先于任何 libsmb2 / libdcerpc 头被处理，ForcedIncludeFiles
 * 正好满足这一点。
 */
#ifndef FILECAT_WIN_COMPAT_H
#define FILECAT_WIN_COMPAT_H

#if defined(_WIN32)

/* inet_ntop / inet_pton 自 Vista 起由 ws2tcpip.h 声明，需要这个版本号。
 * 必须定义在包含 winsock2.h / windows.h 之前。 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* 顺序不能反：winsock2.h 必须先于 windows.h */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

/* ---- MSVC 不认 GCC 的 __attribute__，libdcerpc 里只用在
 *      format(printf, m, n) 这类纯检查上，定义成空即可。 ---- */
#if defined(_MSC_VER) && !defined(__attribute__)
#define __attribute__(x)
#endif

/* ---- POSIX 文件/IO 名称补齐 ----
 * libdcerpc/dcerpc.c 的 dcerpc_read_yaml_file() 直接用
 * open()/read()/close()/fstat() 和 ssize_t，Windows 下对应的是
 * 带下划线的 CRT 版本，这里做一层薄映射。 */
#if defined(_MSC_VER)
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#endif

#ifndef open
#define open  _open
#endif
#ifndef read
#define read  _read
#endif
#ifndef write
#define write _write
#endif
#ifndef close
#define close _close
#endif
#ifndef fstat
#define fstat _fstat64
#endif
#ifndef stat
#define stat  _stat64
#endif

/* Windows 没有 O_CLOEXEC（句柄默认不继承时无需该标志），定义为 0 */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#endif

/* ---- MS-DTYP 同名类型改名，避免与 winnt.h 冲突 ---- */
/* 变量/宏取值常量（如 DELETE、GENERIC_READ）两边数值相同，不参与改名。 */
#define ACCESS_MASK DCE_ACCESS_MASK
#define _ACE_HEADER DCE__ACE_HEADER
#define ACE_HEADER DCE_ACE_HEADER
#define PACE_HEADER DCE_PACE_HEADER
#define _ACCESS_ALLOWED_ACE DCE__ACCESS_ALLOWED_ACE
#define ACCESS_ALLOWED_ACE DCE_ACCESS_ALLOWED_ACE
#define PACCESS_ALLOWED_ACE DCE_PACCESS_ALLOWED_ACE
#define _ACCESS_DENIED_ACE DCE__ACCESS_DENIED_ACE
#define ACCESS_DENIED_ACE DCE_ACCESS_DENIED_ACE
#define PACCESS_DENIED_ACE DCE_PACCESS_DENIED_ACE
#define _SYSTEM_AUDIT_ACE DCE__SYSTEM_AUDIT_ACE
#define SYSTEM_AUDIT_ACE DCE_SYSTEM_AUDIT_ACE
#define PSYSTEM_AUDIT_ACE DCE_PSYSTEM_AUDIT_ACE
#define _SYSTEM_ALARM_ACE DCE__SYSTEM_ALARM_ACE
#define SYSTEM_ALARM_ACE DCE_SYSTEM_ALARM_ACE
#define PSYSTEM_ALARM_ACE DCE_PSYSTEM_ALARM_ACE
#define _SYSTEM_MANDATORY_LABEL_ACE DCE__SYSTEM_MANDATORY_LABEL_ACE
#define SYSTEM_MANDATORY_LABEL_ACE DCE_SYSTEM_MANDATORY_LABEL_ACE
#define PSYSTEM_MANDATORY_LABEL_ACE DCE_PSYSTEM_MANDATORY_LABEL_ACE
#define _SYSTEM_SCOPED_POLICY_ID_ACE DCE__SYSTEM_SCOPED_POLICY_ID_ACE
#define SYSTEM_SCOPED_POLICY_ID_ACE DCE_SYSTEM_SCOPED_POLICY_ID_ACE
#define PSYSTEM_SCOPED_POLICY_ID_ACE DCE_PSYSTEM_SCOPED_POLICY_ID_ACE
#define _ACL DCE__ACL
#define ACL DCE_ACL
#define PACL DCE_PACL
#define _SECURITY_DESCRIPTOR DCE__SECURITY_DESCRIPTOR
#define SECURITY_DESCRIPTOR DCE_SECURITY_DESCRIPTOR
#define PSECURITY_DESCRIPTOR DCE_PSECURITY_DESCRIPTOR

#endif /* _WIN32 */

#endif /* FILECAT_WIN_COMPAT_H */
