/*
 * Windows 下为 libsmb2 补齐缺失的 POSIX 函数。
 *
 * c-libsmb2/lib/init.c 直接使用了 srandom() / random() / getlogin_r()：
 *   - srandom/random：只在没有强随机源时作为兜底序列使用
 *   - getlogin_r：取自登录名作为默认 SMB 用户名
 * 这三个在 MSVC 里都没有，这里用 CRT 的对应能力和 Win32 API 补上。
 */
#if defined(_WIN32)

#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* 兜底随机序列，映射到 CRT 的 rand/srand */
void srandom(unsigned int seed)
{
    srand(seed);
}

long random(void)
{
    /* POSIX random() 返回 [0, 2^31-1]，rand() 返回 [0, RAND_MAX]，
     * 这里直接返回，调用方只取低 8 位 */
    return (long)rand();
}

/* 取当前登录用户名；成功后返回 0，失败返回 -1（与 POSIX 一致） */
int getlogin_r(char *buf, size_t len)
{
    DWORD n = (DWORD)len;

    if (buf == NULL || len == 0) {
        return -1;
    }
    if (!GetUserNameA(buf, &n)) {
        return -1;
    }
    return 0;
}

#endif /* _WIN32 */
