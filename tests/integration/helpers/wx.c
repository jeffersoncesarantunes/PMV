#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED)
        return 2;

    ((volatile char *)p)[0] = (char)0xc3;

    for (;;)
        sleep(60);
}
