#include <unistd.h>

int main(void)
{
    if (unveil("/", "r") == -1)
        return 1;
    if (unveil(NULL, NULL) == -1)
        return 1;
    if (pledge("stdio", NULL) == -1)
        return 1;

    for (;;)
        sleep(60);
}
