#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pmv.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char input[128];
    char decoded[256];
    char encoded[1024];
    char again[256];
    int value;

    size_t n = size < sizeof(input) - 1 ? size : sizeof(input) - 1;
    memcpy(input, data, n);
    input[n] = '\0';

    if (pmv_snapshot_decode(input, decoded, sizeof(decoded)) == 0) {
        if (pmv_snapshot_encode(decoded, encoded, sizeof(encoded)) == 0)
            (void)pmv_snapshot_decode(encoded, again, sizeof(again));
    }

    (void)pmv_parse_int(input, &value);
    return 0;
}
