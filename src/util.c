#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "pmv.h"

int pmv_parse_int(const char *s, int *out)
{
    char *end;
    if (s == NULL || *s == '\0') return -1;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 0 || v > 999999) return -1;
    *out = (int)v;
    return 0;
}

void pmv_json_escape(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\b': fputs("\\b", f); break;
            case '\f': fputs("\\f", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if (*p < 0x20 || *p >= 0x7f) fprintf(f, "\\u%04x", *p);
                else fputc(*p, f);
        }
    }
    fputc('"', f);
}

void pmv_csv_field(FILE *f, const char *s)
{
    int needs_quote = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            needs_quote = 1;
            break;
        }
    }
    if (!needs_quote) {
        fputs(s, f);
        return;
    }
    fputc('"', f);
    for (const char *p = s; *p; p++) {
        if (*p == '"') fputs("\"\"", f);
        else fputc(*p, f);
    }
    fputc('"', f);
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int pmv_snapshot_encode(const char *in, char *out, size_t outsz)
{
    size_t j = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        int escape = (*p == '%' || *p == '|' || *p == '\n' || *p == '\r');
        if (escape) {
            if (j + 3 >= outsz) return -1;
            static const char hex[] = "0123456789ABCDEF";
            out[j++] = '%';
            out[j++] = hex[*p >> 4];
            out[j++] = hex[*p & 0xf];
        } else {
            if (j + 1 >= outsz) return -1;
            out[j++] = (char)*p;
        }
    }
    if (j >= outsz) return -1;
    out[j] = '\0';
    return 0;
}

int pmv_snapshot_decode(const char *in, char *out, size_t outsz)
{
    size_t j = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '%' && hexval((unsigned char)p[1]) >= 0 && hexval((unsigned char)p[2]) >= 0) {
            int v = (hexval((unsigned char)p[1]) << 4) | hexval((unsigned char)p[2]);
            if (j + 1 >= outsz) return -1;
            out[j++] = (char)v;
            p += 2;
        } else {
            if (j + 1 >= outsz) return -1;
            out[j++] = *p;
        }
    }
    out[j] = '\0';
    return 0;
}
