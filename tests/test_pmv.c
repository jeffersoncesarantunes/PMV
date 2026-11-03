/*
 * PMV unit tests for the platform-independent helpers in src/util.c and
 * src/score.c. The OpenBSD kernel interface is intentionally not linked.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pmv.h"

static int failures = 0;

#define CHECK(cond, fmt, ...) do { \
    if (!(cond)) { \
        failures++; \
        printf("  [FAIL] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } else { \
        printf("  [PASS] " fmt "\n", ##__VA_ARGS__); \
    } \
} while (0)

static void test_parse_int(void)
{
    int v;
    CHECK(pmv_parse_int("0", &v) == 0 && v == 0, "parse_int valid zero");
    CHECK(pmv_parse_int("42", &v) == 0 && v == 42, "parse_int valid 42");
    CHECK(pmv_parse_int("999999", &v) == 0 && v == 999999, "parse_int valid max");
    CHECK(pmv_parse_int("1000000", &v) == -1, "parse_int rejects overflow");
    CHECK(pmv_parse_int("-1", &v) == -1, "parse_int rejects negative");
    CHECK(pmv_parse_int("12a", &v) == -1, "parse_int rejects trailing chars");
    CHECK(pmv_parse_int("abc", &v) == -1, "parse_int rejects non-numeric");
    CHECK(pmv_parse_int("", &v) == -1, "parse_int rejects empty");
    CHECK(pmv_parse_int("999999999999999999999", &v) == -1, "parse_int rejects ERANGE");
}

static char *capture_escape(const char *s)
{
    FILE *f = tmpfile();
    if (!f) return NULL;
    pmv_json_escape(f, s);
    if (fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc(512);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, 511, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static void test_json_escape(void)
{
    char *out;
    out = capture_escape("plain");
    CHECK(out && strcmp(out, "\"plain\"") == 0, "json_escape plain");
    free(out);
    out = capture_escape("a\"b");
    CHECK(out && strcmp(out, "\"a\\\"b\"") == 0, "json_escape double quote");
    free(out);
    out = capture_escape("a\\b");
    CHECK(out && strcmp(out, "\"a\\\\b\"") == 0, "json_escape backslash");
    free(out);
    out = capture_escape("l1\nl2");
    CHECK(out && strcmp(out, "\"l1\\nl2\"") == 0, "json_escape newline");
    free(out);
    out = capture_escape("a\tb");
    CHECK(out && strcmp(out, "\"a\\tb\"") == 0, "json_escape tab");
    free(out);
    out = capture_escape("a\x01""b");
    CHECK(out && strcmp(out, "\"a\\u0001b\"") == 0, "json_escape control byte");
    free(out);
}

static char *capture_csv(const char *s)
{
    FILE *f = tmpfile();
    if (!f) return NULL;
    pmv_csv_field(f, s);
    if (fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc(256);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, 255, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static void test_csv_field(void)
{
    char *out;
    out = capture_csv("plain");
    CHECK(out && strcmp(out, "plain") == 0, "csv plain");
    free(out);
    out = capture_csv("a,b");
    CHECK(out && strcmp(out, "\"a,b\"") == 0, "csv comma quoted");
    free(out);
    out = capture_csv("a\"b");
    CHECK(out && strcmp(out, "\"a\"\"b\"") == 0, "csv quote escaped");
    free(out);
}

static void test_score(void)
{
    ProcessInfo p = {0};
    p.has_pledge = 1; p.has_unveil = 1;
    CHECK(compute_security_score(&p) == 5, "score pledge+unveil = 5");
    p.chrooted = 1;
    CHECK(compute_security_score(&p) == 6, "score +chroot = 6");
    p.wxneeded = 1;
    CHECK(compute_security_score(&p) == 4, "score -wxneeded = 4");

    memset(&p, 0, sizeof(p));
    CHECK(compute_security_score(&p) == 0, "score none = 0");
    p.wxneeded = 1;
    CHECK(compute_security_score(&p) == -2, "score wxneeded only = -2");
    p.has_pledge = 1;
    CHECK(compute_security_score(&p) == 1, "score pledge - wxneeded = 1");
}

static void test_snapshot_codec(void)
{
    const char *name = "a|b%\nc\r";
    char encoded[128];
    char decoded[128];
    CHECK(pmv_snapshot_encode(name, encoded, sizeof(encoded)) == 0,
          "snapshot encode succeeds");
    CHECK(strchr(encoded, '|') == NULL && strchr(encoded, '\n') == NULL &&
          strchr(encoded, '\r') == NULL,
          "snapshot encoding removes delimiters");
    CHECK(pmv_snapshot_decode(encoded, decoded, sizeof(decoded)) == 0 &&
          strcmp(decoded, name) == 0,
          "snapshot roundtrip preserves name");
    CHECK(pmv_snapshot_encode("short", decoded, 4) == -1,
          "snapshot encode rejects short buffer");
}

int main(void)
{
    printf("PMV Test Suite\n");
    printf("--------------\n\n");

    test_parse_int();
    test_json_escape();
    test_csv_field();
    test_score();
    test_snapshot_codec();

    printf("\n");
    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    }
    printf("%d test(s) FAILED.\n", failures);
    return 1;
}
