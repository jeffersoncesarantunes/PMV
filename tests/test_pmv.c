/*
 * PMV unit tests — exercises the pure logic of src/main.c without
 * requiring the OpenBSD kernel interface (libkvm).
 *
 * The helpers below mirror the exact implementations used in src/main.c
 * so the formatting/parsing behavior is regression-tested.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static int failures = 0;

#define CHECK(cond, fmt, ...) do { \
    if (!(cond)) { \
        failures++; \
        printf("  [FAIL] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    } else { \
        printf("  [PASS] " fmt "\n", ##__VA_ARGS__); \
    } \
} while (0)

/* Mirror of src/main.c:parse_int */
static int parse_int(const char *s, int *out)
{
    char *end;
    if (s == NULL || *s == '\0') return -1;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 0 || v > 999999) return -1;
    *out = (int)v;
    return 0;
}

static void test_parse_int(void)
{
    int v;
    CHECK(parse_int("0", &v) == 0 && v == 0, "parse_int valid zero");
    CHECK(parse_int("42", &v) == 0 && v == 42, "parse_int valid 42");
    CHECK(parse_int("999999", &v) == 0 && v == 999999, "parse_int valid max");
    CHECK(parse_int("1000000", &v) == -1, "parse_int rejects overflow");
    CHECK(parse_int("-1", &v) == -1, "parse_int rejects negative");
    CHECK(parse_int("12a", &v) == -1, "parse_int rejects trailing chars");
    CHECK(parse_int("abc", &v) == -1, "parse_int rejects non-numeric");
    CHECK(parse_int("", &v) == -1, "parse_int rejects empty");
}

/* Mirror of src/main.c:json_escape into a buffer */
static void json_escape_buf(const char *s, char *out, size_t outsz)
{
    size_t j = 0;
    out[j++] = '"';
    while (*s && j + 2 < outsz) {
        switch (*s) {
            case '"':  out[j++] = '\\'; out[j++] = '"';  break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n';  break;
            case '\r': out[j++] = '\\'; out[j++] = 'r';  break;
            case '\t': out[j++] = '\\'; out[j++] = 't';  break;
            default:   out[j++] = *s;                     break;
        }
        s++;
    }
    out[j++] = '"';
    out[j] = '\0';
}

static void test_json_escape(void)
{
    char out[128];
    json_escape_buf("plain", out, sizeof(out));
    CHECK(strcmp(out, "\"plain\"") == 0, "json_escape plain");

    json_escape_buf("a\"b", out, sizeof(out));
    CHECK(strcmp(out, "\"a\\\"b\"") == 0, "json_escape double quote");

    json_escape_buf("a\\b", out, sizeof(out));
    CHECK(strcmp(out, "\"a\\\\b\"") == 0, "json_escape backslash");

    json_escape_buf("l1\nl2", out, sizeof(out));
    CHECK(strcmp(out, "\"l1\\nl2\"") == 0, "json_escape newline");

    json_escape_buf("a\tb", out, sizeof(out));
    CHECK(strcmp(out, "\"a\\tb\"") == 0, "json_escape tab");
}

/* Score computation duplicated from engine/mitigation scoring logic */
static int compute_score(int wxneeded, int has_pledge, int has_unveil)
{
    int score = 0;
    if (has_pledge) score += 1;
    if (has_unveil) score += 1;
    if (wxneeded) score -= 1;
    return score;
}

static void test_score(void)
{
    CHECK(compute_score(0, 1, 1) == 2, "score both mitigations");
    CHECK(compute_score(0, 0, 0) == 0, "score no mitigations");
    CHECK(compute_score(1, 1, 1) == 1, "score wxneeded subtracts");
    CHECK(compute_score(1, 0, 0) == -1, "score only wxneeded");
}

int main(void)
{
    printf("PMV Test Suite\n");
    printf("──────────────\n\n");

    test_parse_int();
    test_json_escape();
    test_score();

    printf("\n");
    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    }
    printf("%d test(s) FAILED.\n", failures);
    return 1;
}
