#ifndef PMV_COLORS_H
#define PMV_COLORS_H

#define CLR_RESET   "\x1b[0m"
#define CLR_RED     "\x1b[31m"
#define CLR_GREEN   "\x1b[32m"
#define CLR_YELLOW  "\x1b[33m"
#define CLR_BLUE    "\x1b[34m"
#define CLR_MAGENTA "\x1b[35m"
#define CLR_CYAN    "\x1b[36m"
#define CLR_BOLD    "\x1b[1m"

static const char *ansi_color(const char *code) {
    return isatty(STDOUT_FILENO) ? code : "";
}

#endif
