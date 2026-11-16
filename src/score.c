#include "pmv.h"

int compute_security_score(const ProcessInfo *p)
{
    int score = 0;

    if (p->has_pledge) score += 3;
    if (p->has_unveil) score += 2;
    if (p->chrooted)   score += 1;
    if (p->wxneeded)   score -= 2;

    return score;
}
