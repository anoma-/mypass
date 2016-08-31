#include "mymalloc.h"

static int i = 0;

void * mymalloc (size_t sz, int num)
{
    i++;
    printf ("%d\n", i);
    if (i == 3)
        return NULL;
    void *p = malloc (sz * num);
    memset (p, 0, sz*num);
    return  p;
}

