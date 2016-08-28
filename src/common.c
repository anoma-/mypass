#include "common.h"
#include <stdio.h>

static int i = 0;
void * mymalloc (size_t sz)
{
    i++;
    printf ("%d\n", i);
    return calloc (sz, 1);
}

