#include "malloc.h"
static int i = 0;
void * _malloc (size_t sz)
{
    i++;
    printf ("%d\n", i);
    return malloc (sz);
}

