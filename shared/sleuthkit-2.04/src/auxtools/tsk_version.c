/*
 * The Sleuth Kit
 * 
 * $Date: 2005/09/02 19:53:26 $
 */
#include <stdlib.h>
#include <stdio.h>

void
print_version(FILE * hFile)
{
    char *str = "The Sleuth Kit";
#ifdef VER
    fprintf(hFile, "%s ver %s\n", str, VER);
#else
    fprintf(hFile, "%s\n", str);
#endif
    return;
}
