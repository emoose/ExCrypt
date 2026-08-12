#include "portable_io.h"
#include <errno.h>

#ifndef fopen_s
int fopen_s(FILE** file_p, const char* filename, const char* mode)
{
  if (!file_p || !filename || !mode)
    return -1;

  *file_p = fopen(filename, mode);
  if (!*file_p)
    return errno;

  return 0;
}
#endif