#include <string.h>
#include <errno.h>

#ifdef HAVE_GLIBC_STRERROR_R
int main () {
    char buff[512];
    char *string = strerror_r(ENOENT, buff, sizeof(buff));
    
    if(!string || !string[0]) {
      return 1;
    }
    
    return 0;
}
#endif

#ifdef HAVE_POSIX_STRERROR_R
int main () {
    char buff[512];
    int ret = strerror_r(ENOENT, buff, sizeof(buff));
    
    if(!buff[0] || ret) {
	return 1;
    }
    
    return 0;
}
#endif
