/*
 * Copyright (c) 2013, 2104 Anton Dobkin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apn_platform.h"
#include "apn_version.h"

static void __apn_usage(void) {
    printf("Usage: apn-config [OPTION]\n");
    printf("\n");
    printf("Available values for OPTION include:\n\n");
    printf(" --help               output this message\n");
    printf(" --all                output all information\n");
    printf(" --version            output version information\n");
    printf(" --vernum             output the version information as a number (hexadecimal)\n");
    printf(" --libs               library linking information\n");
    printf(" --cc                 output compiler name\n");
    printf(" --cflags             pre-processor and compiler flags\n");
    printf(" --prefix             apn install prefix\n");
    printf(" --includes           library header files information\n");
}

int main(int argc, char **argv) {
    int i = 0;   
    if (argc < 2) {
        __apn_usage();
        return 1;
    }

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--help", 6) == 0) {
            __apn_usage();
            return 0;
        } else if (strncmp(argv[i], "--all", 5) == 0) {
            printf("--version          [%s]\n", APN_VERSION_STRING);
            printf("--vernum           [%X]\n", APN_VERSION_NUM);
            printf("--libs             [-l@CAPN_LIB_NAME@ -L@CAPN_INSTALL_PATH_LIB@]\n");
            printf("--cc               [@CAPN_CC@]\n");
            printf("--cflags           [@CMAKE_C_FLAGS@]\n");
            printf("--prefix           [@CMAKE_INSTALL_PREFIX@]\n");
            printf("--includes         [-I@CAPN_INSTALL_PATH_INCLUDES@]\n");
        } else if (strncmp(argv[i], "--version", 9) == 0) {
            printf("%s\n", APN_VERSION_STRING);
        } else if (strncmp(argv[i], "--vernum", 8) == 0) {
            printf("%X\n", APN_VERSION_NUM);
        } else if (strncmp(argv[i], "--cc", 4) == 0) {
            printf("\n");
        } else if (strncmp(argv[i], "--libs", 6) == 0) {
            printf("-l@CAPN_LIB_NAME@ -L@CAPN_INSTALL_PATH_LIB@\n");
        } else if (strncmp(argv[i], "--cflags", 8) == 0) {
            printf("@CMAKE_C_FLAGs@\n");
        } else if (strncmp(argv[i], "--prefix", 8) == 0) {
            printf("@CMAKE_INSTALL_PREFIX@\n");
        } else if (strncmp(argv[i], "--includes", 10) == 0) {
            printf("-I@CAPN_INSTALL_PATH_INCLUDES@\n");
        } else {
    	    printf("Unknown option: `%s'\n", argv[i]);
        }
    }
    return 0;
}
