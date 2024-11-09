/*
 * Copyright (c) 2015-2021, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Hyperscan example program 1: simplegrep
 *
 * This is a simple example of Hyperscan's most basic functionality: it will
 * search a given input file for a pattern supplied as a command-line argument.
 * It is intended to demonstrate correct usage of the hs_compile and hs_scan
 * functions of Hyperscan.
 *
 * Patterns are scanned in 'DOTALL' mode, which is equivalent to PCRE's '/s'
 * modifier. This behaviour can be changed by modifying the "flags" argument to
 * hs_compile.
 *
 * Build instructions:
 *
 *     gcc -o simplegrep simplegrep.c $(pkg-config --cflags --libs libhs)
 *
 * Usage:
 *
 *     ./simplegrep <pattern> <input file>
 *
 * Example:
 *
 *     ./simplegrep int simplegrep.c
 *
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include <hs.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
static int gsHint = 0;

/**
 * This is the function that will be called for each match that occurs. @a ctx
 * is to allow you to have some application-specific state that you will get
 * access to for each match. In our simple example we're just going to use it
 * to pass in the pattern that was being searched for so we can print it out.
 */
static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) {
    // printf("Match for pattern \"%s\" at offset %llu\n", (char *)ctx, to);
    gsHint++;
    return 0;
}

/**
 * Fill a data buffer from the given filename, returning it and filling @a
 * length with its length. Returns NULL on failure.
 */
static char *readInputData(const char *inputFN, unsigned int *length) {
    FILE *f = fopen(inputFN, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: unable to open file \"%s\": %s\n", inputFN,
                strerror(errno));
        return NULL;
    }

    /* We use fseek/ftell to get our data length, in order to keep this example
     * code as portable as possible. */
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }
    long dataLen = ftell(f);
    if (dataLen < 0) {
        fprintf(stderr, "ERROR: ftell() failed: %s\n", strerror(errno));
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }

    /* Hyperscan's hs_scan function accepts length as an unsigned int, so we
     * limit the size of our buffer appropriately. */
    if ((unsigned long)dataLen > UINT_MAX) {
        dataLen = UINT_MAX;
        printf("WARNING: clipping data to %ld bytes\n", dataLen);
    } else if (dataLen == 0) {
        fprintf(stderr, "ERROR: input file \"%s\" is empty\n", inputFN);
        fclose(f);
        return NULL;
    }

    char *inputData = malloc(dataLen);
    if (!inputData) {
        fprintf(stderr, "ERROR: unable to malloc %ld bytes\n", dataLen);
        fclose(f);
        return NULL;
    }

    char *p = inputData;
    size_t bytesLeft = dataLen;
    while (bytesLeft) {
        size_t bytesRead = fread(p, 1, bytesLeft, f);
        bytesLeft -= bytesRead;
        p += bytesRead;
        if (ferror(f) != 0) {
            fprintf(stderr, "ERROR: fread() failed\n");
            free(inputData);
            fclose(f);
            return NULL;
        }
    }

    fclose(f);

    *length = (unsigned int)dataLen;
    return inputData;
}

static int hyperScanMethod(const char *inputData, unsigned int length, char *pattern)
{
    int ret = 0;

    /* First, we attempt to compile the pattern provided on the command line.
     * We assume 'DOTALL' semantics, meaning that the '.' meta-character will
     * match newline characters. The compiler will analyse the given pattern and
     * either return a compiled Hyperscan database, or an error message
     * explaining why the pattern didn't compile.
     */
    hs_database_t *database;
    hs_compile_error_t *compile_err;
    if (hs_compile(pattern, HS_FLAG_DOTALL, HS_MODE_BLOCK, NULL, &database,
                   &compile_err) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to compile pattern \"%s\": %s\n",
                pattern, compile_err->message);
        hs_free_compile_error(compile_err);
        return -1;
    }
    
    /* Finally, we issue a call to hs_scan, which will search the input buffer
     * for the pattern represented in the bytecode. Note that in order to do
     * this, scratch space needs to be allocated with the hs_alloc_scratch
     * function. In typical usage, you would reuse this scratch space for many
     * calls to hs_scan, but as we're only doing one, we'll be allocating it
     * and deallocating it as soon as our matching is done.
     *
     * When matches occur, the specified callback function (eventHandler in
     * this file) will be called. Note that although it is reminiscent of
     * asynchronous APIs, Hyperscan operates synchronously: all matches will be
     * found, and all callbacks issued, *before* hs_scan returns.
     *
     * In this example, we provide the input pattern as the context pointer so
     * that the callback is able to print out the pattern that matched on each
     * match event.
     */
    hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
        goto l_freedb;
        return -1;
    }

    ret = hs_scan(database, inputData, length, 0, scratch, eventHandler,
                pattern);

    /* Scanning is complete, any matches have been handled, so now we just
     * clean up and exit.
     */
    hs_free_scratch(scratch);
l_freedb:
    hs_free_database(database);
    return ret;

}

static int rookieScanMethod(const char *inputData, unsigned int length, char *pattern)
{
    size_t plen = strlen(pattern);

    gsHint = 0;
    for (size_t i = 0; i < length - (plen - 1); i++)
    {
        ///< 逐行检查pattern的字符
        for (size_t j = 0; j < plen; j++)
        {
            if (pattern[j] != inputData[i + j])
            {
                break;
            }
            else if (j == plen - 1)
            {
                // hit 
                eventHandler(0, 0, i, 0, pattern);
            }
            
        }
    }
    
    return 0;
}

static int myBMScanMethod(const char *inputData, unsigned int length, char *pattern)
{
    size_t plen = strlen(pattern);
    char tmpHint[16] = {0};
    #pragma ivdep
    for (size_t i = 0; i < length - (plen - 1); i++)
    {
        ///< 逐行检查pattern的字符
        #pragma ivdep
        for (size_t j = 0; j < plen; j++)
        {
            if (unlikely(pattern[j] != inputData[i + j]))
            {
                break;
            }
            else if (unlikely(j == plen - 1))
            {
                // hit 
                // eventHandler(0, 0, i, 0, pattern);
                tmpHint[j]++;
            }
            
        }
    }

    #pragma omp simd reduction(+:gsHint)
    for (size_t j = 0; j < 16; j++)
    {
        gsHint += tmpHint[j];
    }

    return 0;
}

static int memScanMethod(const char *inputData, unsigned int length, char *pattern)
{
    
    for (size_t i = 0; i < length; i++)
    {
        if (pattern[0] == inputData[i])
        {
            eventHandler(0, 0, i, 0, pattern);
        }
    }

    return 0;
}

static int paraScanMethod(const char *inputData, unsigned int length, char *pattern)
{
    return 0;
}

typedef int (*ScanFun)(const char *inputData, unsigned int length, char *pattern);

typedef struct ScanTestItem
{
    const char *testName;
    ScanFun     testFun;
} ScanTestItem_t;

///< TODO: 缺少校验方法

ScanTestItem_t testFuncArr[] = 
{
    { .testName = "allMemScan",     .testFun = memScanMethod},
    { .testName = "hyperScan",      .testFun = hyperScanMethod},
    { .testName = "rookieScan",     .testFun = rookieScanMethod},
    { .testName = "myBMScanMethod", .testFun = myBMScanMethod},
    { .testName = "myScan",         .testFun = paraScanMethod},
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pattern> <input file>\n", argv[0]);
        return -1;
    }

    int ret = 0;
    char *pattern = argv[1];
    char *inputFN = argv[2];

    if (access(inputFN, F_OK) != 0) {
        fprintf(stderr, "ERROR: file doesn't exist.\n");
        return -1;
    }
    if (access(inputFN, R_OK) != 0) {
        fprintf(stderr, "ERROR: can't be read.\n");
        return -1;
    }

    /* Next, we read the input data file into a buffer. */
    unsigned int length;
    char *inputData = readInputData(inputFN, &length);
    if (!inputData) {
        return -1;
    }

    printf("Scanning %u bytes with Hyperscan\n", length);

    for (int idx = 0; idx < (int)(sizeof(testFuncArr)/sizeof(testFuncArr[0])); idx++)
    {
        gsHint = 0;
        ScanTestItem_t *pTest = testFuncArr + idx;
        struct timeval start, end;
        gettimeofday(&start, NULL);
        pTest->testFun(inputData, length, pattern);
        gettimeofday(&end, NULL);

        double duration = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000.0;
        printf("[%24s: %8s hit %12d]Time measured: %10.3f ms.\n", pTest->testName, ret == HS_SUCCESS ? "DONE" : "ERROR", gsHint, duration);
    }

    free(inputData);
    return ret;
}
