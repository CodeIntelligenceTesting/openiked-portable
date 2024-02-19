#include <netinet/in.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "fuzzdataprovider.h"

FuzzDataProvider FuzzDataConstruct(const uint8_t *data, size_t nmemb)
{
    FuzzDataProvider retval = {
        .data = data,
        .nmemb = nmemb,
        .consumed = 0
    };
    return retval;
}

size_t FuzzDataBytesRemaining(const FuzzDataProvider *data)
{
    assert(data->consumed <= data->nmemb);
    return data->nmemb - data->consumed;
}

size_t FuzzDataBytesTotal(const FuzzDataProvider *data)
{
    return data->nmemb;
}

uint8_t FuzzDataReadUint8(FuzzDataProvider *data)
{
    if (data->consumed == data->nmemb) {
        return 0;
    }
    size_t index = data->consumed;
    data->consumed++;
    
    return data->data[index];

}

uint16_t FuzzDataReadUint16(FuzzDataProvider *data)
{
    return (FuzzDataReadUint8(data) << 8) | (FuzzDataReadUint8(data));
}

uint32_t FuzzDataReadUint32(FuzzDataProvider *data)
{
    return (FuzzDataReadUint16(data) << 16) | (FuzzDataReadUint16(data));
}

uint8_t *FuzzDataReadRemainingAsString(FuzzDataProvider *data)
{
    /*
     * string are nul-terminated, so replace the last character with a nul
     */
    int allocationSize = FuzzDataBytesRemaining(data) + 1;
    uint8_t *retval = malloc(allocationSize);
    uint8_t *i = retval;
    while (FuzzDataBytesRemaining(data) > 0) {
        i[0] = FuzzDataReadUint8(data);
        i = &i[1];
    }
    i[0] = 0;

    return retval;
}

uint8_t *FuzzDataReadByteArray(FuzzDataProvider *data, size_t nmemb)
{
    assert(nmemb > 0);
    uint8_t *retval = malloc(nmemb);
    for(size_t i=0; i<nmemb; ++i) {
        retval[i] = FuzzDataReadUint8(data);
    }
    return retval;
}

struct sockaddr FuzzDataReadSockAddr(FuzzDataProvider *data)
{
    /*
     * should use c++ static assert for this one if possible
     */
    assert(sizeof(struct sockaddr_in) == sizeof(struct sockaddr));

    struct sockaddr_in retval;
    /*
     * do _not_ write random data into the unnamed parts of this structure.
     * On some operating systems, there is sa_len, others have sin_len, and
     * none of these are standartized, yet all of them default to autodetection
     * if they are zero-ed.
     */
    memset(&retval, 0, sizeof(retval));

#ifdef HAVE_SOCKADDR_SA_LEN
    /*
     * set `sin_len`
     * The `sin_len` name is not standartized though, so use `sa_len` of `struct sockaddr`.
     * `sa_len` is not standartized either, however we have a macro indicating it's
     * presence, while we don't have a macro for `sin_len`.
     */
    ((struct sockaddr *)(&retval))->sa_len = sizeof(retval);
#endif

    retval.sin_family = AF_INET; /* the vroute-netlink implementation seems to rely on this field having a sane value */
    retval.sin_port = 0; /* we can fuzz this one */
    retval.sin_addr.s_addr = 0; /* we can fuzz this one, too */
    /* there is some padding, which can also be written fuzzy junk into but it _should_ be irrelevant. */

    /*
     * hard casting is the way this structure is used anyways.
     */
    return *(struct sockaddr *)(&retval);
}
