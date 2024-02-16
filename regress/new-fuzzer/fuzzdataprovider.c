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
    struct sockaddr retval = {
#ifdef HAVE_SOCKADDR_SA_LEN
        .sa_len = sizeof(struct sockaddr),
#endif
        .sa_family = FuzzDataReadUint32(data),
        .sa_data = {} 
    };
    uint8_t *saData = FuzzDataReadByteArray(data, sizeof(retval.sa_data));
    memcpy(&retval.sa_data, saData, sizeof(retval.sa_data));
    free(saData);
    return retval;
}
