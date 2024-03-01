#pragma once

#include <sys/socket.h>

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    const uint8_t *data;
    size_t nmemb;

    size_t consumed;
} FuzzDataProvider;

FuzzDataProvider FuzzDataConstruct(const uint8_t *data, size_t nmemb);
size_t   FuzzDataBytesRemaining(const FuzzDataProvider *data);
size_t   FuzzDataBytesTotal(const FuzzDataProvider *data);
uint8_t  FuzzDataReadUint8(FuzzDataProvider *data);
uint16_t FuzzDataReadUint16(FuzzDataProvider *data);
uint32_t FuzzDataReadUint32(FuzzDataProvider *data);

uint8_t *FuzzDataReadRemainingAsString(FuzzDataProvider *data);
uint8_t *FuzzDataReadIntoByteArray(FuzzDataProvider *data, uint8_t *dst, size_t nmemb);
uint8_t *FuzzDataReadByteArray(FuzzDataProvider *data, size_t nmemb);

struct sockaddr FuzzDataReadSockAddr(FuzzDataProvider *data);