//////////////////////////////////////////////////////////////////////
/// Copyright (c) 2013-2015 Olle Mattsson
///
/// See the file "LICENSE" for information on usage and redistribution
/// of this file, and for a DISCLAIMER OF ALL WARRANTIES.
///
///-------------------------------------------------------------------
/// File    : xtea_nif.c
/// Author  : Olle Mattsson <olle@rymdis.com>
/// Description : nif for XTEA cryptography
///
/// Created : 29 Mars 2013 by Olle Mattsson <olle@rymdis.com>
///-------------------------------------------------------------------
#include "erl_nif.h"
#include <stdint.h>
#include <string.h>

#define DELTA 0x61C88647
void encrypt(uint32_t* buffer, uint32_t key[], int size);
void decrypt(uint32_t* buffer, uint32_t key[], int size);

static ERL_NIF_TERM xtea_encrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  uint32_t k1, k2, k3, k4;
  int arity;
  const ERL_NIF_TERM *tuple;
  if (!enif_get_tuple(env, argv[0], &arity, &tuple))
    return enif_make_badarg(env);

  if(arity != 5)
    return enif_make_badarg(env);
  if(!enif_get_uint(env, tuple[1], &k1) ||
     !enif_get_uint(env, tuple[2], &k2) ||
     !enif_get_uint(env, tuple[3], &k3) ||
     !enif_get_uint(env, tuple[4], &k4)) {
    return enif_make_badarg(env);
  }

  ErlNifBinary in, out;

  if (!enif_inspect_binary(env, argv[1], &in))
    return enif_make_badarg(env);

  int size = in.size;
  uint32_t padding;
  if((in.size % 8) != 0){
    padding = 8 - (in.size % 8);
    size += padding;
  }

  if(!enif_alloc_binary(size, &out)) {
    return enif_make_badarg(env);
  }

  memset(out.data, 0x33, size);
  memcpy(out.data, in.data, in.size);
  uint32_t key[4];
  key[0] = k1; key[1] = k2; key[2] = k3; key[3] = k4;

  encrypt((uint32_t*)out.data, key, size);
  return enif_make_binary(env, &out);
}

static ERL_NIF_TERM xtea_decrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  uint32_t k1, k2, k3, k4;
  int arity;
  const ERL_NIF_TERM *tuple;
  if (!enif_get_tuple(env, argv[0], &arity, &tuple)) {
    return enif_make_badarg(env);
  }
  if(arity != 5)
    return enif_make_int(env, 200);
  if(!enif_get_uint(env, tuple[1], &k1) ||
     !enif_get_uint(env, tuple[2], &k2) ||
     !enif_get_uint(env, tuple[3], &k3) ||
     !enif_get_uint(env, tuple[4], &k4)) {
    return enif_make_badarg(env);
  }

  ErlNifBinary bin;

  if (!enif_inspect_binary(env, argv[1], &bin))
    return enif_make_badarg(env);

  if(bin.size % 8 != 0){
    return enif_make_badarg(env);
  }

  uint32_t key[4];
  key[0] = k1; key[1] = k2; key[2] = k3; key[3] = k4;

  decrypt((uint32_t*) bin.data, key, bin.size);

  return enif_make_binary(env, &bin);
}

static ErlNifFunc nif_funcs[] =
  {
    {"c_encrypt", 2, xtea_encrypt},
    {"c_decrypt", 2, xtea_decrypt}
  };

ERL_NIF_INIT(xtea,nif_funcs,NULL,NULL,NULL,NULL)


void encrypt(uint32_t* buffer, uint32_t key[], int size)
{
  int read_pos = 0;
  while(read_pos < size/4) {
    uint32_t v0=buffer[read_pos],v1=buffer[read_pos +1];
    uint32_t sum = 0;
    int32_t i;
    for(i = 0; i < 32; i++) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3]);
      sum -= DELTA;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[sum>>11 & 3]);
    }
    buffer[read_pos] = v0; buffer[read_pos + 1] = v1;
    read_pos = read_pos + 2;
    //printf("Readpos %i\n", read_pos);
  }

}

void decrypt(uint32_t* buffer, uint32_t key[], int size)
{
  int read_pos = 0;
  while(read_pos < size/4) {
    uint32_t v0 = buffer[read_pos], v1 = buffer[read_pos +1];
    uint32_t sum = 0xC6EF3720;

    int i;
    for(i = 0; i < 32; i += 1) {
      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[sum>>11 & 3]);
      sum += DELTA;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3]);
    }
    buffer[read_pos] = v0; buffer[read_pos + 1] = v1;
    read_pos = read_pos + 2;
  }

}
