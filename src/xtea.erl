%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2009-2015 Olle Mattsson
%%%
%%% See the file "LICENSE" for information on usage and redistribution
%%% of this file, and for a DISCLAIMER OF ALL WARRANTIES.
%%%
%%%-------------------------------------------------------------------
%%% File    : xtea.erl
%%% Author  : Olle Mattsson <olle@rymdis.com>
%%% Description : XTEA cryptography in erlang and using nif
%%%
%%% Created : 22 May 2009 by Olle Mattsson <olle@rymdis.com>
%%%-------------------------------------------------------------------
-module(xtea).

-export([encrypt/2,decrypt/2]).
-export([c_encrypt/2,c_decrypt/2]).
-export([erl_encrypt/2,erl_decrypt/2]).
-export([fill_padding_bytes/1]).
-export([init/0, generate_key/0]).

-include_lib("xtea/include/xtea.hrl").

-define(SUM, 16#C6EF3720).
-define(DELTA, 16#61C88647).

-compile({inline,[fit/1]}).

-on_load(init/0).

generate_key() ->
    #key{k1 = rand:uniform(4294967295),
         k2 = rand:uniform(4294967295),
         k3 = rand:uniform(4294967295),
         k4 = rand:uniform(4294967295)}.

init() ->
    erlang:load_nif(filename:join(code:priv_dir(xtea), "xtea"), 0).

c_encrypt(_Key, _Bin) ->
    throw({error, nif_not_loaded}).
c_decrypt(_Key, _Bin) ->
    throw({error, nif_not_loaded}).

decrypt(Key, Msg) when is_list(Msg) ->
    decrypt(Key, list_to_binary(Msg));
decrypt(Key, Msg) when is_binary(Msg) ->
    try c_decrypt(Key, Msg)
    catch
        {error, Reason} ->
            io:format("*ERROR* ~p ~p ~p\n", [?MODULE, ?LINE, Reason]),
            erl_decrypt(Key, Msg)
    end.

erl_decrypt(Key, Msg) ->
    erl_decrypt(Key, Msg, []).

%% Take 2*4 bytes and send them to the decrypt function and
%% put the result in an accumulator
erl_decrypt(Key, <<V0:32/?UINT,V1:32/?UINT,B/binary>>, Acc) ->
    Res = do_decrypt(Key,?SUM, V0,V1, 0),
    erl_decrypt(Key, B, [Res|Acc]);
erl_decrypt(_Key, Msg, Acc) when byte_size(Msg) < 8 ->
    make_binary(Acc).


%% Iterate 32 times and then return the result
do_decrypt(Key,Sum, V0, V1, Rounds) when Rounds < 32 ->
    V11 = fit(V1 - (fit(fit(fit(fit(V0 bsl 4) bxor fit(V0 bsr 5)) + V0) bxor fit(Sum + element(fit(fit(Sum bsr 11) band 3)+#key.k1, Key))))),
    %% This can be changed to subtract instead of add
    %% but in my case it had to be addition
    Sum2 = fit(Sum + ?DELTA),
    V01 = fit(V0 - (fit(fit(fit(fit(V11 bsl 4) bxor fit(V11 bsr 5)) + V11) bxor fit(Sum2 + element(fit(Sum2 band 3)+#key.k1, Key))))),
    do_decrypt(Key, Sum2, V01, V11, Rounds +1);
do_decrypt(_Key,_, V0, V1, 32) ->
    {V0,V1}.


encrypt(Key, Msg) ->
    try c_encrypt(Key, Msg)
    catch
        {error, Reason} ->
            io:format("*ERROR* ~p ~p ~p\n", [?MODULE, ?LINE, Reason]),
            erl_encrypt(Key, Msg)
    end.

erl_encrypt(Key, Msg) when is_binary(Msg) ->
    erl_encrypt(Key, fill_padding_bytes(Msg), []);
erl_encrypt(Key, Msg) when is_list(Msg) ->
    erl_encrypt(Key, list_to_binary(Msg)).

%% Take 2*4 bytes and send them to the encrypt function and
%% put the result in an accumulator
erl_encrypt(Key, <<V0:32/?UINT,V1:32/?UINT,B/binary>>, Acc) ->
    Res = do_encrypt(Key, 0, V0, V1, 0),
    erl_encrypt(Key, B, [Res|Acc]);
%% Return a binary of the result
erl_encrypt(_Key, <<>>, Acc) ->
    make_binary(Acc).

%% Iterate 32 times and then return the result
do_encrypt(Key,Sum, V0,V1, Rounds) when Rounds < 32 ->
    V01 = fit(V0 + (fit(fit(fit(fit(V1 bsl 4) bxor fit(V1 bsr 5)) + V1) bxor fit(Sum + element(fit(Sum band 3)+#key.k1, Key))))),
    %% This can be changed to add instead of subtract
    %% but in my case it had to be subtraction
    Sum2 = fit(Sum - ?DELTA),
    V11 = fit(V1 + (fit(fit(fit(fit(V01 bsl 4) bxor fit(V01 bsr 5)) + V01) bxor fit(Sum2 + element(fit(fit(Sum2 bsr 11) band 3)+#key.k1, Key))))),
    do_encrypt(Key, Sum2, V01, V11, Rounds +1);
do_encrypt(_Key, _, V0,V1, 32) ->
    {V0, V1}.


%%%%%%%%%%%%%%%%%%%%%
%% LOCAL FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%

%% This function is needed due to Erlang's handeling of bignums
fit(Int) ->
    Int band 16#FFFFFFFF.

%% Fill up with padding bytes to be able to encrypt the message properly
fill_padding_bytes(Msg) when byte_size(Msg) rem 8 =/= 0 ->
    NumBytesToAdd = 8 - (byte_size(Msg) rem 8),
    PaddingBytes = list_to_binary(lists:duplicate(NumBytesToAdd, 16#33)),
    <<Msg/binary,PaddingBytes/binary>>;
fill_padding_bytes(Msg) ->
    Msg.


%% Make a binary of the returned list from decrypt/encrypt
make_binary(List) ->
    make_binary(List, <<>>).

make_binary([], Acc) ->
    Acc;
make_binary([{V0,V1}|T], Acc) ->
    make_binary(T, <<V0:32/?UINT,V1:32/?UINT,Acc/binary>>).
