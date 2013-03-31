%%%-------------------------------------------------------------------
%%% File    : xtea.erl
%%% Author  : Olle Mattsson <olle@zubat>
%%% Description : XTEA cryptography in erlang and using nif
%%%
%%% Created : 22 May 2009 by Olle Mattsson <olle@zubat>
%%%-------------------------------------------------------------------
-module(xtea).

-export([encrypt/2,decrypt/2]).
-export([erl_encrypt/2,erl_decrypt/2]).
-export([init/0, generate_key/0]).
-export([erl_test/0,erl_test/1,erl_test/2]).
-export([c_test/0,c_test/1,c_test/2]).

-include("xtea.hrl").

-define(SUM, 16#C6EF3720).
-define(DELTA, 16#61C88647).

init() ->
    erlang:load_nif("./xtea", 0).
c_encrypt(_Key, _Bin) ->
    "NIF not loaded".
c_decrypt(_Key, _Bin) ->
    "NIF not loaded".

c_test() ->
    Text = <<"This is a test decrypt/encrypt!!">>,
    Key = #key{k1 = 3404669412, k2 = 1292174806,
	       k3 = 1431840963, k4 = 1813482075},
    c_test(Key, Text).
c_test(Text) when is_list(Text) ->
    Key = #key{k1 = 3404669412, k2 = 1292174806,
	       k3 = 1431840963, k4 = 1813482075},
    c_test(Key, list_to_binary(Text));
c_test(Text) when is_binary(Text) ->
    Key = #key{k1 = 3404669412, k2 = 1292174806,
	       k3 = 1431840963, k4 = 1813482075},
    c_test(Key, Text).

c_test(Key, Text) ->
    io:format("Text: ~p\nKey: ~p\n", [Text,Key]),
    Encrypted = c_encrypt(Key,Text),
    io:format("Encrypted: ~p\n", [Encrypted]),
    Decrypted = c_decrypt(Key,Encrypted),
    io:format("Decrypted: ~p\n", [Decrypted]).

decrypt(Key, Msg) ->
    c_decrypt(Key, Msg).

erl_decrypt(Key, Msg) ->
    erl_decrypt(Key, Msg, []).

%% Take 2*4 bytes and send them to the decrypt function and
%% put the result in an accumulator
erl_decrypt(Key, <<V0:32/?UINT,V1:32/?UINT,B/binary>>, Acc) ->
    Res = do_decrypt(Key,?SUM, V0,V1, 0),
    erl_decrypt(Key, B, [Res|Acc]);
erl_decrypt(_Key, Msg, Acc) when size(Msg) < 8 ->
    make_binary(Acc).


%% Iterate 32 times and then return the result
do_decrypt(_Key,_, V0, V1, 32) ->
    {V0,V1};
do_decrypt(Key,Sum, V0, V1, Rounds) when Rounds < 32 ->
    V11 = fit(V1 - (fit(fit(fit(fit(V0 bsl 4) bxor fit(V0 bsr 5)) + V0) bxor fit(Sum + element(fit(fit(Sum bsr 11) band 3)+#key.k1, Key))))),
    %% This can be changed to subtract instead of add
    %% but in my case it had to be addition
    Sum2 = fit(Sum + ?DELTA),
    V01 = fit(V0 - (fit(fit(fit(fit(V11 bsl 4) bxor fit(V11 bsr 5)) + V11) bxor fit(Sum2 + element(fit(Sum2 band 3)+#key.k1, Key))))),
    do_decrypt(Key, Sum2, V01, V11, Rounds +1).


encrypt(Key, Msg) ->
    c_encrypt(Key, Msg).

erl_encrypt(Key, Msg) ->
    erl_encrypt(Key, fill_padding_bytes(Msg), []).

%% Take 2*4 bytes and send them to the encrypt function and
%% put the result in an accumulator
erl_encrypt(Key, <<V0:32/?UINT,V1:32/?UINT,B/binary>>, Acc) ->
    Res = do_encrypt(Key, 0, V0, V1, 0),
    erl_encrypt(Key, B, [Res|Acc]);
%% Return a binary of the result
erl_encrypt(_Key, <<>>, Acc) ->
    make_binary(Acc).

%% Iterate 32 times and then return the result
do_encrypt(_Key, _, V0,V1, 32) ->
    {V0, V1};
do_encrypt(Key,Sum, V0,V1, Rounds) when Rounds < 32 ->
    V01 = fit(V0 + (fit(fit(fit(fit(V1 bsl 4) bxor fit(V1 bsr 5)) + V1) bxor fit(Sum + element(fit(Sum band 3)+#key.k1, Key))))),
    %% This can be changed to add instead of subtract
    %% but in my case it had to be subtraction
    Sum2 = fit(Sum - ?DELTA),
    V11 = fit(V1 + (fit(fit(fit(fit(V01 bsl 4) bxor fit(V01 bsr 5)) + V01) bxor fit(Sum2 + element(fit(fit(Sum2 bsr 11) band 3)+#key.k1, Key))))),
    do_encrypt(Key, Sum2, V01, V11, Rounds +1).

    
%% This is a function to test the encrypt/decrypt functionality
erl_test() ->
    Text = <<"This is a test decrypt/encrypt!!">>,
    Key = #key{k1 = 3404669412, k2 = 1292174806,
	       k3 = 1431840963, k4 = 1813482075},
    erl_test(Key, Text).
erl_test(Text) when is_list(Text) ->
    Key = #key{k1 = 3404669412, k2 = 1292174806,
	       k3 = 1431840963, k4 = 1813482075},
    erl_test(Key, list_to_binary(Text));
erl_test(Text) when is_binary(Text) ->
    Key = #key{k1 = 3404669412, k2 = 1292174806,
	       k3 = 1431840963, k4 = 1813482075},
    erl_test(Key, Text).

erl_test(Key, Text) when is_binary(Text),
			 is_tuple(Key),
			 size(Key) == 5 ->
    io:format("Text: ~p\nKey: ~p\n", [Text,Key]),
    Encrypted = erl_encrypt(Key,Text),
    io:format("Encrypted: ~p\n", [Encrypted]),
    Decrypted = erl_decrypt(Key,Encrypted),
    io:format("Decrypted: ~p\n", [Decrypted]).


%%%%%%%%%%%%%%%%%%%%%
%% LOCAL FUNCTIONS
%%%%%%%%%%%%%%%%%%%%%

%% This function is needed due to Erlang's handeling of bignums
fit(Int) ->
    <<Int2:32/?UINT>> =
	<<Int:32/?UINT>>,
    Int2.

%% Fill up with padding bytes to be able to encrypt the message properly
fill_padding_bytes(Msg) when size(Msg) rem 8 =/= 0 ->
    NumBytesToAdd = 8 - (size(Msg) rem 8),
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


generate_key() ->
    #key{k1 = random:uniform(4294967295),
	 k2 = random:uniform(4294967295),
	 k3 = random:uniform(4294967295),
	 k4 = random:uniform(4294967295)}.
    
