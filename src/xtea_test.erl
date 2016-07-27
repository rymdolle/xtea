%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2013-2015 Olle Mattsson
%%%
%%% See the file "LICENSE" for information on usage and redistribution
%%% of this file, and for a DISCLAIMER OF ALL WARRANTIES.
%%%
%%%-------------------------------------------------------------------
%%% @author  Olle Mattsson <olle@rymdis.com>
%%% @doc
%%%
%%% @end
%%% Created :  6 Apr 2013 by  <olle@rymdis.com>
%%%-------------------------------------------------------------------
-module(xtea_test).

-include_lib("xtea/include/xtea.hrl").

-export([start/0, start/2, start/3]).
-export([c_test_async/2, c_test_sync/3,
         erl_test_async/2, erl_test_sync/3,
         generate_message/1,
         c_test_while/5, erl_test_while/5]).

start() ->
    start(10000, 100).

start(Num, Bytes) ->
    start(Num, Bytes, 5).

start(Num, Bytes, Seconds) ->
    io:format("Init xtea\n",  []),

    io:format("Starting test.\nGenerating key and message.\n", []),
    Key = xtea:generate_key(),
    Msg = generate_message(Bytes),
    io:format("Key: ~p\nMsg size: ~p.\n", [Key, byte_size(Msg)]),

    CSync = Num,
    ErlSync = Num,
    io:format("~p sync C test encrypt/decryptions\t\t", [CSync]),
    {CTime, ok} = timer:tc(fun() -> c_test_sync(CSync, Key, Msg) end),
    io:format("~p seconds\n", [CTime/1000000]),
    io:format("~p sync Erlang test encrypt/decryptions\t", [ErlSync]),
    {ErlTime,ok}= timer:tc(fun() -> erl_test_sync(ErlSync, Key, Msg) end),
    io:format("~p seconds\n", [ErlTime/1000000]),

    CAsync = Num,
    ErlAsync = Num,
    io:format("~p async C test encrypt/decryptions\t\t", [CAsync]),
    {CTime2, ok} = timer:tc(fun() -> c_test_async(CAsync, Key, Msg) end),
    io:format("~p seconds\n", [CTime2/1000000]),
    io:format("~p async Erlang test encrypt/decryptions\t", [ErlAsync]),
    {ErlTime2,ok}= timer:tc(fun() -> erl_test_async(ErlAsync, Key, Msg) end),
    io:format("~p seconds\n", [ErlTime2/1000000]),

    Time = Seconds* 1000,
    io:format("Testing C encrypt/decrypt for ~p seconds\t\t", [Time div 1000]),
    CTests = c_test_while(Key, Msg, Time),
    io:format("~p tests\n", [CTests]),
    io:format("Testing Erlang encrypt/decrypt for ~p seconds \t", [Time div 1000]),
    ErlTests = erl_test_while(Key, Msg, Time),
    io:format("~p tests\n", [ErlTests]),

    io:format("Test complete.\n", []).


generate_message(N) ->
    generate_message(N, <<>>).

generate_message(N, Acc) when N > 0 ->
    generate_message(N-1, <<(rand())/integer,Acc/binary>>);
generate_message(0,Acc) ->
    xtea:fill_padding_bytes(Acc).


rand() ->
    rand:uniform(10) -1.


c_test_sync(Num, Key, Msg) when Num > 0 ->
    Encrypted = xtea:c_encrypt(Key, Msg),
    Decrypted = xtea:c_decrypt(Key, Encrypted),
    if Decrypted =/= Msg ->
            io:format("Msg: ~p\nEncrypted: ~p\nDecrypted: ~p\n", [Msg, Encrypted, Decrypted]),
            throw(do_not_match_c);
       true -> ok
    end,
    c_test_sync(Num-1, Key, Msg);
c_test_sync(0,_, _) ->
    ok.


erl_test_sync(Num, Key, Msg) when Num > 0 ->
    Encrypted = xtea:erl_encrypt(Key, Msg),
    Decrypted = xtea:erl_decrypt(Key, Encrypted),
    if Decrypted =/= Msg ->
            throw(do_not_match_erl);
       true -> ok
    end,
    erl_test_sync(Num-1, Key, Msg);
erl_test_sync(0, _,_) ->
    ok.

c_test_async(Num, Key, Msg) ->
    c_test_async(Num, Key, Msg, []).

c_test_async(Num, Key, Msg, Pids) when Num > 0 ->
    Pid = spawn_link(fun() -> c_test_async(Key, Msg) end),
    c_test_async(Num-1, Key, Msg, [Pid|Pids]);
c_test_async(0,_, _, Pids) ->
    lists:foreach(fun(Pid) -> Pid ! {self(), start} end, Pids),
    NumPids = length(Pids),
    rec(NumPids),
    ok.

erl_test_async(Num, Key, Msg) ->
    erl_test_async(Num, Key, Msg, []).

erl_test_async(Num, Key, Msg, Pids) when Num > 0 ->
    Pid = spawn_link(fun() -> erl_test_async(Key, Msg) end),
    erl_test_async(Num-1, Key, Msg, [Pid|Pids]);
erl_test_async(0, _,_, Pids) ->
    lists:foreach(fun(Pid) -> Pid ! {self(), start} end, Pids),
    NumPids = length(Pids),
    rec(NumPids),
    ok.

rec(Num) when Num > 0  ->
    receive
        done ->
            rec(Num -1)
    end;
rec(0) ->
    ok.


c_test_async(Key, Msg) ->
    receive
        {From, start} ->
            Encrypted = xtea:c_encrypt(Key, Msg),
            Decrypted = xtea:c_decrypt(Key, Encrypted),
            if Decrypted =/= Msg ->
                    io:format("Msg: ~p\nEncrypted: ~p\nDecrypted: ~p\n", [Msg, Encrypted, Decrypted]),
                    throw(do_not_match_c);
               true -> From ! done
            end;
        quit ->
            ok
    end.

erl_test_async(Key, Msg) ->
    receive
        {From, start} ->
            Encrypted = xtea:erl_encrypt(Key, Msg),
            Decrypted = xtea:erl_decrypt(Key, Encrypted),
            if Decrypted =/= Msg ->
                    throw(do_not_match_erl);
               true -> From ! done
            end;
        quit ->
            ok
    end.


c_test_while(Key, Msg, Time) ->
    Self = self(),
    Pid = spawn_link(fun() -> c_test_while(false, 0, Key, Msg, Self) end),
    timer:send_after(Time, Pid, done),
    receive
        {tests, Tests} ->
            Tests
    end.

c_test_while(false, Tests, Key, Msg, Pid) ->
    receive
        done ->
            c_test_while(true, Tests, Key, Msg, Pid)
    after 0 ->
            Encrypted = xtea:encrypt(Key, Msg),
            Decrypted = xtea:decrypt(Key, Encrypted),
            if Decrypted =/= Msg ->
                    io:format("Msg: ~p\nEncrypted: ~p\nDecrypted: ~p\n", [Msg, Encrypted, Decrypted]),
                    throw(do_not_match_c);
               true -> ok
            end,
            c_test_while(false, Tests+1, Key, Msg, Pid)
    end;
c_test_while(true, Tests, _,_, Pid) ->
    Pid ! {tests, Tests}.



erl_test_while(Key, Msg, Time) ->
    Self = self(),
    Pid = spawn_link(fun() -> erl_test_while(false, 0, Key, Msg, Self) end),
    timer:send_after(Time, Pid, done),
    receive
        {tests, Tests} ->
            Tests
    end.

erl_test_while(false, Tests, Key, Msg, Pid) ->
    receive
        done ->
            erl_test_while(true, Tests, Key, Msg, Pid)
    after 0 ->
            Encrypted = xtea:erl_encrypt(Key, Msg),
            Decrypted = xtea:erl_decrypt(Key, Encrypted),
            if Decrypted =/= Msg ->
                    throw(do_not_match_erl);
               true -> ok
            end,

            erl_test_while(false, Tests+1, Key, Msg, Pid)
    end;
erl_test_while(true, Tests, _,_, Pid) ->
    Pid ! {tests, Tests}.
