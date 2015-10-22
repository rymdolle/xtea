%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2013-2015 Olle Mattsson
%%%
%%% See the file "LICENSE" for information on usage and redistribution
%%% of this file, and for a DISCLAIMER OF ALL WARRANTIES.
%%%
%%%-------------------------------------------------------------------
%%% @author  <olle@rymdis.com>
%%% @doc
%%%
%%% @end
%%% Created : 29 Mar 2013 by  <olle@rymdis.com>
%%%-------------------------------------------------------------------

-define(UINT, unsigned-integer-little).

-record(key, {k1 :: integer(),
              k2 :: integer(),
              k3 :: integer(),
              k4 :: integer()}).
