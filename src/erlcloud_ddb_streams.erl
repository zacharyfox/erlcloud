%% Amazon Kinesis Service (Kinesis)

-module(erlcloud_ddb_streams).

%%% Library initialization.
-export([configure/2, configure/3, configure/4, new/2, new/3]).

-export([list_streams/0, list_streams/1, list_streams/2, list_streams/3,
         describe_stream/1, describe_stream/2, describe_stream/3, describe_stream/4,
         get_shard_iterator/3, get_shard_iterator/4, get_shard_iterator/5,
         get_records/1, get_records/2, get_records/3
        ]).

-include_lib("erlcloud/include/erlcloud.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-spec new(string(), string()) -> aws_config().

new(AccessKeyID, SecretAccessKey) ->
    #aws_config{
       access_key_id=AccessKeyID,
       secret_access_key=SecretAccessKey
      }.

-spec new(string(), string(), string()) -> aws_config().

new(AccessKeyID, SecretAccessKey, Host) ->
    #aws_config{
       access_key_id=AccessKeyID,
       secret_access_key=SecretAccessKey,
       kinesis_host=Host
      }.


-spec new(string(), string(), string(), non_neg_integer()) -> aws_config().

new(AccessKeyID, SecretAccessKey, Host, Port) ->
    #aws_config{
       access_key_id=AccessKeyID,
       secret_access_key=SecretAccessKey,
       kinesis_host=Host,
       kinesis_port=Port
      }.

-spec configure(string(), string()) -> ok.

configure(AccessKeyID, SecretAccessKey) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey)),
    ok.

-spec configure(string(), string(), string()) -> ok.

configure(AccessKeyID, SecretAccessKey, Host) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey, Host)),
    ok.

-spec configure(string(), string(), string(), non_neg_integer()) -> ok.

configure(AccessKeyID, SecretAccessKey, Host, Port) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey, Host, Port)),
    ok.

default_config() -> erlcloud_aws:default_config().

%%------------------------------------------------------------------------------
%% @doc
%% DynamoDB Streams API:
%% [http://dynamodb-preview.s3-website-us-west-2.amazonaws.com/docs/streams-api/API_ListStreams.html]
%%
%% ===Example===
%%
%% This operation returns an array of the names of all the streams that are associated with a DynamoDB table.
%%
%% `
%% erlcloud_ddb_streams:list_streams().
%%   {ok, [{<<"StreamIds">>,
%%           [<<"ba907c6bb822a2239ee9337d0453ac5a1433349544981afa48">>]}]}
%% '
%%
%% @end
%%------------------------------------------------------------------------------

parameters_to_json([{Key, Value}|Parameters]) when Key =:= 'exclusive_start_stream_id' ->
    [{<<"ExclusiveStartStreamId">>, Value}|parameters_to_json(Parameters)];
parameters_to_json([{Key, Value}|Parameters]) when Key =:= 'table_name' ->
    [{<<"TableName">>, Value}|parameters_to_json(Parameters)];
parameters_to_json([{Key, Value}|Parameters]) when Key =:= 'limit' ->
    [{<<"Limit">>, Value}|parameters_to_json(Parameters)];
parameters_to_json([]) ->
    [].

-spec list_streams/0 :: () -> proplist().

list_streams() ->
   list_streams(default_config()).

-spec list_streams/1 :: (string() | aws_config()) -> proplist().

list_streams(Config) when is_record(Config, aws_config) ->
   erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.ListStreams", []);
list_streams(Parameters) ->
   Json = parameters_to_json(Parameters),
   erlcloud_ddb_impl:request(default_config(), "DynamoDBStreams_20120810.ListStreams", Json).

-spec list_streams/2 :: (string(), 1..100 | aws_config()) -> proplist().

list_streams(Parameters, Config) when is_record(Config, aws_config) ->
   Json = parameters_to_json(Parameters),
   erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.ListStreams", Json);
list_streams(Parameters, Limit) when is_integer(Limit), Limit > 0, Limit =< 100 ->
   Json = parameters_to_json([Parameters|{limit, Limit}]),
   erlcloud_ddb_impl:request(default_config(), "DynamoDBStreams_20120810.ListStreams", Json).

-spec list_streams/3 :: (string(), 1..100, aws_config()) -> proplist().

list_streams(Parameters, Limit, Config) when is_record(Config, aws_config), is_integer(Limit), Limit > 0, Limit =< 100 ->
   Json = parameters_to_json([Parameters|{limit, Limit}]),
   erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.ListStreams", Json).

%%------------------------------------------------------------------------------
%% @doc
%% DynamoDB Streams API:
%% [http://dynamodb-preview.s3-website-us-west-2.amazonaws.com/docs/streams-api/API_DescribeStream.html]
%%
%% ===Example===
%%
%% This operation returns the following information about the stream: the current status of the stream, the stream Amazon Resource Name (ARN), and an array of shard objects that comprise the stream.
%%
%% `
%% erlcloud_ddb_streams:describe_stream(<<"ba907c6bb822a2239ee9337d0453ac5a1433349544981afa48">>).
%%   {ok, [{<<"StreamDescription">>,
%%           [{<<"StreamId">>,
%%               <<"ba907c6bb822a2239ee9337d0453ac5a1433349544981afa48">>},
%%              {<<"StreamStatus">>,<<"ENABLED">>},
%%              {<<"StreamViewType">>,<<"NEW_AND_OLD_IMAGES">>},
%%              {<<"CreationRequestDateTime">>,1433349544.974},
%%              {<<"TableName">>, <<"us-east-1.dholm-stack.dev.aims.account">>},
%%              {<<"StreamARN">>, <<"arn:aws:dynamodb:ddblocal:000000000000:table/us-east-1.dholm-stack.dev.aims.account/stream/ba907c6bb822a2239ee9337d0453ac5a1433349544981afa48/">>},
%%              {<<"KeySchema">>, [[{<<"AttributeName">>,<<"id">>}, {<<"KeyType">>,<<"HASH">>}]]},
%%              {<<"Shards">>, [
%%                 [{<<"ShardId">>, <<"shardId-00000001433349544993-4843a53b">>},
%%                  {<<"SequenceNumberRange">>, [{<<"StartingSequenceNumber">>, <<"000000000000000000001">>}]}]]}]}]}
%% '
%%
%% @end
%%------------------------------------------------------------------------------

-spec describe_stream/1 :: (string()) -> proplist().

describe_stream(StreamId) ->
   describe_stream(StreamId, default_config()).

-spec describe_stream/2 :: (string(), 1..100 | aws_config()) -> proplist().

describe_stream(StreamId, Config) when is_record(Config, aws_config) ->
   Json = [{<<"StreamId">>, StreamId}],
   erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.DescribeStream", Json);
describe_stream(StreamId, Limit) when is_integer(Limit), Limit > 0, Limit =< 100 ->
   Json = [{<<"StreamId">>, StreamId}, {<<"Limit">>, Limit}],
   erlcloud_ddb_impl:request(default_config(), "DynamoDBStreams_20120810.DescribeStream", Json).

-spec describe_stream/3 :: (string(), 1..100, string() | aws_config()) -> proplist().

describe_stream(StreamId, Limit, Config) when is_record(Config, aws_config) ->
   Json = [{<<"StreamId">>, StreamId}, {<<"Limit">>, Limit}],
   erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.DescribeStream", Json);
describe_stream(StreamId, Limit, ExcludeShard) when is_integer(Limit), Limit > 0, Limit =< 100 ->
   Json = [{<<"StreamId">>, StreamId}, {<<"Limit">>, Limit}, {<<"ExclusiveStartShardId">>, ExcludeShard}],
   erlcloud_ddb_impl:request(default_config(), "DynamoDBStreams_20120810.DescribeStream", Json).

-spec describe_stream/4 :: (string(), 1..100, string(), aws_config()) -> proplist().

describe_stream(StreamId, Limit, ExcludeShard, Config) when is_record(Config, aws_config), is_integer(Limit), Limit > 0, Limit =< 100 ->
   Json = [{<<"StreamId">>, StreamId}, {<<"Limit">>, Limit}, {<<"ExclusiveStartShardId">>, ExcludeShard}],
   erlcloud_ddb_impl:request(default_config(), "DynamoDBStreams_20120810.DescribeStream", Json).


%%------------------------------------------------------------------------------
%% @doc
%% DynamoDB Streams API:
%% [http://dynamodb-preview.s3-website-us-west-2.amazonaws.com/docs/streams-api/API_GetShardIterator.html]
%%
%% ===Example===
%%
%% This operation returns a shard iterator in ShardIterator. The shard iterator specifies the position in the shard from which you want to start reading data records sequentially.
%%
%% `
%% erlcloud_ddb_streams:get_shard_iterator(<<"ba907c6bb822a2239ee9337d0453ac5a1433349544981afa48">>, <<"shardId-00000001433349544993-4843a53b">>, <<"TRIM_HORIZON">>).
%%   {ok,[{<<"ShardIterator">>,
%%    <<"AAAAAAAAAAFHJejL6/AjDShV3pIXsxYZT7Xj2G6EHxokHqT2D1stIOVYUEyprlUGWUepKqUDaR0+hB6qTlKvZa+fsBRqgHi4"...>>}]}
%% '
%%
%% @end
%%------------------------------------------------------------------------------

-spec get_shard_iterator/3 :: (string(), string(), string()) -> proplist().

get_shard_iterator(StreamId, ShardId, ShardIteratorType) ->
  Json = [{<<"StreamId">>, StreamId}, {<<"ShardId">>, ShardId}, {<<"ShardIteratorType">>, ShardIteratorType}],
  erlcloud_ddb_impl:request(default_config(), "DynamoDBStreams_20120810.GetShardIterator", Json).

-spec get_shard_iterator/4 :: (string(), string(), string(), string() | aws_config()) -> proplist().

get_shard_iterator(StreamId, ShardId, ShardIteratorType, Config) when is_record(Config, aws_config) ->
  Json = [{<<"StreamId">>, StreamId}, {<<"ShardId">>, ShardId}, {<<"ShardIteratorType">>, ShardIteratorType}],
  erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.GetShardIterator", Json);
get_shard_iterator(StreamId, ShardId, ShardIteratorType, StartingSequenceNumber) ->
  Json = [{<<"StreamId">>, StreamId}, {<<"ShardId">>, ShardId}, {<<"ShardIteratorType">>, ShardIteratorType}, {<<"SequenceNumber">>, StartingSequenceNumber}],
  erlcloud_ddb_impl:request(default_config(), "DynamoDBStreams_20120810.GetShardIterator", Json).

-spec get_shard_iterator/5 :: (string(), string(), string(), string(), aws_config()) -> proplist().

get_shard_iterator(StreamId, ShardId, ShardIteratorType, StartingSequenceNumber, Config) when is_record(Config, aws_config) ->
  Json = [{<<"StreamId">>, StreamId}, {<<"ShardId">>, ShardId}, {<<"ShardIteratorType">>, ShardIteratorType}, {<<"SequenceNumber">>, StartingSequenceNumber}],
  erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.GetShardIterator", Json).


%%------------------------------------------------------------------------------
%% @doc
%% DynamoDB Streams API:
%% [http://dynamodb-preview.s3-website-us-west-2.amazonaws.com/docs/streams-api/API_GetRecords.html]
%%
%% ===Example===
%%
%% This operation returns one or more data records from a shard. A GetRecords operation request can retrieve up to 10 MB of data.
%%
%% `
%% {ok, [{_, A2}]} = erlcloud_ddb_streams:get_shard_iterator(<<"ba907c6bb822a2239ee9337d0453ac5a1433349544981afa48">>, <<"ba907c6bb822a2239ee9337d0453ac5a1433349544981afa48">>, <<"TRIM_HORIZON">>).
%% {ok,[{<<"ShardIterator">>,
%%      <<"AAAAAAAAAAEuncwaAk+GTC2TIdmdg5w6dIuZ4Scu6vaMGPtaPUfopvw9cBm2NM3Rlj9WyI5JFJr2ahuSh3Z187AdW4Lug86E"...>>}]}
%% erlcloud_ddb_streams:get_records(A2).
%%  {ok,[{<<"NextShardIterator">>,
%%      <<"AAAAAAAAAAEkuCmrC+QDW1gUywyu7G8GxvRyM6GSMkcHQ9wrvCJBW87mjn9C8YEckkipaoJySwgKXMmn1BwSPjnjiUCsu6pc"...>>},
%%      [{<<"Records">>,
%%          [[{<<"eventID">>,<<"caf208ce-2fd3-48e9-95f9-b8450e8f91dd">>},
%%            {<<"eventName">>,<<"INSERT">>},
%%            {<<"eventVersion">>,<<"1.0">>},
%%            {<<"eventSource">>,<<"aws:dynamodb">>},
%%            {<<"awsRegion">>,<<"ddblocal">>},
%%            {<<"dynamodb">>,
%%               [{<<"Keys">>,[{<<"id">>,[{<<"S">>,<<"19078169">>}]}]},
%%                {<<"NewImage">>,
%%                 [{<<"id">>,[{<<"S">>,<<"19078169">>}]},
%%                  {<<"name">>,[{<<"S">>,<<"Account Name">>}]}]},
%%                {<<"SequenceNumber">>,<<"000000000000000000001">>},
%%                {<<"SizeBytes">>,36},
%%                {<<"StreamViewType">>,<<"NEW_AND_OLD_IMAGES">>}]}]]}]]},
%% '
%%
%% @end
%%------------------------------------------------------------------------------

-spec get_records/1 :: (string()) -> proplist().

get_records(ShardIterator) ->
  Json = [{<<"ShardIterator">>, ShardIterator}],
  get_normalized_records(default_config(), Json).

-spec get_records/2 :: (string(), 1..100 | aws_config()) -> proplist().

get_records(ShardIterator, Config) when is_record(Config, aws_config) ->
  Json = [{<<"ShardIterator">>, ShardIterator}],
  erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.GetRecords", Json);
get_records(ShardIterator, Limit) when is_integer(Limit), Limit > 0, Limit =< 100 ->
  Json = [{<<"ShardIterator">>, ShardIterator}, {<<"Limit">>, Limit}],
  get_normalized_records(default_config(), Json).

-spec get_records/3 :: (string(), 1..100, aws_config()) -> proplist().

get_records(ShardIterator, Limit, Config) when is_record(Config, aws_config), is_integer(Limit), Limit > 0, Limit =< 100 ->
  Json = [{<<"ShardIterator">>, ShardIterator}, {<<"Limit">>, Limit}],
  get_normalized_records(Config, Json).

%% Normalize records from Kinesis

get_normalized_records(Config, Json) when is_record(Config, aws_config) ->
  case erlcloud_ddb_impl:request(Config, "DynamoDBStreams_20120810.GetRecords", Json) of
    {ok, Response} -> {ok, normalize_response(Response)};
    {error, Msg} -> {error, Msg}
  end.


normalize_record([{K,V} | T]) when K == <<"Data">> -> [ {K, base64:decode(V)} | normalize_record(T) ];
normalize_record([K | T]) -> [K | normalize_record(T) ];
normalize_record([]) -> [].

normalize_records([K | V]) -> [ normalize_record(K) | normalize_records(V) ];
normalize_records([]) -> [].

normalize_response([{K,V} | T]) when K == <<"Records">> -> [ {K, normalize_records(V)} | normalize_response(T)];
normalize_response([K | T]) -> [K | normalize_response(T)];
normalize_response([]) -> [].
