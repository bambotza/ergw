%% Copyright 2015, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(ggsn_gn_proxy).

-behaviour(gtp_api).

-compile({parse_transform, cut}).

-export([validate_options/1, init/2, request_spec/3,
	 handle_pdu/4,
	 handle_request/5, handle_response/5,
	 handle_event/4, terminate/3]).

-export([delete_context/4, close_context/4]).

-include_lib("kernel/include/logger.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").
-include("include/ergw.hrl").

-import(ergw_aaa_session, [to_session/1]).

-compile([nowarn_unused_record]).

-define(T3, 10 * 1000).
-define(N3, 5).
-define(RESPONSE_TIMEOUT, (?T3 + (?T3 div 2))).

-define(IS_REQUEST_TUNNEL(Key, Msg, Tunnel),
	(is_record(Key, request) andalso
	 is_record(Msg, gtp) andalso
	 Key#request.socket =:= Tunnel#tunnel.socket andalso
	 Msg#gtp.tei =:= Tunnel#tunnel.local#fq_teid.teid)).

-define(IS_REQUEST_TUNNEL_OPTIONAL_TEI(Key, Msg, Tunnel),
	(is_record(Key, request) andalso
	 is_record(Msg, gtp) andalso
	 Key#request.socket =:= Tunnel#tunnel.socket andalso
	 (Msg#gtp.tei =:= 0 orelse
	  Msg#gtp.tei =:= Tunnel#tunnel.local#fq_teid.teid))).

%%====================================================================
%% API
%%====================================================================

-define('Cause',					{cause, 0}).
-define('IMSI',						{international_mobile_subscriber_identity, 0}).
-define('Recovery',					{recovery, 0}).
-define('Tunnel Endpoint Identifier Data I',		{tunnel_endpoint_identifier_data_i, 0}).
-define('Tunnel Endpoint Identifier Control Plane',	{tunnel_endpoint_identifier_control_plane, 0}).
-define('NSAPI',					{nsapi, 0}).
-define('End User Address',				{end_user_address, 0}).
-define('Access Point Name',				{access_point_name, 0}).
-define('Protocol Configuration Options',		{protocol_configuration_options, 0}).
-define('SGSN Address for signalling',			{gsn_address, 0}).
-define('SGSN Address for user traffic',		{gsn_address, 1}).
-define('MSISDN',					{ms_international_pstn_isdn_number, 0}).
-define('Quality of Service Profile',			{quality_of_service_profile, 0}).
-define('IMEI',						{imei, 0}).

-define(CAUSE_OK(Cause), (Cause =:= request_accepted orelse
			  Cause =:= new_pdp_type_due_to_network_preference orelse
			  Cause =:= new_pdp_type_due_to_single_address_bearer_only)).

request_spec(v1, _Type, Cause)
  when Cause /= undefined andalso not ?CAUSE_OK(Cause) ->
    [];

request_spec(v1, create_pdp_context_request, _) ->
    [{?'IMSI',						conditional},
     {{selection_mode, 0},				conditional},
     {?'Tunnel Endpoint Identifier Data I',		mandatory},
     {?'Tunnel Endpoint Identifier Control Plane',	conditional},
     {?'NSAPI',						mandatory},
     {{nsapi, 1},					conditional},
     {{charging_characteristics, 0},			conditional},
     {?'End User Address',				conditional},
     {?'Access Point Name',				conditional},
     {?'SGSN Address for signalling',			mandatory},
     {?'SGSN Address for user traffic',			mandatory},
     {{gsn_address, 2},					conditional},
     {{gsn_address, 3},					conditional},
     {?'MSISDN',					conditional},
     {?'Quality of Service Profile',			mandatory},
     {{traffic_flow_template, 0},			conditional},
     {?'IMEI',						conditional}];

request_spec(v1, create_pdp_context_response, _) ->
    [{?'Cause',						mandatory},
     {{reordering_required, 0},				conditional},
     {?'Tunnel Endpoint Identifier Data I',		conditional},
     {?'Tunnel Endpoint Identifier Control Plane',	conditional},
     {{charging_id, 0},					conditional},
     {?'End User Address',				conditional},
     {?'SGSN Address for signalling',			conditional},
     {?'SGSN Address for user traffic',			conditional},
     {{gsn_address, 2},					conditional},
     {{gsn_address, 3},					conditional},
     {?'Quality of Service Profile',			conditional}];

%% SGSN initated reqeuest:
%% request_spec(v1, update_pdp_context_request, _) ->
%%     [{?'Tunnel Endpoint Identifier Data I',		mandatory},
%%      {?'Tunnel Endpoint Identifier Control Plane',	conditional},
%%      {?'NSAPI',						mandatory},
%%      {?'SGSN Address for signalling',			mandatory},
%%      {?'SGSN Address for user traffic',			mandatory},
%%      {{gsn_address, 2},					conditional},
%%      {{gsn_address, 3},					conditional},
%%      {?'Quality of Service Profile',			mandatory},
%%      {{traffic_flow_template, 0},			conditional}];

request_spec(v1, update_pdp_context_request, _) ->
    [{?'NSAPI',						mandatory}];

request_spec(v1, update_pdp_context_response, _) ->
    [{{cause, 0},					mandatory},
     {?'Tunnel Endpoint Identifier Data I',		conditional},
     {?'Tunnel Endpoint Identifier Control Plane',	conditional},
     {{charging_id, 0},					conditional},
     {?'SGSN Address for signalling',			conditional},
     {?'SGSN Address for user traffic',			conditional},
     {{gsn_address, 2},					conditional},
     {{gsn_address, 3},					conditional},
     {?'Quality of Service Profile',			conditional}];

request_spec(v1, delete_pdp_context_request, _) ->
    [{{teardown_ind, 0},				conditional},
     {?'NSAPI',						mandatory}];

request_spec(v1, delete_pdp_context_response, _) ->
    [{?'Cause',						mandatory}];

request_spec(v1, _, _) ->
    [].

-define(Defaults, []).

validate_options(Opts) ->
    ?LOG(debug, "GGSN Gn/Gp Options: ~p", [Opts]),
    ergw_proxy_lib:validate_options(fun validate_option/2, Opts, ?Defaults).

validate_option(Opt, Value) ->
    ergw_proxy_lib:validate_option(Opt, Value).

init(#{proxy_sockets := ProxySockets, node_selection := NodeSelect,
       proxy_data_source := ProxyDS, contexts := Contexts},
     #{bearer := #{right := RightBearer} = Bearer} = Data) ->

    {ok, Session} = ergw_aaa_session_sup:new_session(self(), to_session([])),

    {ok, run, Data#{proxy_sockets => ProxySockets,
		    'Version' => v1,
		    'Session' => Session,
		    contexts => Contexts,
		    node_selection => NodeSelect,
		    bearer => Bearer#{right => RightBearer#bearer{interface = 'Core'}},
		    proxy_ds => ProxyDS}}.

handle_event(enter, _OldState, _State, _Data) ->
    keep_state_and_data;

handle_event(cast, {packet_in, _Socket, _IP, _Port, _Msg}, _State, _Data) ->
    ?LOG(warning, "packet_in not handled (yet): ~p", [_Msg]),
    keep_state_and_data;

handle_event(info, {timeout, _, {delete_pdp_context_request, Direction, _ReqKey, _Request}},
	     _State, Data) ->
    ?LOG(warning, "Proxy Delete PDP Context Timeout ~p", [Direction]),

    delete_forward_session(normal, Data),
    {next_state, shutdown, Data};

handle_event(info, _Info, _State, _Data) ->
    keep_state_and_data;

handle_event(state_timeout, #proxy_request{} = ReqKey, connecting, Data) ->
    gtp_context:request_finished(ReqKey),
    delete_forward_session(normal, Data),
    {next_state, shutdown, Data};

handle_event(state_timeout, _, connecting, Data) ->
    delete_forward_session(normal, Data),
    {next_state, shutdown, Data}.

handle_pdu(ReqKey, Msg, _State, Data) ->
    ?LOG(debug, "GTP-U v1 Proxy: ~p, ~p",
		[ReqKey, gtp_c_lib:fmt_gtp(Msg)]),
    {keep_state, Data}.

%%
%% resend request
%%
handle_request(ReqKey, Request, true, _State,
	       #{left_tunnel := LeftTunnel, right_tunnel := RightTunnel})
  when ?IS_REQUEST_TUNNEL(ReqKey, Request, LeftTunnel) ->
    ergw_proxy_lib:forward_request(RightTunnel, ReqKey, Request),
    keep_state_and_data;

handle_request(ReqKey, Request, true, _State,
	       #{left_tunnel := LeftTunnel, right_tunnel := RightTunnel})
  when ?IS_REQUEST_TUNNEL(ReqKey, Request, RightTunnel) ->
    ergw_proxy_lib:forward_request(LeftTunnel, ReqKey, Request),
    keep_state_and_data;

%%
%% some request type need special treatment for resends
%%
handle_request(ReqKey, #gtp{type = create_pdp_context_request} = Request, true,
	       _State, #{right_tunnel := RightTunnel}) ->
    ergw_proxy_lib:forward_request(RightTunnel, ReqKey, Request),
    keep_state_and_data;
handle_request(ReqKey, #gtp{type = ms_info_change_notification_request} = Request, true,
	       _State, #{left_tunnel := LeftTunnel, right_tunnel := RightTunnel})
  when ?IS_REQUEST_TUNNEL_OPTIONAL_TEI(ReqKey, Request, LeftTunnel) ->
    ergw_proxy_lib:forward_request(RightTunnel, ReqKey, Request),
    keep_state_and_data;

handle_request(_ReqKey, _Request, true, _State, _Data) ->
    ?LOG(error, "resend of request not handled ~p, ~p",
		[_ReqKey, gtp_c_lib:fmt_gtp(_Request)]),
    keep_state_and_data;

handle_request(ReqKey,
	       #gtp{type = create_pdp_context_request,
		    ie = IEs} = Request, _Resent, State,
	       #{context := Context0, aaa_opts := AAAopts, node_selection := NodeSelect,
		 left_tunnel := LeftTunnel0,
		 bearer := #{left := LeftBearer0} = Bearer0,
		 'Session' := Session} = Data)
  when State == run; State == connecting ->
    Context = ggsn_gn:update_context_from_gtp_req(Request, Context0),

    {LeftTunnel1, LeftBearer1} =
	case ggsn_gn:update_tunnel_from_gtp_req(Request, LeftTunnel0, LeftBearer0) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{tunnel = LeftTunnel0})
	end,
    Bearer1 = Bearer0#{left => LeftBearer1},
    LeftTunnel = gtp_path:bind(Request, LeftTunnel1),

    gtp_context:terminate_colliding_context(LeftTunnel, Context),

    SessionOpts0 = ggsn_gn:init_session(IEs, LeftTunnel, Context, AAAopts),
    SessionOpts = ggsn_gn:init_session_from_gtp_req(IEs, AAAopts, LeftTunnel, SessionOpts0),

    ProxyInfo =
	case handle_proxy_info(SessionOpts, LeftTunnel, LeftBearer1, Context, Data) of
	    {ok, Result2} -> Result2;
	    {error, Err2} -> throw(Err2#ctx_err{tunnel = LeftTunnel})
	end,

    ProxySocket = ergw_proxy_lib:select_gtp_proxy_sockets(ProxyInfo, Data),

    %% GTP v1 services only, we don't do v1 to v2 conversion (yet)
    Services = [{"x-3gpp-ggsn", "x-gn"}, {"x-3gpp-ggsn", "x-gp"},
		{"x-3gpp-pgw", "x-gn"}, {"x-3gpp-pgw", "x-gp"}],
    ProxyGGSN =
	case ergw_proxy_lib:select_gw(ProxyInfo, v1, Services, NodeSelect, ProxySocket) of
	    {ok, Result3} -> Result3;
	    {error, Err3} -> throw(Err3#ctx_err{tunnel = LeftTunnel})
	end,

    Candidates = ergw_proxy_lib:select_sx_proxy_candidate(ProxyGGSN, ProxyInfo, Data),
    SxConnectId = ergw_sx_node:request_connect(Candidates, NodeSelect, 1000),

    {ok, _} = ergw_aaa_session:invoke(Session, SessionOpts, start, #{async =>true}),

    ProxyContext = init_proxy_context(Context, ProxyInfo),
    RightTunnel0 = init_proxy_tunnel(ProxySocket, ProxyGGSN),
    RightTunnel = gtp_path:bind(RightTunnel0),

    ergw_sx_node:wait_connect(SxConnectId),
    {PCtx0, NodeCaps} =
	case ergw_pfcp_context:select_upf(Candidates) of
	    {ok, Result4} -> Result4;
	    {error, Err4} -> throw(Err4#ctx_err{context = ProxyContext, tunnel = LeftTunnel})   %% TBD: proxy context ???
	end,

    Bearer2 =
	case ergw_gsn_lib:assign_local_data_teid(left, PCtx0, NodeCaps, LeftTunnel, Bearer1) of
	    {ok, Result5} -> Result5;
	    {error, Err5} -> throw(Err5#ctx_err{tunnel = LeftTunnel})
	end,
    Bearer3 =
	case ergw_gsn_lib:assign_local_data_teid(right, PCtx0, NodeCaps, RightTunnel, Bearer2) of
	    {ok, Result6} -> Result6;
	    {error, Err6} -> throw(Err6#ctx_err{tunnel = LeftTunnel})
	end,

    PCC = ergw_proxy_lib:proxy_pcc(),
    {PCtx, Bearer} =
	case ergw_pfcp_context:create_session(gtp_context, PCC, PCtx0, Bearer3, Context) of
	    {ok, Result7} -> Result7;
	    {error, Err7} -> throw(Err7#ctx_err{tunnel = LeftTunnel})
	end,

    case gtp_context:remote_context_register_new(LeftTunnel, Bearer, Context) of
	ok -> ok;
	{error, Err8} -> throw(Err8#ctx_err{tunnel = LeftTunnel})
    end,

    DataNew =
	Data#{context => Context, proxy_context => ProxyContext, pfcp => PCtx,
	      left_tunnel => LeftTunnel, right_tunnel => RightTunnel, bearer => Bearer},

    forward_request(sgsn2ggsn, ReqKey, Request, RightTunnel,
		    maps:get(right, Bearer), ProxyContext, Data),

    %% 30 second timeout to have enough room for resents
    Action = [{state_timeout, 30 * 1000, ReqKey}],
    {next_state, connecting, DataNew, Action};

handle_request(ReqKey,
	       #gtp{type = update_pdp_context_request} = Request,
	       _Resent, connected,
	       #{proxy_context := ProxyContext,
		 left_tunnel := LeftTunnelOld, right_tunnel := RightTunnelOld,
		 bearer := #{left := LeftBearerOld, right := RightBearer} = Bearer} = Data)
  when ?IS_REQUEST_TUNNEL(ReqKey, Request, LeftTunnelOld) ->
    {LeftTunnel0, LeftBearer} =
	case ggsn_gn:update_tunnel_from_gtp_req(
	       Request, LeftTunnelOld#tunnel{version = v1}, LeftBearerOld) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{tunnel = LeftTunnelOld})
	end,
    LeftTunnel = ergw_gtp_gsn_lib:update_tunnel_endpoint(Request, LeftTunnelOld, LeftTunnel0),

    RightTunnel0 = ergw_gtp_gsn_lib:handle_peer_change(
		     LeftTunnel, LeftTunnelOld, RightTunnelOld#tunnel{version = v1}),
    RightTunnel = ergw_gtp_gsn_lib:update_tunnel_endpoint(RightTunnelOld, RightTunnel0),

    DataNew =
	Data#{left_tunnel => LeftTunnel, right_tunnel => RightTunnel,
	      bearer => Bearer#{left => LeftBearer}},

    forward_request(sgsn2ggsn, ReqKey, Request, RightTunnel, RightBearer, ProxyContext, Data),

    {keep_state, DataNew};

%%
%% GGSN to SGW Update PDP Context Request
%%
handle_request(ReqKey,
	       #gtp{type = update_pdp_context_request} = Request,
	       _Resent, connected,
	       #{context := Context,
		 left_tunnel := LeftTunnel, right_tunnel := RightTunnel,
		 bearer := #{left := LeftBearer}} = Data)
  when ?IS_REQUEST_TUNNEL(ReqKey, Request, RightTunnel) ->
    DataNew = bind_forward_path(ggsn2sgsn, Request, Data),

    forward_request(ggsn2sgsn, ReqKey, Request, LeftTunnel, LeftBearer, Context, Data),

    {keep_state, DataNew};

handle_request(ReqKey,
	       #gtp{type = ms_info_change_notification_request} = Request,
	       _Resent, connected,
	       #{proxy_context := ProxyContext,
		 left_tunnel := LeftTunnel, right_tunnel := RightTunnel,
		 bearer := #{right := RightBearer}} = Data)
  when ?IS_REQUEST_TUNNEL_OPTIONAL_TEI(ReqKey, Request, LeftTunnel) ->
    DataNew = bind_forward_path(sgsn2ggsn, Request, Data),

    forward_request(sgsn2ggsn, ReqKey, Request, RightTunnel, RightBearer, ProxyContext, Data),

    {keep_state, DataNew};

handle_request(ReqKey,
	       #gtp{type = delete_pdp_context_request} = Request,
	       _Resent, connected,
	       #{proxy_context := ProxyContext,
		 left_tunnel := LeftTunnel, right_tunnel := RightTunnel,
		 bearer := #{right := RightBearer}} = Data0)
  when ?IS_REQUEST_TUNNEL(ReqKey, Request, LeftTunnel) ->
    forward_request(sgsn2ggsn, ReqKey, Request, RightTunnel, RightBearer, ProxyContext, Data0),

    Msg = {delete_pdp_context_request, sgsn2ggsn, ReqKey, Request},
    Data = restart_timeout(?RESPONSE_TIMEOUT, Msg, Data0),

    {keep_state, Data};

handle_request(ReqKey,
	       #gtp{type = delete_pdp_context_request} = Request,
	       _Resent, connected,
	       #{context := Context,
		 left_tunnel := LeftTunnel, right_tunnel := RightTunnel,
		 bearer := #{left := LeftBearer}} = Data0)
  when ?IS_REQUEST_TUNNEL(ReqKey, Request, RightTunnel) ->
    forward_request(ggsn2sgsn, ReqKey, Request, LeftTunnel, LeftBearer, Context, Data0),

    Msg = {delete_pdp_context_request, ggsn2sgsn, ReqKey, Request},
    Data = restart_timeout(?RESPONSE_TIMEOUT, Msg, Data0),

    {keep_state, Data};

handle_request(#request{socket = Socket} = ReqKey, Msg, _Resent, _State, _Data) ->
    ?LOG(warning, "Unknown Proxy Message on ~p: ~p", [Socket, Msg]),
    gtp_context:request_finished(ReqKey),
    keep_state_and_data.

handle_response(#proxy_request{direction = sgsn2ggsn},
		timeout, #gtp{type = create_session_request}, State, _)
  when State == connected; State == connecting ->
    keep_state_and_data;

handle_response(#proxy_request{direction = sgsn2ggsn} = ProxyRequest,
		#gtp{type = create_pdp_context_response,
		     ie = #{?'Cause' := #cause{value = Cause}}} = Response,
		_Request, _State,
		#{context := Context, proxy_context := PrevProxyCtx, pfcp := PCtx0,
		  left_tunnel := LeftTunnel, right_tunnel := RightTunnel0,
		  bearer := #{left := LeftBearer, right := RightBearer0} = Bearer0} = Data) ->
    ?LOG(debug, "OK Proxy Response ~p", [Response]),

    {RightTunnel1, RightBearer} =
	case ggsn_gn:update_tunnel_from_gtp_req(Response, RightTunnel0, RightBearer0) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{tunnel = LeftTunnel})
	end,
    RightTunnel = gtp_path:bind(Response, RightTunnel1),
    Bearer = Bearer0#{right := RightBearer},

    ProxyContext = ggsn_gn:update_context_from_gtp_req(Response, PrevProxyCtx),

    gtp_context:remote_context_register(RightTunnel, Bearer, ProxyContext),

    Return =
	if ?CAUSE_OK(Cause) ->
		PCC = ergw_proxy_lib:proxy_pcc(),
		{PCtx, _} =
		    case ergw_pfcp_context:modify_session(PCC, [], #{}, Bearer, PCtx0) of
			{ok, Result2} -> Result2;
			{error, Err2} -> throw(Err2#ctx_err{tunnel = LeftTunnel})
		    end,
		DataNew =
		    Data#{proxy_context => ProxyContext, pfcp => PCtx,
			  right_tunnel => RightTunnel, bearer => Bearer},
		{next_state, connected, DataNew};
	   true ->
		delete_forward_session(normal, Data),
		{next_state, shutdown, Data}
	end,

    forward_response(ProxyRequest, Response, LeftTunnel, LeftBearer, Context),
    Return;

handle_response(#proxy_request{direction = sgsn2ggsn} = ProxyRequest,
		#gtp{type = update_pdp_context_response} = Response,
		_Request, _State,
		#{context := Context, proxy_context := ProxyContextOld, pfcp := PCtxOld,
		  left_tunnel := LeftTunnel, right_tunnel := RightTunnelOld,
		  bearer := #{left := LeftBearer, right := RightBearerOld} = Bearer0} = Data) ->
    ?LOG(debug, "OK Proxy Response ~p", [Response]),

    {RightTunnel0, RightBearer} =
	case ggsn_gn:update_tunnel_from_gtp_req(Response, RightTunnelOld, RightBearerOld) of
	    {ok, Result1} -> Result1;
	    {error, Err1} -> throw(Err1#ctx_err{tunnel = LeftTunnel})
	end,
    RightTunnel =
	ergw_gtp_gsn_lib:update_tunnel_endpoint(Response, RightTunnelOld, RightTunnel0),
    Bearer = Bearer0#{right := RightBearer},

    ProxyContext = ggsn_gn:update_context_from_gtp_req(Response, ProxyContextOld),

    gtp_context:remote_context_register(RightTunnel, Bearer, ProxyContext),

    PCC = ergw_proxy_lib:proxy_pcc(),
    {PCtx, _} =
	case ergw_pfcp_context:modify_session(PCC, [], #{}, Bearer, PCtxOld) of
	    {ok, Result2} -> Result2;
	    {error, Err2} -> throw(Err2#ctx_err{tunnel = LeftTunnel})
	end,

    forward_response(ProxyRequest, Response, LeftTunnel, LeftBearer, Context),

    DataNew =
	Data#{proxy_context => ProxyContext, pfcp => PCtx,
	      right_tunnel => RightTunnel, bearer => Bearer},
    {keep_state, DataNew};

handle_response(#proxy_request{direction = ggsn2sgsn} = ProxyRequest,
		#gtp{type = update_pdp_context_response} = Response,
		_Request, _State,
		#{proxy_context := ProxyContext,
		  right_tunnel := RightTunnel, bearer := #{right := RightBearer}}) ->
    ?LOG(debug, "OK SGSN Response ~p", [Response]),

    forward_response(ProxyRequest, Response, RightTunnel, RightBearer, ProxyContext),
    keep_state_and_data;

handle_response(#proxy_request{direction = sgsn2ggsn} = ProxyRequest,
		#gtp{type = ms_info_change_notification_response} = Response,
		_Request, _State,
		#{context := Context,
		  left_tunnel := LeftTunnel, bearer := #{left := LeftBearer}}) ->
    ?LOG(debug, "OK Proxy Response ~p", [Response]),

    forward_response(ProxyRequest, Response, LeftTunnel, LeftBearer, Context),
    keep_state_and_data;

handle_response(#proxy_request{direction = sgsn2ggsn} = ProxyRequest,
		#gtp{type = delete_pdp_context_response} = Response,
		_Request, _State,
		#{context := Context,
		  left_tunnel := LeftTunnel, bearer := #{left := LeftBearer}} = Data0) ->
    ?LOG(debug, "OK Proxy Response ~p", [Response]),

    forward_response(ProxyRequest, Response, LeftTunnel, LeftBearer, Context),

    Data = cancel_timeout(Data0),
    delete_forward_session(normal, Data),
    {next_state, shutdown, Data};

handle_response(#proxy_request{direction = ggsn2sgsn} = ProxyRequest,
		#gtp{type = delete_pdp_context_response} = Response,
		_Request, _State,
		#{proxy_context := ProxyContext,
		  right_tunnel := RightTunnel, bearer := #{right := RightBearer}} = Data0) ->
    ?LOG(debug, "OK SGSN Response ~p", [Response]),

    forward_response(ProxyRequest, Response, RightTunnel, RightBearer, ProxyContext),
    Data = cancel_timeout(Data0),
    delete_forward_session(normal, Data),
    {next_state, shutdown, Data};

handle_response(#proxy_request{request = ReqKey} = _ReqInfo,
		Response, _Request, _State, _Data) ->
    ?LOG(warning, "Unknown Proxy Response ~p", [Response]),

    gtp_context:request_finished(ReqKey),
    keep_state_and_data;

handle_response(_, _, #gtp{type = delete_pdp_context_request}, shutdown, _) ->
    keep_state_and_data;

handle_response({Direction, From}, timeout, #gtp{type = delete_pdp_context_request},
		shutdown_initiated, Data) ->
    pdp_context_teardown_response({error, timeout}, Direction, From, Data);

handle_response({Direction, From}, #gtp{type = delete_pdp_context_response},
		_Request, shutdown_initiated, Data) ->
    pdp_context_teardown_response(ok, Direction, From, Data).

terminate(_Reason, _State, _Data) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

handle_proxy_info(Session, Tunnel, Bearer, Context, #{proxy_ds := ProxyDS}) ->
    PI = ergw_proxy_lib:proxy_info(Session, Tunnel, Bearer, Context),
    case gtp_proxy_ds:map(ProxyDS, PI) of
	ProxyInfo when is_map(ProxyInfo) ->
	    ?LOG(debug, "OK Proxy Map: ~p", [ProxyInfo]),
	    {ok, ProxyInfo};

	{error, Cause} ->
	    ?LOG(warning, "Failed Proxy Map: ~p", [Cause]),
	    {error, ?CTX_ERR(?FATAL, Cause)}
    end.

delete_forward_session(Reason, #{pfcp := PCtx, 'Session' := Session}) ->
    URRs = ergw_pfcp_context:delete_session(Reason, PCtx),
    SessionOpts = to_session(gtp_context:usage_report_to_accounting(URRs)),
    ?LOG(debug, "Accounting Opts: ~p", [SessionOpts]),
    ergw_aaa_session:invoke(Session, SessionOpts, stop, #{async => true}).

init_proxy_tunnel(Socket, {_GwNode, GGSN}) ->
    Info = ergw_gtp_socket:info(Socket),
    RightTunnel =
	ergw_gsn_lib:assign_tunnel_teid(
	  local, Info, ergw_gsn_lib:init_tunnel('Core', Info, Socket, v1)),
    RightTunnel#tunnel{remote = #fq_teid{ip = GGSN}}.

init_proxy_context(#context{imei = IMEI, context_id = ContextId,
			    default_bearer_id = NSAPI, version = Version},
		   #{imsi := IMSI, msisdn := MSISDN, apn := DstAPN}) ->
    {APN, _OI} = ergw_node_selection:split_apn(DstAPN),

    #context{
       apn               = APN,
       imsi              = IMSI,
       imei              = IMEI,
       msisdn            = MSISDN,

       context_id        = ContextId,
       default_bearer_id = NSAPI,

       version           = Version
      }.

set_req_from_context(_, _, #context{apn = APN},
		     _K, #access_point_name{instance = 0} = IE)
  when is_list(APN) ->
    IE#access_point_name{apn = APN};
set_req_from_context(_, _, #context{imsi = IMSI},
		     _K, #international_mobile_subscriber_identity{instance = 0} = IE)
  when is_binary(IMSI) ->
    IE#international_mobile_subscriber_identity{imsi = IMSI};
set_req_from_context(_, _, #context{msisdn = MSISDN},
		  _K, #ms_international_pstn_isdn_number{instance = 0} = IE)
  when is_binary(MSISDN) ->
    IE#ms_international_pstn_isdn_number{msisdn = {isdn_address, 1, 1, 1, MSISDN}};
set_req_from_context(#tunnel{local = #fq_teid{ip = IP}}, _, _,
		     _K, #gsn_address{instance = 0} = IE) ->
    IE#gsn_address{address = ergw_inet:ip2bin(IP)};
set_req_from_context(_, #bearer{local = #fq_teid{ip = IP}}, _,
		     _K, #gsn_address{instance = 1} = IE) ->
    IE#gsn_address{address = ergw_inet:ip2bin(IP)};
set_req_from_context(_, #bearer{local = #fq_teid{teid = TEI}}, _,
		     _K, #tunnel_endpoint_identifier_data_i{instance = 0} = IE) ->
    IE#tunnel_endpoint_identifier_data_i{tei = TEI};
set_req_from_context(#tunnel{local = #fq_teid{teid = TEI}}, _, _,
		     _K, #tunnel_endpoint_identifier_control_plane{instance = 0} = IE) ->
    IE#tunnel_endpoint_identifier_control_plane{tei = TEI};
set_req_from_context(_, _, _, _K, IE) ->
    IE.

update_gtp_req_from_context(Tunnel, Bearer, Context, GtpReqIEs) ->
    maps:map(set_req_from_context(Tunnel, Bearer, Context, _, _), GtpReqIEs).

build_context_request(#tunnel{remote = #fq_teid{teid = TEI}} = Tunnel, Bearer,
		      Context, NewPeer, SeqNo,
		      #gtp{type = Type, ie = RequestIEs} = Request) ->
    ProxyIEs0 = maps:without([?'Recovery'], RequestIEs),
    ProxyIEs1 = update_gtp_req_from_context(Tunnel, Bearer, Context, ProxyIEs0),
    ProxyIEs = gtp_v1_c:build_recovery(Type, Tunnel, NewPeer, ProxyIEs1),
    Request#gtp{tei = TEI, seq_no = SeqNo, ie = ProxyIEs}.

msg(#tunnel{remote = #fq_teid{teid = RemoteCntlTEI}}, Type, RequestIEs) ->
    #gtp{version = v1, type = Type, tei = RemoteCntlTEI, ie = RequestIEs}.

send_request(Tunnel, DstIP, DstPort, T3, N3, Msg, ReqInfo) ->
    gtp_context:send_request(Tunnel, DstIP, DstPort, T3, N3, Msg, ReqInfo).

send_request(#tunnel{remote = #fq_teid{ip = RemoteCntlIP}} = Tunnel, T3, N3, Msg, ReqInfo) ->
    send_request(Tunnel, RemoteCntlIP, ?GTP2c_PORT, T3, N3, Msg, ReqInfo).

send_request(Tunnel, T3, N3, Type, RequestIEs, ReqInfo) ->
    send_request(Tunnel, T3, N3, msg(Tunnel, Type, RequestIEs), ReqInfo).

initiate_pdp_context_teardown(sgsn2ggsn = Direction, From, connected,
			      #{right_tunnel := Tunnel,
				proxy_context := #context{default_bearer_id = NSAPI}} = Data) ->
    Type = delete_pdp_context_request,
    RequestIEs0 = [#cause{value = request_accepted},
		   #teardown_ind{value = 1},
		   #nsapi{nsapi = NSAPI}],
    RequestIEs = gtp_v1_c:build_recovery(Type, Tunnel, false, RequestIEs0),
    send_request(Tunnel, ?T3, ?N3, Type, RequestIEs, {Direction, From}),
    maps:update_with(shutdown, [Direction|_], [Direction], Data);
initiate_pdp_context_teardown(ggsn2sgsn = Direction, From, State,
			      #{left_tunnel := Tunnel,
				context := #context{default_bearer_id = NSAPI}} = Data)
  when State == connected; State == connecting ->
    Type = delete_pdp_context_request,
    RequestIEs0 = [#cause{value = request_accepted},
		   #teardown_ind{value = 1},
		   #nsapi{nsapi = NSAPI}],
    RequestIEs = gtp_v1_c:build_recovery(Type, Tunnel, false, RequestIEs0),
    send_request(Tunnel, ?T3, ?N3, Type, RequestIEs, {Direction, From}),
    maps:update_with(shutdown, [Direction|_], [Direction], Data);
initiate_pdp_context_teardown(_, _, _, Data) ->
    Data.

pdp_context_teardown_response(Answer, Direction, From, #{shutdown := Shutdown0} = Data) ->
    case lists:delete(Direction, Shutdown0) of
	[] ->
	    Action = case From of
			 undefined -> [];
			 _ -> [{reply, From, Answer}]
		     end,
	    {next_state, shutdown, maps:remove(shutdown, Data), Action};
	Shutdown ->
	    {keep_state, Data#{shutdown => Shutdown}}
    end.

bind_forward_path(sgsn2ggsn, Request,
		  #{left_tunnel := LeftTunnel, right_tunnel := RightTunnel} = Data) ->
    Data#{left_tunnel => gtp_path:bind(Request, LeftTunnel),
	  right_tunnel => gtp_path:bind(RightTunnel)};
bind_forward_path(ggsn2sgsn, Request,
		  #{left_tunnel := LeftTunnel, right_tunnel := RightTunnel} = Data) ->
    Data#{left_tunnel => gtp_path:bind(LeftTunnel),
	  right_tunnel => gtp_path:bind(Request, RightTunnel)}.

forward_request(Direction, ReqKey, #gtp{seq_no = ReqSeqNo, ie = ReqIEs} = Request,
		Tunnel, Bearer, Context, Data) ->
    FwdReq = build_context_request(Tunnel, Bearer, Context, false, undefined, Request),
    ergw_proxy_lib:forward_request(Direction, Tunnel, FwdReq, ReqKey,
				   ReqSeqNo, is_map_key(?'Recovery', ReqIEs), Data).

forward_response(#proxy_request{request = ReqKey, seq_no = SeqNo, new_peer = NewPeer},
		 Response, Tunnel, Bearer, Context) ->
    GtpResp = build_context_request(Tunnel, Bearer, Context, NewPeer, SeqNo, Response),
    gtp_context:send_response(ReqKey, GtpResp).


cancel_timeout(#{timeout := TRef} = Data) ->
    case erlang:cancel_timer(TRef) of
        false ->
            receive {timeout, TRef, _} -> ok
            after 0 -> ok
            end;
        _ ->
            ok
    end,
    maps:remove(timeout, Data);
cancel_timeout(Data) ->
    Data.

restart_timeout(Timeout, Msg, Data) ->
    cancel_timeout(Data),
    Data#{timeout => erlang:start_timer(Timeout, self(), Msg)}.

close_context(Side, TermCause, State, Data)
  when State == connected; State == connecting ->
    case Side of
	left  ->
	    initiate_pdp_context_teardown(sgsn2ggsn, undefined, State, Data);
	right ->
	    initiate_pdp_context_teardown(ggsn2sgsn, undefined, State, Data);
	both ->
	    initiate_pdp_context_teardown(sgsn2ggsn, undefined, State, Data),
	    initiate_pdp_context_teardown(ggsn2sgsn, undefined, State, Data)
    end,
    delete_forward_session(TermCause, Data).

delete_context(From, TermCause, State, Data0)
  when State == connected; State == connecting ->
    Data1 = initiate_pdp_context_teardown(sgsn2ggsn, From, State, Data0),
    Data = initiate_pdp_context_teardown(ggsn2sgsn, From, State, Data1),
    delete_forward_session(TermCause, Data),
    {next_state, shutdown_initiated, Data};
delete_context(undefined, _, _, _) ->
    keep_state_and_data;
delete_context(From, _, _, _) ->
    {keep_state_and_data, [{reply, From, ok}]}.
