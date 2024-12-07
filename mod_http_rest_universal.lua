-- HTTP REST API allowing invocation of any loaded module function.
--
-- Copyright (c) 2024 Rémi Bardon <remi@remibardon.name>

local encodings = require "prosody.util.encodings";
local base64 = encodings.base64;
-- local log = require "prosody.util.logger".init("http_rest_universal");
local errors = require "prosody.util.error";
local jid = require "prosody.util.jid";
local um = require "prosody.core.usermanager";

local tokens = module:depends("tokenauth");

-- COPYRIGHT: Greatly inspired by `mod_rest`.
local post_errors = errors.init("mod_http_rest_universal", {
	noauthz = { code = 401; type = "auth"; condition = "not-authorized"; text = "No credentials provided" };
	unauthz = { code = 403; type = "auth"; condition = "not-authorized"; text = "Credentials not accepted" };
	malformauthz = { code = 403; type = "auth"; condition = "not-authorized"; text = "Credentials malformed" };
	prepauthz = { code = 403; type = "auth"; condition = "not-authorized"; text = "Credentials failed stringprep" };
	parse = { code = 400; type = "modify"; condition = "not-well-formed"; text = "Failed to parse payload" };
	xmlns = { code = 422; type = "modify"; condition = "invalid-namespace"; text = "'xmlns' attribute must be empty" };
	name = { code = 422; type = "modify"; condition = "unsupported-stanza-type"; text = "Invalid stanza, must be 'message', 'presence' or 'iq'." };
	to = { code = 422; type = "modify"; condition = "improper-addressing"; text = "Invalid destination JID" };
	from = { code = 422; type = "modify"; condition = "invalid-from"; text = "Invalid source JID" };
	from_auth = { code = 403; type = "auth"; condition = "not-authorized"; text = "Not authorized to send stanza with requested 'from'" };
	iq_type = { code = 422; type = "modify"; condition = "invalid-xml"; text = "'iq' stanza must be of type 'get' or 'set'" };
	iq_tags = { code = 422; type = "modify"; condition = "bad-format"; text = "'iq' stanza must have exactly one child tag" };
	mediatype = { code = 415; type = "cancel"; condition = "bad-format"; text = "Unsupported media type" };
	size = { code = 413; type = "modify"; condition = "resource-constraint", text = "Payload too large" };
});

-- COPYRIGHT: Greatly inspired by `mod_rest`.
local token_session_errors = errors.init("mod_tokenauth", {
	["internal-error"] = { code = 500; type = "wait"; condition = "internal-server-error" };
	["invalid-token-format"] = { code = 403; type = "auth"; condition = "not-authorized"; text = "Credentials malformed" };
	["not-authorized"] = { code = 403; type = "auth"; condition = "not-authorized"; text = "Credentials not accepted" };
});

-- COPYRIGHT: Greatly inspired by `mod_rest`.
local function check_credentials(request) -- > session | boolean, error
	local auth_type, auth_data = string.match(request.headers.authorization, "^(%S+)%s(.+)$");
	auth_type = auth_type and auth_type:lower();
	if not (auth_type and auth_data) or not auth_mechanisms:contains(auth_type) then
		return nil, post_errors.new("noauthz", { request = request });
	end

	if auth_type == "basic" then
		local creds = base64.decode(auth_data);
		if not creds then
			return nil, post_errors.new("malformauthz", { request = request });
		end
		local username, password = string.match(creds, "^([^:]+):(.*)$");
		if not username then
			return nil, post_errors.new("malformauthz", { request = request });
		end
		username, password = encodings.stringprep.nodeprep(username), encodings.stringprep.saslprep(password);
		if not username or not password then
			return false, post_errors.new("prepauthz", { request = request });
		end
		if not um.test_password(username, module.host, password) then
			return false, post_errors.new("unauthz", { request = request });
		end
		return { username = username; host = module.host };
	elseif auth_type == "bearer" then
		if tokens.get_token_session then
			local token_session, err = tokens.get_token_session(auth_data);
			if not token_session then
				return false, token_session_errors.new(err or "not-authorized", { request = request });
			end
			return token_session;
		else -- COMPAT w/0.12
			local token_info = tokens.get_token_info(auth_data);
			if not token_info or not token_info.session then
				return false, post_errors.new("unauthz", { request = request });
			end
			return token_info.session;
		end
	end
	return nil, post_errors.new("noauthz", { request = request });
end

-- COPYRIGHT: Greatly inspired by `mod_http_oauth2`.
local function get_request_credentials(request)
	if not request.headers.authorization then return; end

	local auth_type, auth_data = string.match(request.headers.authorization, "^(%S+)%s(.+)$");
	if not auth_type then return nil; end

	-- As described in Section 2.3 of [RFC5234], the string Bearer is case-insensitive.
	-- https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11#section-5.1.1
	auth_type = auth_type:lower();

	if auth_type == "basic" then
		local creds = base64.decode(auth_data);
		if not creds then return; end
		local username, password = string.match(creds, "^([^:]+):(.*)$");
		if not username then return; end
		return {
			type = "basic";
			username = username;
			password = password;
		};
	elseif auth_type == "bearer" then
		return {
			type = "bearer";
			bearer_token = auth_data;
		};
	end

	return nil;
end

-- COPYRIGHT: Greatly inspired by `mod_rest`.
local function handle_request(event, path, body)
	local request, response = event.request, event.response;
	local log = request.log or module._log;
	local from;
	local origin;

	if not request.headers.authorization and www_authenticate_header then
		response.headers.www_authenticate = www_authenticate_header;
		return post_errors.new("noauthz");
	end

	local credentials = get_request_credentials(request);
	if not credentials or not credentials.bearer_token then
		module:log("debug", "Missing credentials for UserInfo endpoint: %q", credentials)
		return 401;
	end

	local err;
	origin, err = check_credentials(request);
	if not origin then
		return err or post_errors.new("unauthz");
	end
	from = jid.join(origin.username, origin.host, origin.resource);
	origin.full_jid = from;
	origin.type = "c2s";
	origin.log = log;
end

module:depends("http");
module:provides("http", {
	route = {
		["POST /*"] = handle_request;
	};
});
