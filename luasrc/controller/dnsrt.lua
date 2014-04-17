--[[
LuCI - Lua Configuration Interface

Copyright 2014 Owen Kirby <oskirby@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id: $
]]--

module("luci.controller.dnsrt", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/dnsrt") then
		return
	end

	entry({"admin", "network", "dnsrt"}, cbi("dnsrt"), _("DNS Router"), 62)
	entry({"admin", "network", "dnsrt", "cache_status"}, call("cache_status")).leaf = true
end

function cache_status()
	luci.http.prepare_content("application/json")
	local rv = { }
	local nfs = require "nixio.fs"
	local cachefile = "/tmp/dnsrt.cache"
	
	local fd = io.open(cachefile, "r")
	if not fd then
		luci.http.write_json(rv)
		return
	end
	
	while true do
		local ln = fd:read("*l")
		if not ln then
			break
		end
		local domain, ttl, class, type, data = ln:match("^(%S+) (%d+) (%S+) (%S+) (%S+)")
		rv[#rv+1] = {
			domain	= domain,
			ttl	= os.difftime(tonumber(ttl) or 0, os.time()),
			class	= "IN",
			type	= type,
			data	= data
		}
	end
	
	fd:close()	
	luci.http.write_json(rv)
end

