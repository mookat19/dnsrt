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
end
