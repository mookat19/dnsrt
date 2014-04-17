--[[
LuCI - Lua Configuration Interface

Copyright 2014 Owen Kirby <oskirby@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id: $
]]--

require("luci.tools.webadmin")
m = Map("dnsrt", translate("DNS Router"),
	translate("DNS Router is a routing daemon that listens for DNS messages " ..
		"and updates the routing table with redirects based on domain name " ..
		"matches."))

s = m:section(TypedSection, "main", translate("DNS Router Configuration"))
s.anonymous = true
s.addremove = false

r = s:option(Value, "router", translate("Router"),
	translate("Next hop address for intercepted " ..
	"<abbr title=\"Domain Name System\">DNS</abbr> records."))
r.rmempty = false
r.datatype = "ipaddr"
r.placeholder = "1.2.3.4"

iface = s:option(ListValue, "interface", translate("Interface"))     
luci.tools.webadmin.cbi_add_networks(iface)

dn = s:option(DynamicList, "domain", translate("Domain names"),
        translate("List of <abbr title=\"Domain Name System\">DNS</abbr> " ..
                                "domains to intercept for routing"))
dn.datatype = "hostname"
dn.placeholder = "/example.org/10.1.2.3"       

s2 = m:section(TypedSection, "_dummy", translate("DNS Router Cache"), "")
s2.addremove = false
s2.anonymous = true
s2.template = "dnsrt_cache"

return m
