local x = ""
local totlen = 1280
local hlen = 8
local t = totlen - hlen
local p = 1000000

for i = 1, t, 1 do
	x = x.."x"
end
request = function()
	local n = math.random(p)
	wrk.method = "POST"
	wrk.path = "http://www.micchie.net/"
	wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
	wrk.body = string.format("%-08d%s", n, x)
	return wrk.format(wrk.method, wrk.path, wrk.headers, wrk.body)
end
