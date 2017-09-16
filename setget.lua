local x = ""
local y = ""
local setlen = 1280
local hlen = 8
local t = setlen - hlen
local p = 8
local getlen = 64
local t2 = getlen - hlen

for i = 1, t2, 1 do
	y = y.."y"
end
for i = 1, t, 1 do
	x = x.."x"
end
request = function()
	local n = math.random(p*2)

	if n < p then
		wrk.method = "POST"
		wrk.path = "http://www.micchie.net/"
		wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
		wrk.body = string.format("%-08d%s", n, x)
	else
		wrk.method = "GET"
		wrk.path = string.format("/%-08d", n-p)
		wrk.body = y
	end
	return wrk.format(wrk.method, wrk.path, wrk.headers, wrk.body)
end
