local x = ""
local totlen = 1280

for i = 1, totlen, 1 do
	x = x.."x"
end
request = function()
	wrk.method = "POST"
	wrk.path = "http://www.micchie.net/"
	wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
	wrk.body = string.format(1, x)
	return wrk.format(wrk.method, wrk.path, wrk.headers, wrk.body)
end
