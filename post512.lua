wrk.method = "POST"
s = "foo=bar&baz=quux"
wrk.body = s
for i = 0, 31 do
	wrk.body = wrk.body..s
end
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"

