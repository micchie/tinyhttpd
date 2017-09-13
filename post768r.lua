local requests = { }
local total = 0
local x = {}
local counter = 0

function fillarray(x, num)
	for i = 1, num do
		x[i] = i
	end
end

function shufarray(x, num)
	math.randomseed(os.time())

	for i = 1, num - 1, 1 do
		r = math.random(i, num)
		if (i < r) then x[i], x[r] = x[r], x[i] end
	end
	--for i = 1, num, 1 do print(x[i]) end
end

function str(x)
	return x..""
end

init = function(args)
	plen = 768
	hlen = 8
	fillarray(x, 10)
	--[[
	shufarray(x, #x)
	local f = io.open("random-1m.txt", "r")
	i = 0
	for l in f:lines() do
		x[i] = l
		i = i + 1
	end
	f:close()
	print(x[900000])
	]]

	wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
	wrk.method = "POST"

	s = "x"
	h = " "

	for i = 1, #x, 1 do
		wrk.body = x[i]
		for j = 1, hlen - #(str(x[i])) do
			wrk.body = wrk.body..h
		end
		for j = 1, plen - hlen do
			wrk.body = wrk.body..s
		end
		table.insert(requests, wrk.format())
	end
	--total = #table
	total = #x
end

request = function()
	local n = math.random(total)
	return requests[n]
	--[[
	if counter == total then
		counter = 0
	end
	return requests[x[counter] ]
	]]
end

