--[[
	This is a pure Lua implementation of sha1 (Secure Hash Algorithm 1). 
	Based on lua-bit-numberlua : https://github.com/davidm/lua-bit-numberlua/
	Author = "Abdelmouneim Hanine <sup3rnova.m0nster@gmail.com>"
	URL = https://github.com/abdelmouneim/
	LICENSE = {
	
		Copyright (c) 2016 Abdelmouneim Hanine <sup3rnova.m0nster@gmail.com>
		Permission is hereby granted, free of charge, to any person obtaining a copy
		of this software and associated documentation files (the "Software"), to deal
		in the Software without restriction, including without limitation the rights
		to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
		copies of the Software, and to permit persons to whom the Software is
		furnished to do so, subject to the following conditions:
		The above copyright notice and this permission notice shall be included in
		all copies or substantial portions of the Software.
		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
		IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
		FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
		LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
		OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
		THE SOFTWARE.	
	}	
]]


local bit = require 'numberlua';
local string = require "string";
-- this function take a sting as it's argument and return a table that contains the ascii code of it's chars.
function string_to_ascii_code(str)
	local str_len = #chunk;
	local result = {};
	for i=1,str_len do 
		result[i] = string.byte(str,i);
	end
	return result;
end

function num2hex(num)
	local hexstr = '0123456789abcdef'
	local s = ''
	while num > 0 do
		local mod = math.fmod(num, 16)
		s = string.sub(hexstr, mod+1, mod+1) .. s
		num = math.floor(num / 16)
	end
	if s == '' then s = '0' end
	if s:len() % 2 ~= 0 then s = '0'..s end
	return s
end

--- Returns HEX representation of str
function str2hex(str)
	local hex = ''
	while #str > 0 do
		local hb = num2hex(string.byte(str, 1, 1))
		if #hb < 2 then hb = '0' .. hb end
		hex = hex .. hb
		str = string.sub(str, 2)
	end
	return hex
end

function size_as_8bytes(size)
	local result = "";
	size_as_hex = num2hex(size*8);
	size_len_bytes = #size_as_hex / 2 ;
	if size_len_bytes > 0 then 
		result = string.rep( string.char(0), 8 - size_len_bytes );
	end
	for i = 1,#size_as_hex,2 do
		 result = result..string.char( tonumber( size_as_hex:sub(i,i+1), 16 ) )	;
	end
	return result;	 
end

function sha1( chunk)
	-- chunk = msg + "0x80" + Zero's + msg_len;
	-- msg_len is coded as 64 bits = 8 octets;
	-- chunk lenght should be modulo 64 bytes
	local chunk_len = #chunk;
	local chunk_len_without_zeros = #chunk + 1 + 8; 
	local char_1 = string.char(0x80);
	local zeros = "";
	local zeros_len = chunk_len_without_zeros % 64;
	if zeros_len > 0 then 
		zeros = string.rep(string.char(0), 64 - zeros_len);
	end
	local chunk_len_as_8bytes = size_as_8bytes(chunk_len);
	chunk = chunk..char_1..zeros..chunk_len_as_8bytes;
	local number_of_chunk = #chunk/64;
	local iteration = 0;
	local A, B, C, D, E, f, k, temp;
	local h0, h1, h2, h3, h4 = 1732584193, 4023233417, 2562383102, 271733878, 3285377520;
	while iteration < number_of_chunk do 
		-- Break The Chunk Into words
		-- Break each chunk up into sixteen 32-bit words
		local start_index = iteration * 64 + 1;
		iteration = iteration + 1;
		local words = {};
		local j = 0; -- words[0] ---> words[15]
		for i = 1,64,4 do
			local word = str2hex( chunk:sub(start_index+i-1,start_index+i+2) );
			--result = result..string.char( tonumber( size_as_hex:sub(start_index+i,i+3), 16 ) );
			words[j] = tonumber(word,16); -- from hex to decimal
			j = j+1;
		end
		--  'Extend' into 80 words
		--  words[16] ---> words[79]
		for i = 16,79 do
			-- We begin by selecting four of the current words. The ones we want are: [i-3], [i-8], [i-14] and [i-16].
			-- Now that we have our words selected we will start by performing what's known as an 'XOR' or 'Exclusive OR' on them.
			-- Left rotate
			words[i] = bit.bxor( bit.bxor( words[i-3], words[i-8] ) , bit.bxor( words[i-14], words[i-16] ) );
			words[i] = bit.rol( words[i], 1 ) ;
			
		end
		-- Set the letters A-->E equal to the variables h0-->h4. 
		A, B, C, D, E = h0, h1, h2, h3, h4;
		-- The main loop
		-- 	Words 0-19 go to function 1
		-- 	Words 20-39 go to function 2
		-- 	Words 40-59 go to function 3
		-- 	Words 60-79 go to function 4
		for i=0, 79 do
			if i <= 19 then -- function 1
				-- set f = (B AND C) or (!B AND D)
				-- set k = 1518500249
				f = bit.bor( bit.band( B, C ) , bit.band( bit.bnot(B), D) );
				k = 1518500249
			elseif i <= 39 then -- function 2
				-- set f =  B XOR C XOR D
				-- set k = 1859775393
				f = bit.bxor( bit.bxor( B, C ) , D );
				k = 1859775393;				
			elseif i <= 59 then -- function 3
				-- set f =  (B AND C) OR (B AND D) OR (C AND D)
				-- set k = 2400959708
				f = bit.bor( bit.bor( bit.band( B, C ) , bit.band( B, D ) ) , bit.band( C, D ) )
				k = 2400959708
			else-- function 4
				-- set f = B XOR C XOR D, same as function 2
				-- set k = 3395469782
				f = bit.bxor( bit.bxor( B, C ) , D );
				k = 3395469782
			end -- end if 
			-- temp = (A left rotate 5) + F + E + K + (the current word).
			-- E = D
			-- D = C
			-- C = B Left Rotate 30
			-- B = A
			-- A = temp
			temp = bit.band (bit.rol(A,5)+ f + E + k + words[i] , 0xffffffff ) ; -- and 0xffffffff to trancate the result to 32bits
			E, D, C, B, A = D, C, bit.rol(B,30), A, temp;

		end -- end for i = 0 ---> 79
		-- The end 
		h0, h1 = bit.band(h0+A, 0xffffffff), bit.band(h1+B, 0xffffffff) ; 
		h2, h3 = bit.band(h2+C, 0xffffffff), bit.band(h3+D, 0xffffffff) ; 
		h4 = bit.band(h4+E, 0xffffffff) ; 


	end -- end while iteration < number_of_chunk
	
	return num2hex(h0)..num2hex(h1)..num2hex(h2)..num2hex(h3)..num2hex(h4);

end -- end function 


-- Example 
print ( sha1( "A Test" ) );
