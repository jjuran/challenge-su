/*
	hexadecimal.cc
	--------------
*/

#include "hexadecimal.hh"


#pragma exceptions off


typedef byte half;

const half bad = 0;

// (hex-digit & 0x1f) -> numeric nibble
static half decoded_hex_table[] =
{
	bad, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, bad,
	bad, bad, bad, bad, bad, bad, bad, bad,
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
	0x8, 0x9, bad, bad, bad, bad, bad, bad
};

// (nibble & 0x0f) -> ASCII hex digit
static char encoded_hex_table[] =
{
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

static inline
half decoded_hex_digit( char c )
{
	return decoded_hex_table[ c & 0x1f ];
}

static inline
char encoded_hex_char( half d )
{
	return encoded_hex_table[ d & 0x0f ];
}

char* hexpcpy_lower( char* out, const void* in, unsigned n )
{
	const byte* p = (const byte*) in;
	
	while ( n-- )
	{
		const byte c = *p++;
		
		*out++ = encoded_hex_char( c >> 4 );
		*out++ = encoded_hex_char( c >> 0 );
	}
	
	return out;
}

byte* unhexpcpy( byte* out, const char* in, unsigned n )
{
	while ( n-- )
	{
		const half h = decoded_hex_digit( *in++ ) << 4;
		const half l = decoded_hex_digit( *in++ ) << 0;
		
		*out++ = h | l;
	}
	
	return out;
}
