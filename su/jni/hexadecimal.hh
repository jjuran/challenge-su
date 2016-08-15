/*
	hexadecimal.hh
	--------------
*/

#ifndef HEXADECIMAL_HH
#define HEXADECIMAL_HH

typedef unsigned char byte;

char* hexpcpy_lower( char* out, const void* in, unsigned n );

byte* unhexpcpy( byte* out, const char* in, unsigned n );

#endif
