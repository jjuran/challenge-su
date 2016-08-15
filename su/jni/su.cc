/*
	su.cc
	-----
	
	This is an implementation of `su` that authenticates non-root users by
	issuing a cryptographic challenge, which must be answered by an Ed25519
	signature of the challenge using the correct secret key.  It's intended
	for use with Android devices.
	
	Unlike the typical Android `su`, this one does not solicit confirmation
	by the user through a Superuser app.  Instead, it issues a cryptographic
	challenge on stdout, to which it expects a response on stdin.
	
	The challenge is a sequence of 32 mostly-random bytes, in hexadecimal
	form.  The response is an Ed25519 signature of the challenge.  For the
	benefit of `adb shell` users, the actual message to be signed consists
	of the 64 hexadecimal digits (using lowercase letters) followed by LF --
	65 bytes in total.  The trailing newline is included for convenience
	with utilities like `echo` and `cat`.
	
	The message must be signed with the Ed25519 secret key corresponding to
	the public key installed on the device.  The resulting 64-byte signature
	must then be encoded in hexadecimal (either case) and entered on stdin
	(presumably via Paste), followed by a newline (LF).  If the signature
	verifies, then `su` sets the gid and uid to root and execs the shell.
	
	The intended use case is a user running `adb shell` from a trusted host
	where the secret key is stored, seeking to invoke a root shell for the
	purpose of performing privileged maintenance tasks.
	
	DISCLAIMER:  I'm not a cryptographer or a security expert.  Don't assume
	this program achieves any particular standard of security or correctness.
	Read the code and do your own analysis.
*/

// POSIX
#include <fcntl.h>
#include <unistd.h>

// Standard C
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ed25519-donna
#include "ed25519.h"

// su
#include "hexadecimal.hh"


#pragma exceptions off


#define PROGRAM  "su"

#define PUBLIC_KEY_PATH  "/etc/su/public_key"
#define RANDOM_PATH      "/dev/urandom"
#define SHELL_PATH       "/system/bin/sh"

const unsigned n_random_bytes = 28;


#define STR_LEN( s )  "" s, (sizeof s - 1)

#define ERROR( s )  error( STR_LEN( PROGRAM ": " s ": " ) )
#define FAIL( s )   fail ( STR_LEN( PROGRAM ": " s "\n" ) )

static int exit_status = 125;

static
void error( const char* msg, unsigned len )
{
	const char* err = strerror( errno );
	
	write( STDERR_FILENO, msg, len );
	write( STDERR_FILENO, err, strlen( err ) );
	write( STDERR_FILENO, STR_LEN( "\n" ) );
	
	exit( exit_status );
}

static
void fail( const char* msg, unsigned len )
{
	write( STDERR_FILENO, msg, len );
	
	exit( exit_status );
}

static
void make_challenge( uint32_t* buffer )
{
	uint32_t* p = buffer;
	
	const uint32_t t = (uint32_t) time( NULL );
	
	*p++ = t;
	
	int fd = open( RANDOM_PATH, O_RDONLY );
	
	if ( fd < 0 )
	{
		ERROR( RANDOM_PATH );
	}
	
	ssize_t n_read = read( fd, p, n_random_bytes );
	
	if ( n_read < 0 )
	{
		ERROR( RANDOM_PATH );
	}
	
	if ( n_read != n_random_bytes )
	{
		FAIL( "insufficient data from " RANDOM_PATH );
	}
	
	close( fd );
}

static
bool response_answers_challenge( const uint8_t*  sig,
                                 const uint8_t*  msg,
                                 unsigned        msg_len )
{
	const int fd = open( PUBLIC_KEY_PATH, O_RDONLY );
	
	if ( fd < 0 )
	{
		ERROR( PUBLIC_KEY_PATH );
	}
	
	ed25519_public_key public_key;
	
	ssize_t n_read = read( fd, public_key, sizeof public_key );
	
	if ( n_read < 0 )
	{
		ERROR( PUBLIC_KEY_PATH );
	}
	
	if ( n_read != sizeof public_key )
	{
		FAIL( "insufficient data from " PUBLIC_KEY_PATH );
	}
	
	close( fd );
	
	int nok = ed25519_sign_open( msg, msg_len, public_key, sig );
	
	return ! nok;
}

static
bool authenticate()
{
	const unsigned challenge_size = sizeof (uint32_t) + n_random_bytes;
	
	write( STDOUT_FILENO, STR_LEN( "Standby..." ) );
	sleep( 1 );
	write( STDOUT_FILENO, STR_LEN( "\n" ) );
	
	uint32_t challenge[ challenge_size / sizeof (uint32_t) ];
	
	make_challenge( challenge );
	
	char challenge_hex[ challenge_size * 2 + 1 ];
	
	char* p = hexpcpy_lower( challenge_hex, &challenge, challenge_size );
	
	*p = '\n';
	
	write( STDOUT_FILENO, STR_LEN( "Challenge: " ) );
	write( STDOUT_FILENO, challenge_hex, sizeof challenge_hex );  // has LF
	
	char response_hex[ 256 ];
	
	ssize_t n_read = read( STDIN_FILENO, response_hex, sizeof response_hex );
	
	if ( n_read < 0 )
	{
		ERROR( "<response>" );
	}
	
	if ( n_read == 129  &&  response_hex[ 128 ] == '\n' )
	{
		uint8_t response[ 64 ];
		
		unhexpcpy( response, response_hex, sizeof response );
		
		const bool valid = response_answers_challenge( response,
		                                               (uint8_t*) challenge_hex,
		                                               sizeof challenge_hex );
		
		if ( valid )
		{
			write( STDOUT_FILENO, STR_LEN( "ACCESS GRANTED\n" ) );
			return true;
		}
	}
	
	write( STDOUT_FILENO, STR_LEN( "ACCESS DENIED\n" ) );
	return false;
}

int main( int argc, char** argv )
{
	if ( argc > 1 )
	{
		FAIL( "no arguments are allowed" );
	}
	
	if ( geteuid() != 0 )
	{
		FAIL( "not running as root (is it setuid?)" );
	}
	
	const int current_uid = getuid();
	
	if ( current_uid != 0 )
	{
		const bool ok = authenticate();
		
		if ( ! ok )
		{
			exit( 1 );
		}
	}
	
	const uid_t uid = 0;
	const gid_t gid = 0;
	
	if ( setgid( gid ) < 0 )
	{
		ERROR( "setgid" );
	}
	
	if ( setuid( uid ) < 0 )
	{
		ERROR( "setuid" );
	}
	
	execlp( SHELL_PATH, "sh", NULL );
	
	exit_status = (errno == ENOENT) + 126;
	
	ERROR( SHELL_PATH );
	
	return 0;
}
