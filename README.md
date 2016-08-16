challenge-su
============

Copyright 2016 Joshua Juran

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

----

This program is free software: you can redistribute it and/or modify
it under the terms of the [GNU Affero General Public License][AGPL] as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

[AGPL]:  <AGPL-3.0.txt>
