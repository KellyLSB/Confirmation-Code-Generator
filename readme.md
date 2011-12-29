Confirmation Code Generator (https://github.com/KellyLSB/Confirmation-Code-Generator)
=====================================================================================
Inspired by a similar class written by David Boskovic (http://github.com/dboskovic)

Information
===========

This generator encrypts and decrypts ID numbers to and from an Alpha Numeric (A-Z,0-9)
Tracking number like code. It then stores a Salt, and a Salt Format ID within the code.
When the Code is decrypted it looks for the Salt Format ID which tells the class where
it can find the Salt within the Code. The Salt is then extracted from the Code and sent
to the decrypter where it is used to determine which decryption key should be used.

USAGE
=====

	<?php
	$ConfCode = new ConfirmationCode;
	
	// $len is the length of the id (The code itself will tack on 4 characters.)
	// If $len = 8 then the code will be 12 digits long. If $len = 4 then the code
	// will be 8 digits long.
	$code = $ConfCode->auto('id' [, $len = 8]);
	
	// $code is the generated code.
	$id = $ConfCode->auto($code);
	
	// $id is the decrypted number.
	
	?>

License
=======
Confirmation Code Generator by Kelly Lauren Summer Becker is licensed under a Creative Commons Attribution-ShareAlike 3.0 Unported License.
Permissions beyond the scope of this license may be available at http://kellybecker.me.

[<img src="http://i.creativecommons.org/l/by-sa/3.0/88x31.png" alt="BY-SA" title="BY-SA">](http://creativecommons.org/licenses/by-sa/3.0/)