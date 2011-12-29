<?php

/**
 * Confirmation Code Generator (https://github.com/KellyLSB/Confirmation-Code-Generator)
 * Inspired by a similar class written by David Boskovic (http://github.com/dboskovic)
 *
 * * * * * * * *
 * Information *
 * * * * * * * *
 *
 * This generator encrypts and decrypts ID numbers to and from an Alpha Numeric (A-Z,0-9)
 * Tracking number like code. It then stores a Salt, and a Salt Format ID within the code.
 * When the Code is decrypted it looks for the Salt Format ID which tells the class where
 * it can find the Salt within the Code. The Salt is then extracted from the Code and sent
 * to the decrypter where it is used to determine which decryption key should be used.
 *
 * * * * *
 * USAGE *
 * * * * *
 *
 * $ConfCode = new ConfirmationCode;
 *
 * // $len is the length of the id (The code itself will tack on 4 characters.)
 * // If $len = 8 then the code will be 12 digits long. If $len = 4 then the code
 * // will be 8 digits long.
 * $code = $ConfCode->auto('id' [, $len = 8]);
 *
 * // $code is the generated code.
 * $id = $ConfCode->auto($code);
 * 
 * // $id is the decrypted number.
 *
 * * * * * *
 * License *
 * * * * * *
 *
 * Confirmation Code Generator by Kelly Lauren Summer Becker is licensed under a Creative Commons Attribution-ShareAlike 3.0 Unported License.
 * Permissions beyond the scope of this license may be available at http://kellybecker.me.
 *
 * @package default
 * @author Kelly Lauren Summer Becker
 * @website http://kellybecker.me
 * @license http://creativecommons.org/licenses/by-sa/3.0/
 */

class ConfirmationCode {
	public function auto($val, $len = 8) {
		if(is_numeric($val))
			return $this->encode($val, $len);
		else 
			return $this->decode($val);
	}
	
	private $letter_sets = array(
		0 => 'P0MVLWNTZD',
		1 => 'UE58X2VSCT',
		2 => '43Z0Y9AQLS',
		3 => 'V5Q1P4E8L9',
		4 => 'MOIRZCWXED',
		5 => '7NBYXCZU9R',
		6 => 'G2S90I84MC',
		7 => 'TQAMIWH4ZC',
		8 => 'POERHBYA1F',
		9 => 'XKO20UB3IL',
		10 => 'Y0NTH78VSO',
		11 => 'P4DE6VUZLK',
		12 => '9OKN2JLQGI',
		13 => '61UTFSN0BR',
		14 => 'R7ZAHJVGE9',
		15 => 'ADHIZ5WNUQ',
		16 => 'Z9SPX2OQI5',
		17 => 'V7YFEU4PTJ',
		18 => 'YZVFD6UXNG',
		19 => 'VH8UDLCE93',
		20 => 'W0H5GMTFZK',
		21 => 'GXE6CT2VOP',
		22 => 'QH2FLZOM9V',
		23 => 'MBGHIF78PU',
		24 => 'MHS04FY8L7',
		25 => 'E95IGRSMZ1',
		26 => 'MN8AILRB95',
		27 => 'S7JVO4EHCD',
		28 => 'GT01ZPLVUA',
		29 => '9OKN2JLQGI',
		30 => 'DUF24AGTSN',
		31 => '4ASPNFJ2BR',
		32 => 'OR465YEXQV',
		33 => 'DUF24AGTSN',
		34 => 'M78PCRAGKS',
		35 => 'D8LVQSKA7U'
	);
	
	private $salt_formats = array(
		0 => '00',
		1 => '01',
		2 => '10',
		3 => '20',
		4 => '02',
	);
	
	private $salt = 'AQL91WFO3UZ4XPCMR78SDEY6KH5B2GVTNIJ0';
	
	public function encode($id, $len = 8) {
		if(!is_numeric($id)) throw new Exception('Must Be Number');
		if($len < 4) throw new Exception('Minimum Length is `4`');
		
		$str = '';
		$crypt = str_pad($id, $len, '0', STR_PAD_LEFT);;
		$rand = array(rand(0,35),rand(0,35));
		echo "<hr />";
		for($x=0;$x<$len;$x++)
			$str .= $this->conv(substr($crypt, $x, 1), $x%2 ? $rand[0] : $rand[1]);
		return substr(chunk_split($this->inject_salt($str, $rand), 4, '-'), 0, -1);
	}
	
	public function decode($crypt) {
		$crypt = preg_replace('/[^A-Za-z0-9]+/', '', strtoupper($crypt));
		
		$rand = $this->retrieve_salt($crypt);
		$len = strlen($crypt);
		for($x=0;$x<$len;$x++)
			$str .= $this->reconv(substr($crypt, $x, 1), $x%2 ? $rand[0] : $rand[1]);
		return $str;
	}
	
	private function conv($num, $rand) {
		return substr($this->letter_sets[$rand], $num, 1);
	}
	
	private function reconv($num, $rand) {
		return strpos($this->letter_sets[$rand], $num);
	}
	
	private function inject_salt($crypt, $salt) {
		$return = '';
		$fnum = rand(0,4);
		$crypt = str_split($crypt);
		$saltf = str_split($this->salt_formats[$fnum]);
		$second = (count($crypt) - 1) - $saltf[1];
		foreach($crypt as $key=>$letter) {
			if($key == $saltf[0])
				$return .= substr($this->salt, $salt[0], 1);
			if($key == $second)
				$return .= substr($this->salt, $salt[1], 1);
				
			$return .= $letter;
		}
		return $return.substr($this->salt, $fnum, 2);
	}
	
	private function retrieve_salt(&$crypt) {
		$return = array();
		$crypt2 = '';
		$fnum = substr(substr($crypt, -2), 0, 1);
		$fnum = strpos($this->salt, $fnum);
		$crypt = str_split(substr($crypt, 0, -2));
		$saltf = str_split($this->salt_formats[$fnum]);
		$second = (count($crypt) - 2) - $saltf[1];
		foreach($crypt as $key=>$letter) {
			if($key == $saltf[0] || $key == $second) {
				$return[] = strpos($this->salt, $letter);
				continue;
			}
			$crypt2 .= $letter;
		}
		$crypt = $crypt2;
		return $return;
	}
}