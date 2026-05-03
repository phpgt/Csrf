<?php
namespace GT\Csrf\Exception;

class CsrfTokenMalformedException extends CsrfException {
	public function __construct() {
		parent::__construct("CSRF Token is malformed");
	}
}
