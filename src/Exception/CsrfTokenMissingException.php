<?php
namespace GT\Csrf\Exception;

class CsrfTokenMissingException extends CsrfException {
	public function __construct() {
		parent::__construct("CSRF Token not found");
	}
}
