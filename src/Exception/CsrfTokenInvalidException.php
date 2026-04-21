<?php
namespace Gt\Csrf\Exception;

class CsrfTokenInvalidException extends CsrfException {
	public function __construct(string $tokenReceived) {
		parent::__construct(
			"CSRF Token '$tokenReceived' does not exist"
		);
	}
}
