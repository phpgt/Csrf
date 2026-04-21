<?php
namespace GT\Csrf\Exception;

class CsrfTokenSpentException extends CsrfException {
	public function __construct(
		string $tokenReceived,
		int $previousUseTime
	) {
		parent::__construct(
			"CSRF Token '{$tokenReceived}' previously used at "
			. date("c", $previousUseTime)
		);
	}
}
