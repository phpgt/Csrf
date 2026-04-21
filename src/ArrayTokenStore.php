<?php
namespace Gt\Csrf;

use Gt\Csrf\Exception\CsrfTokenInvalidException;
use Gt\Csrf\Exception\CsrfTokenSpentException;

/**
 * NOTE that if this implementation is going to work across web requests, it must be stored on the
 * session - it has no other way of remembering the tokens!
 */
class ArrayTokenStore extends TokenStore {
	/** @var array<string, ?int> */
	private array $arrayStore = [];

	public function saveToken(string $token):void {
		$this->arrayStore[$token] = null;
		$tokenCount = count($this->arrayStore);
		while($tokenCount > $this->maxTokens) {
			array_shift($this->arrayStore);
			$tokenCount--;
		}
	}

	public function verifyToken(string $token):void {
		if(!array_key_exists($token, $this->arrayStore)) {
			throw new CsrfTokenInvalidException(
				$token
			);
		}
		elseif(!is_null($this->arrayStore[$token])) {
			throw new CsrfTokenSpentException(
				$token,
				$this->arrayStore[$token]
			);
		}
	}

	public function consumeToken(string $token):void {
		$this->arrayStore[$token] = time();
	}
}
