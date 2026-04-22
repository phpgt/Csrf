<?php
namespace GT\Csrf;

use GT\Csrf\Exception\CsrfTokenInvalidException;
use GT\Csrf\Exception\CsrfTokenSpentException;
use Gt\Session\SessionContainer;

class SessionTokenStore extends TokenStore {
	const SESSION_KEY = "tokenList";

	protected SessionContainer $session;

	public function __construct(
		SessionContainer $session,
		?int $maxTokens = null
	) {
		$this->session = $session;
		parent::__construct($maxTokens);
	}

	public function saveToken(string $token):void {
		$tokenList = $this->session->get(self::SESSION_KEY) ?? [];
		$tokenList[$token] = null;

		$tokenCount = count($tokenList);
		while($tokenCount > $this->getMaxTokens()) {
			array_shift($tokenList);
			$tokenCount--;
		}

		$this->session->set(self::SESSION_KEY, $tokenList);
	}

	public function verifyToken(string $token):void {
		$tokenList = $this->session->get(self::SESSION_KEY) ?? [];

		if(!array_key_exists($token, $tokenList)) {
			throw new CsrfTokenInvalidException(
				$token
			);
		}
		elseif(!is_null($tokenList[$token])) {
			throw new CsrfTokenSpentException(
				$token,
				$tokenList[$token]
			);
		}
	}

	public function consumeToken(string $token):void {
		$tokenList = $this->session->get(self::SESSION_KEY) ?? [];
		$tokenList[$token] = time();
		$this->session->set(self::SESSION_KEY, $tokenList);
	}
}
