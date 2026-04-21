<?php
namespace Gt\Csrf;

use Gt\Csrf\Exception\CsrfTokenInvalidException;
use Gt\Csrf\Exception\CsrfTokenMissingException;
use Gt\Csrf\Exception\CsrfTokenSpentException;

/**
 * Extend this base class to create a store for CSRF tokens. The core functionality of generating
 * the tokens is provided by the base class, but can be overridden.
 */
abstract class TokenStore {
	protected ?int $maxTokens = 1000;
	protected int $tokenLength = 32;

	/**
	 * An optional limit of the number of valid tokens the TokenStore will retain may be passed.
	 * If not specified, an unlimited number of tokens will be retained (which is probably
	 * fine unless you have a very, very busy site with long-running sessions).
	 *
	 * @see static::DEFAULT_MAX_TOKENS
	 */
	public function __construct(?int $maxTokens = null) {
		if(!is_null($maxTokens)) {
			$this->maxTokens = $maxTokens;
		}
	}

	public function getMaxTokens():int {
		return $this->maxTokens;
	}

	/**
	 * Specify that tokens of a different length should be generated.
	 *
	 * @see static::DEFAULT_MAX_TOKENS
	 */
	public function setTokenLength(int $newTokenLength):void {
		$this->tokenLength = $newTokenLength;
	}

	/**
	 * Generate a new token. NOTE: This method does NOT store the token.
	 */
	public function generateNewToken():string {
// This function uses PHP 7.2's inbuilt random_bytes function, which generates
// raw bytes. When converted to hex, each byte is represented by two
// characters, hence why we divide the token length by two.
		return bin2hex(random_bytes($this->tokenLength / 2));
	}

	/**
	 * If a $_POST global exists, check that it contains a token and that the token is valid.
	 * The name the token is stored-under is contained in HTMLDocumentProtector::TOKEN_NAME.
	 *
	 * @param array<string, int>|object $postData
	 * @throws CsrfTokenMissingException There's a $_POST request present but no
	 * token present
	 * @throws CsrfTokenInvalidException There's a token included on the $_POST,
	 * but its value is invalid.
	 * @throws CsrfTokenSpentException  There's a token included on the
	 * $_POST but it has already been consumed by a previous request.
	 * @see TokenStore::verifyToken().
	 */
	public function verify(array|object $postData):void {
// Expect the token to be present on ALL post requests.
		if(!is_array($postData)
		&& is_callable([$postData, "asArray"])) {
			$postData = call_user_func([$postData, "asArray"]);
		}

		if(!empty($postData)) {
			if(!isset($postData[HTMLDocumentProtector::TOKEN_NAME])) {
				throw new CsrfTokenMissingException();
			}

			$this->verifyToken($postData[HTMLDocumentProtector::TOKEN_NAME]);
			$this->consumeToken($postData[HTMLDocumentProtector::TOKEN_NAME]);
		}
	}

	/**
	 * Save a token as valid for later verification.
	 */
	abstract public function saveToken(string $token):void;

	/**
	 * Mark a token as "used".
	 */
	abstract public function consumeToken(string $token):void;

	/**
	 * Check that the token is valid (i.e. exists and has not been consumed already).
	 *
	 * @throws CsrfTokenInvalidException The token is invalid (i.e. is not
	 * contained within the store).
	 * @throws CsrfTokenSpentException The token has been consumed already. This
	 * scenario might be handled differently by the web app in case the user
	 * pressed submit twice in quick succession - instructing them
	 * to refresh the page and resubmit their form for example.
	 */
	abstract public function verifyToken(string $token):void;
}
