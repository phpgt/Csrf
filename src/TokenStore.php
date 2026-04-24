<?php
namespace GT\Csrf;

use GT\Csrf\Exception\CsrfTokenInvalidException;
use GT\Csrf\Exception\CsrfTokenMalformedException;
use GT\Csrf\Exception\CsrfTokenMissingException;
use GT\Csrf\Exception\CsrfTokenSpentException;
use GT\Ulid\Ulid;

/**
 * Extend this base class to create a store for CSRF tokens. The core functionality of generating
 * the tokens is provided by the base class, but can be overridden.
 */
abstract class TokenStore {
	protected ?int $maxTokens = 1000;
	protected int $tokenLength = 32;

	/**
	 * Optionally configure how many valid tokens the store will retain.
	 *
	 * If not specified, the default limit is 1000 tokens.
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
	 * Specify the length of the ULID portion of generated tokens.
	 *
	 * The full token string will also include the "CSRF_" prefix.
	 */
	public function setTokenLength(int $newTokenLength):void {
		$this->tokenLength = $newTokenLength;
	}

	/**
	 * Generate a new token. NOTE: This method does NOT store the token.
	 *
	 * The generated token is a prefixed ULID, so the full string length is
	 * the configured token length plus the length of "CSRF_".
	 */
	public function generateNewToken():string {
		return new Ulid(
			prefix: "CSRF",
			length: $this->tokenLength,
		);
	}

	/**
	 * If a $_POST global exists, check that it contains a token and that the token is valid.
	 * The name the token is stored-under is contained in HTMLDocumentProtector::TOKEN_NAME.
	 *
	 * @param array<string, mixed>|object $postData
	 * @throws CsrfTokenMissingException There's a $_POST request present but no
	 * token present
	 * @throws CsrfTokenInvalidException There's a token included on the $_POST,
	 * but its value is not known to the store.
	 * @throws CsrfTokenMalformedException There's a token included on the
	 * $_POST, but it is not a string.
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
            $token = $postData[HTMLDocumentProtector::TOKEN_NAME] ?? null;

			if(!isset($token)) {
				throw new CsrfTokenMissingException();
			}

			if(!is_string($token)) {
				throw new CsrfTokenMalformedException();
			}

			$this->verifyToken($token);
			$this->consumeToken($token);
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
