<?php
namespace GT\Csrf\Test;

use Exception;
use GT\Csrf\Exception\CsrfTokenInvalidException;
use GT\Csrf\Exception\CsrfTokenSpentException;
use GT\Csrf\SessionTokenStore;
use Gt\Session\SessionStore;
use PHPUnit\Framework\TestCase;

class SessionTokenStoreTest extends TestCase {
	public function testSaveToken_whenEmpty():void {
		$tokenToSet = uniqid();

		$session = self::createMock(SessionStore::class);
		$session->method("get")
			->willReturn([]);

		$session->expects($this->once())
			->method("set")
			->with(
				SessionTokenStore::SESSION_KEY,
				[$tokenToSet => null]
			);

		$sessionTokenStore = new SessionTokenStore($session);
		$sessionTokenStore->saveToken($tokenToSet);
	}

	public function testSaveToken_whenNotEmpty():void {
		$tokenToSet = uniqid("new-", true);
		$existingTokens = [];
		for($i = 0; $i < 10; $i++) {
			$key = uniqid("existing-", true);
			$existingTokens[$key] = null;
		}

		$session = self::createMock(SessionStore::class);
		$session->method("get")
			->willReturn($existingTokens);

		$existingTokensWithNewToken = [];
		foreach($existingTokens as $key => $value) {
			$existingTokensWithNewToken[$key] = $value;
		}
		$existingTokensWithNewToken[$tokenToSet] = null;

		$session->expects($this->once())
			->method("set")
			->with(
				SessionTokenStore::SESSION_KEY,
				$existingTokensWithNewToken
			);

		$sessionTokenStore = new SessionTokenStore($session);
		$sessionTokenStore->saveToken($tokenToSet);
	}

	public function testSaveToken_pastMaxTokens():void {
		$tokenToSet = uniqid("new-");
		$existingTokens = [];
		for($i = 0; $i < 10; $i++) {
			$key = uniqid("existing-$i-");
			$existingTokens[$key] = null;
		}

		$session = self::createMock(SessionStore::class);
		$session->method("get")
			->willReturn($existingTokens);

		$existingTokensWithNewToken = [];
		foreach($existingTokens as $key => $value) {
			$existingTokensWithNewToken[$key] = $value;
		}
		array_shift($existingTokensWithNewToken);
		$existingTokensWithNewToken[$tokenToSet] = null;

		$session->expects($this->once())
			->method("set")
			->with(
				SessionTokenStore::SESSION_KEY,
				$existingTokensWithNewToken
			);

		$sessionTokenStore = new SessionTokenStore(
			$session,
			10
		);
		$sessionTokenStore->saveToken($tokenToSet);
	}

	public function testVerifyToken_notExists():void {
		$tokenToCheckFor = uniqid("token-");
		$existingTokens = [];
		for($i = 0; $i < 10; $i++) {
			$key = uniqid("token-");
			$existingTokens[$key] = null;
		}

		$session = self::createMock(SessionStore::class);
		$session->method("get")
			->willReturn($existingTokens);

		self::expectException(CsrfTokenInvalidException::class);
		$sessionTokenStore = new SessionTokenStore($session);
		$sessionTokenStore->verifyToken($tokenToCheckFor);
	}

	public function testVerifyToken_spent():void {
		$tokenToCheckFor = uniqid("token-");
		$existingTokens = [];
		for($i = 0; $i < 9; $i++) {
			$key = uniqid("token-");
			$existingTokens[$key] = null;
		}

// Add the token to check for in the middle of the existing tokens.
		$existingTokens = array_merge(
			array_slice($existingTokens, 0, 4),
			[$tokenToCheckFor => time()],
			array_slice($existingTokens, 4)
		);

		$session = self::createMock(SessionStore::class);
		$session->method("get")
			->willReturn($existingTokens);

		self::expectException(CsrfTokenSpentException::class);
		$sessionTokenStore = new SessionTokenStore($session);
		$sessionTokenStore->verifyToken($tokenToCheckFor);
	}

	public function testVerify():void {
		$tokenToCheckFor = uniqid("token-");
		$existingTokens = [];
		for($i = 0; $i < 9; $i++) {
			$key = uniqid("token-");
			$value = rand(0, 1) ? null : time();
			$existingTokens[$key] = $value;
		}

		$existingTokens = array_merge(
			array_slice($existingTokens, 0, 4),
			[$tokenToCheckFor => null],
			array_slice($existingTokens, 4)
		);

		$session = self::createMock(SessionStore::class);
		$session->method("get")
			->willReturn($existingTokens);

		$exception = null;
		$sessionTokenStore = new SessionTokenStore($session);

		try {
			$sessionTokenStore->verifyToken($tokenToCheckFor);
		}
		catch(Exception $exception) {}

		self::assertNull($exception);
	}

	public function testConsumeToken():void {
		$existingTokens = [];
		for($i = 0; $i < 10; $i++) {
			$key = uniqid("token-");
			$value = rand(0, 1) ? null : time();
			$existingTokens[$key] = $value;
		}

		$tokenToConsume = array_rand($existingTokens);

		$existingTokensConsumed = [];
		foreach($existingTokens as $key => $value) {
			if($key === $tokenToConsume) {
				$value = time();
			}

			$existingTokensConsumed[$key] = $value;
		}

		$session = self::createMock(SessionStore::class);
		$session->method("get")
			->willReturn($existingTokens);

		$session->expects($this->once())
			->method("set")
			->with(
				SessionTokenStore::SESSION_KEY,
				$existingTokensConsumed
			);

		$sessionTokenStore = new SessionTokenStore($session);
		$sessionTokenStore->consumeToken($tokenToConsume);
	}
}
