<?php
namespace GT\Csrf\Test;

use Exception;
use GT\Csrf\ArrayTokenStore;
use GT\Csrf\Exception\CsrfTokenInvalidException;
use GT\Csrf\Exception\CsrfTokenSpentException;
use PHPUnit\Framework\TestCase;

class ArrayTokenStoreTest extends TestCase {
	public function testGenerateNewToken_saveToken_aTokenExists():void {
		$sut = new ArrayTokenStore();
		// generate a token
		$token = $sut->generateNewToken();
		$sut->saveToken($token);
		// check it exists
		$exception = null;

		try {
			$sut->verifyToken($token);
		}
		catch(Exception $exception) {}

		self::assertNull($exception);
	}

	public function testVerifyToken_aTokenDoesntExist():void {
		$sut = new ArrayTokenStore();
		// see if a non-existent token passes
		$this->expectException(CSRFTokenInvalidException::class);
		$sut->verifyToken("mickey mouse");
	}

	public function test_consumeToken():void {
		$sut = new ArrayTokenStore();

		$token = $sut->generateNewToken();
		$sut->saveToken($token);

		$sut->consumeToken($token);

// make sure the consumed token no longer passes verification
		$this->expectException(CSRFTokenSpentException::class);
		$sut->verifyToken($token);
	}

	public function testVerifyToken_tokenLimit():void {
		$sut = new ArrayTokenStore();
		$firstToken = $sut->generateNewToken();
		$sut->saveToken($firstToken);

		$lastToken = null;
		for($tokenCount = 0; $tokenCount < $sut->getMaxTokens(); $tokenCount++) {
			$lastToken = $sut->generateNewToken();
			$sut->saveToken($lastToken);
		}

		$sut->verifyToken($lastToken);
// now we've hit the max, the original token should no longer be valid
		$this->expectException(CSRFTokenInvalidException::class);
		$sut->verifyToken($firstToken);
	}

	public function testConstructor_changeTokenLimit():void {
		$tokenLimit = 5;
		$sut = new ArrayTokenStore($tokenLimit);

// check that the new limit has stuck
		self::assertEquals($tokenLimit, $sut->getMaxTokens());

		$firstToken = $sut->generateNewToken();
		$sut->saveToken($firstToken);

		$lastToken = null;
		for($tokenCount = 0; $tokenCount < $tokenLimit; $tokenCount++) {
			$lastToken = $sut->generateNewToken();
			$sut->saveToken($lastToken);
		}

		$sut->verifyToken($lastToken);
// now we've hit the max, the original token should no longer be valid
		$this->expectException(CSRFTokenInvalidException::class);
		$sut->verifyToken($firstToken);
	}
}
