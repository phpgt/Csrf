<?php
namespace GT\Csrf\Test;

use Exception;
use GT\Csrf\ArrayTokenStore;
use GT\Csrf\Exception\CsrfException;
use GT\Csrf\Exception\CsrfTokenInvalidException;
use GT\Csrf\Exception\CsrfTokenMissingException;
use GT\Csrf\Exception\CsrfTokenSpentException;
use GT\Csrf\HTMLDocumentProtector;
use PHPUnit\Framework\TestCase;
use stdClass;

class TokenStoreTest extends TestCase {
	const ONE_FORM = <<<HTML
		<!doctype html>
		<html>
		<head>
			<meta charset="utf-8" />
			<title>Test HTML</title>
		</head>
		<body>
			<h1>This HTML is for the unit test.</h1>
			<p>Hello, CSRF!</p>
			
			<form method="post">
				<input required />
				<button>Submit me</button>
			</form>
		</body>
		</html>
		HTML;

	/** no post request received */
	public function testVerify_noPost():void {
		$exception = null;

		try {
			$sut = new ArrayTokenStore();
			$sut->verify([]);
		}
		catch(CsrfException $exception) {}

		self::assertNull($exception);
	}

	/** POST request received but without a token */
	public function testVerify_noToken():void {
		$post = [];
		$post["doink"] = "binky";
		$sut = new ArrayTokenStore();
		$this->expectException(CSRFTokenMissingException::class);
		$sut->verify($post);
	}

	/** POST request received with token but invalid */
	public function testVerify_invalidToken():void {
		$post = [];
		$post["doink"] = "binky";
		$post[HTMLDocumentProtector::TOKEN_NAME] = "12321";
		$sut = new ArrayTokenStore();
		$this->expectException(CSRFTokenInvalidException::class);
		$sut->verify($post);
	}

	/** POST request received with token but invalid */
	public function testVerify_spentToken():void {
		$tokenStore = new ArrayTokenStore();
		$token = $tokenStore->generateNewToken();
		$tokenStore->saveToken($token);
		$tokenStore->consumeToken($token);

		$post = [];
		$post["doink"] = "binky";
// add the token as if it were from a previous page
		$post[HTMLDocumentProtector::TOKEN_NAME] = $token;

		$this->expectException(CSRFTokenSpentException::class);
		$tokenStore->verify($post);
	}

	/** POST request received with token and valid */
	public function testVerify_validToken():void {
		$tokenStore = new ArrayTokenStore();
		$token = $tokenStore->generateNewToken();
		$tokenStore->saveToken($token);

		$post = [];
		$post["doink"] = "binky";
// add the token as if it were from a previous page
		$post[HTMLDocumentProtector::TOKEN_NAME] = $token;

		$exception = null;

		try {
			$tokenStore->verify($post);
		}
		catch(CsrfException $exception) {}

		self::assertNull($exception);
	}

	/**
	 * php.gt/webengine provides user input as a custom object
	 * with an asArray function.
	 */
	public function testVerify_validTokenObj():void {
		$tokenStore = new ArrayTokenStore();
		$token = $tokenStore->generateNewToken();
		$tokenStore->saveToken($token);

		$arrayData = [
			HTMLDocumentProtector::TOKEN_NAME => $token,
			"example" => uniqid(),
			"test" => "testValidTokenObj",
		];

		$mockBuilder = self::getMockBuilder(StdClass::class);
		$mockBuilder->addMethods(["asArray"]);
		$post = $mockBuilder->getMock();
		$post->method("asArray")
			->willReturn($arrayData);

		$exception = null;

		try {
			$tokenStore->verify($post);
		}
		catch(CsrfException $exception) {}

		self::assertNull($exception);
	}

	/** check that repeated calls to the token generator result in unique tokens */
	public function testGenerateNewToken_codesAreUnique():void {
		$sut = new ArrayTokenStore();
		$previousTokens = [];

		$iterations = 5;
		for($i = 0; $i < $iterations; $i++) {
			$token = $sut->generateNewToken();
			self::assertArrayNotHasKey($token, $previousTokens);
			$previousTokens[$token] = null;
		}

		self::assertCount($iterations, $previousTokens);
	}

	public function testSaveToken_tokenLengthChange():void {
		$sut = new ArrayTokenStore();
		$tokenLength = 16;
		$sut->setTokenLength($tokenLength);

		$token = $sut->generateNewToken();
		self::assertStringStartsWith("CSRF_", $token);
		self::assertEquals(
			strlen("CSRF_") + $tokenLength,
			strlen($token)
		);

	// now make sure the custom-length token is successfully stored
		$sut->saveToken($token);

		$exception = null;

		try {
			$sut->verifyToken($token);
		}
		catch(Exception $exception) {}

		self::assertNull($exception);
	}

	public function testGenerateNewToken_usesCsrfUlidPrefix():void {
		$sut = new ArrayTokenStore();
		$token = $sut->generateNewToken();
		self::assertStringStartsWith("CSRF_", $token);
		self::assertSame(
			strlen("CSRF_") + 32,
			strlen($token)
		);
	}
}
