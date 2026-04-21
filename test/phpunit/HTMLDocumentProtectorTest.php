<?php
namespace GT\Csrf\Test;

use GT\Csrf\ArrayTokenStore;
use GT\Csrf\HTMLDocumentProtector;
use Gt\Dom\HTMLDocument;
use PHPUnit\Framework\TestCase;

class HTMLDocumentProtectorTest extends TestCase {
	const NO_FORMS = <<<HTML
		<!doctype html>
		<html>
		<head>
			<meta charset="utf-8" />
			<title>Test HTML</title>
		</head>
		<body>
			<h1>This HTML is for the unit test.</h1>
			<p>There are a few elements in this document, but no forms.</p>
		</body>
		</html>
		HTML;

	const ONE_FORM = <<<HTML
		<!doctype html>
		<html>
		<head>
			<meta charset="utf-8" />
			<title>Test HTML</title>
		</head>
		<body>
			<h1>This HTML is for the unit test.</h1>
			<p>There is one form in this document.</p>
			
			<form method="post">
				<input name="test-input" />
				<button>Submit!</button>
			</form>
		</body>
		</html>
		HTML;

	const THREE_FORMS = <<<HTML
		<!doctype html>
		<html>
		<head>
			<meta charset="utf-8" />
			<title>Test HTML</title>
		</head>
		<body>
			<h1>This HTML is for the unit test.</h1>
			<p>There are three forms in this document.</p>
			
			<form method="post">
				<input name="test-input" />
				<button>Submit!</button>
			</form>
			
			<form>
				<input name="query" value="A text field" />
				<button>Submit!</button>
			</form>
			
			<!-- an empty form too...-->
			<form method="post"></form>
		</body>
		</html>
		HTML;

	const HAS_META_ALREADY = <<<HTML
		<!doctype html>
		<html>
		<head>
			<meta charset="utf-8" />
			<meta name="csrf-token" content="abc" />
			<title>Test HTML</title>
		</head>
		<body>
			<h1>This HTML is for the unit test.</h1>
			<p>This document has a form and an existing CSRF token.</p>
			<!-- an empty form too...-->
			<form method="post"></form>
		</body>
		</html>
		HTML;

	const NO_HEAD = <<<HTML
		<!doctype html>
		<html>
		</html>
		HTML;

	public function testConstruct_fromString():void {
		$sut = new HTMLDocumentProtector(
			self::NO_FORMS,
			new ArrayTokenStore()
		);
		$document = $sut->getHTMLDocument();
		self::assertInstanceOf(HTMLDocument::class, $document);
		self::assertSame(
			"Test HTML",
			$document->querySelector("title")->textContent
		);
	}

	public function testConstruct_fromDomDocument():void {
		$document = new HTMLDocument(self::ONE_FORM);
		$sut = new HTMLDocumentProtector($document, new ArrayTokenStore());
		$doc = $sut->getHTMLDocument();
		self::assertSame($document, $doc);
		self::assertEquals(
			"Test HTML",
			$doc->querySelector("title")->textContent
		);
	}

	public function testProtect_zeroForms():void {
		$sut = new HTMLDocumentProtector(
			new HTMLDocument(self::NO_FORMS),
			new ArrayTokenStore()
		);
		$sut->protect();

		$document = $sut->getHTMLDocument();
		$nodeList = $document->querySelectorAll(
			"head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']"
		);

// check that the token has been injected into the head
		self::assertCount(1, $nodeList);
		self::assertNotEmpty($nodeList[0]->getAttribute("content"));
// and that a form hasn't been created or something similar
		self::assertNull($document->querySelector("form"));
	}

	public function testProtect_singleForm():void {
		$sut = new HTMLDocumentProtector(
			new HTMLDocument(self::ONE_FORM),
			new ArrayTokenStore()
		);
		$sut->protect();

// check that the token has been injected
		$document = $sut->getHTMLDocument();
		self::assertStringContainsString(HTMLDocumentProtector::TOKEN_NAME, $document);
		self::assertNotNull($document->forms[0]->querySelector("input[name='" . HTMLDocumentProtector::TOKEN_NAME . "']"));
		self::assertNotEmpty(
			$document->forms[0]->querySelector(
				"input[name='" . HTMLDocumentProtector::TOKEN_NAME . "']"
			)->value
		);

// check that the meta tag has been created too
		$metaTag = $document->querySelector("head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']");
		self::assertNotNull($metaTag);
		self::assertNotEmpty($metaTag->getAttribute("content"));
		self::assertEquals(
			$metaTag->content,
			$document->forms[0]->querySelector(
				"input[name='" . HTMLDocumentProtector::TOKEN_NAME . "']"
			)->value
		);
	}

	public function testProtect_multipleForms():void {
		$sut = new HTMLDocumentProtector(
			new HTMLDocument(self::THREE_FORMS),
			new ArrayTokenStore()
		);
		$sut->protect();

// check that the token has been injected in all POST forms (not GET)
		$document = $sut->getHTMLDocument();
		self::assertCount(
			2,
			$document->querySelectorAll(
				"form input[name='" . HTMLDocumentProtector::TOKEN_NAME . "']"
			)
		);
		self::assertCount(
			1,
			$document->querySelectorAll(
				"head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']")
		);
	}

	public function testProtect_singleCodeSharedAcrossForms():void {
		$sut = new HTMLDocumentProtector(
			new HTMLDocument(self::THREE_FORMS),
			new ArrayTokenStore()
		);
		$sut->protect();

		$document = $sut->getHTMLDocument();
		$token = null;
		foreach($document->querySelectorAll("form input[name='" . HTMLDocumentProtector::TOKEN_NAME . "']") as $input) {
			if($token === null) {
				$token = $input->value;
			}
			else {
				self::assertEquals($token, $input->value);
			}
		}

		$metaTag = $document->querySelector("head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']");
		self::assertEquals($token, $metaTag->content);
	}

	public function testProtect_uniqueCodePerForm():void {
		$sut = new HTMLDocumentProtector(
			new HTMLDocument(self::THREE_FORMS),
			new ArrayTokenStore()
		);
		$sut->protect(HTMLDocumentProtector::ONE_TOKEN_PER_FORM);

		$document = $sut->getHTMLDocument();
		$metaTag = $document->querySelector("head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']");
		self::assertNotNull($metaTag);
		$prevToken = $metaTag->content;

		foreach($document->querySelectorAll(
			"form input[name='" . HTMLDocumentProtector::TOKEN_NAME . "']") as $input) {
			$newToken = $input->value;
			self::assertNotEquals($newToken, $prevToken);
			$prevToken = $newToken;
		}
	}

	public function testProtect_metaTagNoHead():void {
		$sut = new HTMLDocumentProtector(
			new HTMLDocument(self::NO_HEAD),
			new ArrayTokenStore()
		);
		$sut->protect();

		$document = $sut->getHTMLDocument();
		$metaTag = $document->querySelector("head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']");
		self::assertNotNull($metaTag);
		self::assertNotEmpty($metaTag->content);
	}

	public function testProtect_metaTagAlreadyExists():void {
		$document = new HTMLDocument(self::HAS_META_ALREADY);
		$metaTag = $document->querySelector("head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']");
		$originalValue = $metaTag->content;
		$sut = new HTMLDocumentProtector($document, new ArrayTokenStore());
		$sut->protect();

		$metaTag = $document->querySelector("head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']");
		self::assertNotNull($metaTag);
		self::assertNotEmpty($metaTag->getAttribute("content"));
// make sure it's been updated (i.e. doesn't still have the value from the original html)
		self::assertNotEquals($originalValue, $metaTag->content);
	}

	public function testProtect_metaTagMultipleForms():void {
		$document = new HTMLDocument(self::THREE_FORMS);
		$sut = new HTMLDocumentProtector($document, new ArrayTokenStore());
		$sut->protect(HTMLDocumentProtector::ONE_TOKEN_PER_FORM);

		$nodeList = $document->querySelectorAll("head meta[name='" . HTMLDocumentProtector::TOKEN_NAME . "']");
// There should still only be 1 meta tag...
		self::assertCount(1, $nodeList);
// ... but the tag's content should have two values (one per POST form).
		$tokenArray = explode(",", $nodeList[0]->content);
		self::assertCount(2, $tokenArray);
	}

	public function testProtect_differentTokenName() {
		$sut = new HTMLDocumentProtector(new HTMLDocument(self::HAS_META_ALREADY), new ArrayTokenStore());
		$tokenName = HTMLDocumentProtector::TOKEN_NAME;
		$sut->protect();

// check that the token has been injected in all forms
		$document = $sut->getHTMLDocument();
		self::assertCount(
			1,
			$document->querySelectorAll("form input[name='$tokenName']")
		);
		self::assertCount(
			1,
			$document->querySelectorAll("head meta[name='$tokenName']")
		);

// and make sure the pre-existing meta tag hasn't been squashed
		self::assertCount(
			1,
			$document->querySelectorAll("head meta[name='csrf-token']")
		);
	}
}
