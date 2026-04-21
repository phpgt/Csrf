<?php
namespace Gt\Csrf;

use GT\Dom\HTMLDocument;

class HTMLDocumentProtector {
	/**
	 * Use this flag in the protectAndInject() method
	 */
	const ONE_TOKEN_PER_PAGE = "PAGE";
	const ONE_TOKEN_PER_FORM = "FORM";

	/**
	 * @var string The name to be used for the head meta tag and hidden html input fields used
	 * to store the token in the page
	 */
	const TOKEN_NAME = "csrf-token";

	private HTMLDocument $document;
	private TokenStore $tokenStore;

	public function __construct(
		string|HTMLDocument $document,
		TokenStore $tokenStore
	) {
		if(is_string($document)) {
			$document = new HTMLDocument($document);
		}
		$this->document = $document;
		$this->tokenStore = $tokenStore;
	}

	/**
	 * Inject a CSRF token into each form in the html page, and add a meta tag to the header
	 * with a "content" attribute containing a token.
	 *
	 * The way the tokens are generated can be configured using the $tokenSharing parameter:
	 *
	 * Specify self::ONE_TOKEN_PER_FORM if different tokens should be used for each form on the
	 * page (and a different token again in the head meta tag). This is only required if
	 * multiple forms from a single page could be submitted without reloading the page - using
	 * AJAX for example. Note that the submitted token would still be "spent", so the server
	 * response page should be parsed to lift out the new token and inject it into the form
	 * that was just submitted.
	 *
	 * Specify self::ONE_TOKEN_PER_PAGE if the same token can be used for all forms across the
	 * page and the head meta tag. This is the default, and is considerably more efficient than
	 * generating unique tokens. In most cases this default is suitable - wherever the normal
	 * model of returning a new page in response to a form submit is used.
	 */
	public function protect(
		string $tokenSharing = self::ONE_TOKEN_PER_PAGE
	):string {
		$forms = $this->document->forms;
		$tokenArray = [];

		$token = null;

		if($forms->length > 0) {
			foreach($forms as $form) {
				$formMethod = $form->getAttribute("method");
				if(strtolower($formMethod) !== "post") {
					continue;
				}

				if($tokenSharing === self::ONE_TOKEN_PER_FORM
				|| is_null($token)) {
					$token = $this->tokenStore->generateNewToken();
					$this->tokenStore->saveToken($token);
					array_push($tokenArray, $token);
				}

				$csrfElement = $this->document->createElement(
					"input"
				);
				$csrfElement->setAttribute(
					"name",
					static::TOKEN_NAME
				);
				$csrfElement->setAttribute(
					"value",
					$token
				);
				$csrfElement->setAttribute(
					"type",
					"hidden"
				);
				$form->insertBefore(
					$csrfElement,
					$form->firstChild
				);
			}
		}

		if(is_null($token)) {
			$token = $this->tokenStore->generateNewToken();
			$this->tokenStore->saveToken($token);
			array_push($tokenArray, $token);
		}

		$meta = $this->document->querySelector(
			"head meta[name='" . self::TOKEN_NAME . "']"
		);

		if(is_null($meta)) {
			$meta = $this->document->createElement("meta");
			$meta->setAttribute(
				"name",
				self::TOKEN_NAME
			);

			$head = $this->document->querySelector(
				"head"
			);

			if(is_null($head)) {
				$head = $this->document->createElement(
					"head"
				);
				$htmlElement = $this->document->querySelector(
					"html"
				);

				$htmlElement->appendChild($head);
			}

			$head->appendChild($meta);
		}

		$meta->setAttribute("content", implode(",", $tokenArray));
		return $token;
	}

	/**
	 * Retrieve the injected html.
	 *
	 * @return HTMLDocument Note that this can be used as-is, or if you
	 * want to access the html as a string call the HTMLDocument->saveHTML()
	 * method.
	 */
	// phpcs:disable Generic.NamingConventions.CamelCapsFunctionName
	public function getHTMLDocument():HTMLDocument {
		return $this->document;
	}
	// phpcs:enable Generic.NamingConventions.CamelCapsFunctionName
}
