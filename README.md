Automatic protection from Cross-Site Request Forgery.
=====================================================

This library handles [CSRF protection](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) automatically for you, including generating tokens, injecting them into all forms in the page and then verifying that a valid token is present whenever a POST request is received.

***

<a href="https://github.com/PhpGt/Csrf/actions" target="_blank">
    <img src="https://badge.status.php.gt/csrf-build.svg" alt="Build status" />
</a>
<a href="https://scrutinizer-ci.com/g/PhpGt/Csrf" target="_blank">
    <img src="https://badge.status.php.gt/csrf-quality.svg" alt="Code quality" />
</a>
<a href="https://scrutinizer-ci.com/g/PhpGt/Csrf" target="_blank">
    <img src="https://badge.status.php.gt/csrf-coverage.svg" alt="Code coverage" />
</a>
<a href="https://packagist.org/packages/PhpGt/Csrf" target="_blank">
    <img src="https://badge.status.php.gt/csrf-version.svg" alt="Current version" />
</a>
<a href="http://www.php.gt/csrf" target="_blank">
	<img src="https://badge.status.php.gt/csrf-docs.svg" alt="PHP.Gt/Csrf documentation" />
</a>

Usage: Protection in Three Steps
--------------------------------

The CSRF library does two things:

  * Injects CSRF tokens into `form`s
  * Verifies `POST` requests to make sure they contain a valid token

Each is just a single method call, but you need to set up first.

### Step 1: Set up

Start by creating the TokenStore. There are currently two implementations — the `ArrayTokenStore` and `SessionTokenStore`.  The `ArrayTokenStore` is the most basic and does not persist in any way, but can be extended into custom integrations. The `SessionTokenStore` is an inbuilt implementation that persists tokens between requests, so that tokens generated for one page request can be checked on another. The easiest way to add CSRF protection is to use the Session:

```php
use Gt\Csrf\SessionTokenStore;

// $session is an object-oriented representation of $_SESSION
// that implements the Gt\Session\SessionContainer Interface.
$tokenStore = new SessionTokenStore($session);
```

### Step 2: Verify

Before running any other code (especially things that could affect data), you should check to make sure that there's a valid CSRF token in place if it's needed:

```php
use Gt\Csrf\Exception\CSRFException;

if(this_is_a_post_request()) {
	try {
		$tokenStore->verify();
	}
	catch(CSRFException $e) {
// Stop processing this request and get out of there!
	}
}
```

If the request contains a POST and there is no valid CSRF token, a `CSRFException` will be thrown — so you should plan to catch it.  Remember, if that happens, the request was fraudulent, so you shouldn't process it!

### Step 3: Inject for Next Time

Finally, once you've finished processing your html code and it's ready to send back to the client, you should inject the CSRF tokens. If you don't, the request will fail to pass Step 2 when the page gets submitted!

```php
use Gt\Csrf\HTMLDocumentProtector;

// The html can come in as anything accepted by Gt\Dom\HTMLDocument - here it's a
// plain string in a variable.
$html = "<html>...</html>";

// Now do the processing.
$protector = new HTMLDocumentProtector($html, $tokenStore);
$protector->protect();

// Output the HTML of the document - you will see the new fields have
// been automatically injected.
echo $protector->getHTMLDocument();
```

Using tokens of a different lengths
-----------------------------------

By default, 32 character tokens are generated. They use characters from the set [a-zA-Z0-9], meaning a 64-bit token which would take a brute-force attacker making 100,000 requests per second around 2.93 million years to guess. If this seems either excessive or inadequate you can change the token length using `TokenStore::setTokenLength()`.

Special note about client-side requests
---------------------------------------

Note that if there are several forms on your page, a unique token will be generated and injected into each form. When a form is submitted using a client-side request (XMLHTTPRequest or Fetch, a.k.a. AJAX), the response will contain a new token that must be refreshed in the page ready for the next submission.

If you would prefer to have one token per page, shared across all forms, this can be configured by passing in the TOKEN_PER_PAGE parameter to the projectAndInject method: `$page->protectAndInject(HTMLDocumentProtector::TOKEN_PER_PAGE);`.

Storing one token per page will reduce the amount of server resources required, but concurrent client-side requests will fail, which is why one token per form is the default.

Alternatives to storing tokens on the session
---------------------------------------------

The package includes an `ArrayTokenStore`, which can be stored on the session. You can implement alternative token stores such as a RDBMS or NoSQL by subclassing `TokenStore` and implementing the abstract methods.

# Proudly sponsored by

[JetBrains Open Source sponsorship program](https://www.jetbrains.com/community/opensource/)

[![JetBrains logo.](https://resources.jetbrains.com/storage/products/company/brand/logos/jetbrains.svg)](https://www.jetbrains.com/community/opensource/)
