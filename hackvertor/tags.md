# Tags Reference

Hackvertor includes ~200 built-in tags organized by category.

## Encode

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `base64` | `<@base64>hello</@base64>` | `aGVsbG8=` |
| `base64url` | `<@base64url>hello?</@base64url>` | `aGVsbG8_` |
| `base32` | `<@base32>hello</@base32>` | `NBSWY3DP` |
| `base58` | `<@base58>hello</@base58>` | `Cn8eVZg` |
| `urlencode` | `<@urlencode>a=1&b=2</@urlencode>` | `a%3d1%26b%3d2` |
| `urlencode_all` | `<@urlencode_all>abc</@urlencode_all>` | `%61%62%63` |
| `burp_urlencode` | `<@burp_urlencode>test value</@burp_urlencode>` | `test+value` |
| `html_entities` | `<@html_entities><script></@html_entities>` | `&lt;script&gt;` |
| `html5_entities` | `<@html5_entities>©</@html5_entities>` | `&copy;` |
| `hex` | `<@hex(" ")>ABC</@hex>` | `41 42 43` |
| `hex_entities` | `<@hex_entities>abc</@hex_entities>` | `&#x61;&#x62;&#x63;` |
| `hex_escapes` | `<@hex_escapes>abc</@hex_escapes>` | `\x61\x62\x63` |
| `unicode_escapes` | `<@unicode_escapes>abc</@unicode_escapes>` | `\u0061\u0062\u0063` |
| `css_escapes` | `<@css_escapes>abc</@css_escapes>` | `\61\62\63` |
| `octal_escapes` | `<@octal_escapes>abc</@octal_escapes>` | `\141\142\143` |
| `dec_entities` | `<@dec_entities>abc</@dec_entities>` | `&#97;&#98;&#99;` |
| `jwt` | `<@jwt("HS256","secret")>{"sub":"1234"}</@jwt>` | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature` |
| `quoted_printable` | `<@quoted_printable>héllo</@quoted_printable>` | `h=C3=A9llo` |
| `saml` | `<@saml><xml>data</xml></@saml>` | (deflate+base64 encoded) |
| `powershell` | `<@powershell>whoami</@powershell>` | `powershell -enc dwBoAG8AYQBtAGkA` |
| `php_chr` | `<@php_chr>abc</@php_chr>` | `chr(97).chr(98).chr(99)` |
| `sql_hex` | `<@sql_hex>admin</@sql_hex>` | `0x61646d696e` |
| `utf7` | `<@utf7>test</@utf7>` | `+AHQ-est` |

## Decode

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `d_base64` | `<@d_base64>aGVsbG8=</@d_base64>` | `hello` |
| `d_base64url` | `<@d_base64url>aGVsbG8_</@d_base64url>` | `hello?` |
| `d_base32` | `<@d_base32>NBSWY3DP</@d_base32>` | `hello` |
| `d_base58` | `<@d_base58>Cn8eVZg</@d_base58>` | `hello` |
| `d_url` | `<@d_url>hello%20world</@d_url>` | `hello world` |
| `d_burp_url` | `<@d_burp_url>hello+world</@d_burp_url>` | `hello world` |
| `d_html_entities` | `<@d_html_entities>&lt;script&gt;</@d_html_entities>` | `<script>` |
| `d_html5_entities` | `<@d_html5_entities>&copy;</@d_html5_entities>` | `©` |
| `d_js_string` | `<@d_js_string>\x61\x62\x63</@d_js_string>` | `abc` |
| `d_css_escapes` | `<@d_css_escapes>\61\62\63</@d_css_escapes>` | `abc` |
| `d_octal_escapes` | `<@d_octal_escapes>\141\142\143</@d_octal_escapes>` | `abc` |
| `d_unicode_escapes` | `<@d_unicode_escapes>\u0061\u0062</@d_unicode_escapes>` | `ab` |
| `d_jwt_get_payload` | `<@d_jwt_get_payload>eyJ...token...</@d_jwt_get_payload>` | `{"sub":"1234"}` |
| `d_jwt_get_header` | `<@d_jwt_get_header>eyJ...token...</@d_jwt_get_header>` | `{"alg":"HS256"}` |
| `d_jwt_verify` | `<@d_jwt_verify("secret")>eyJ...token...</@d_jwt_verify>` | `Valid` or `Invalid` |
| `d_quoted_printable` | `<@d_quoted_printable>h=C3=A9llo</@d_quoted_printable>` | `héllo` |
| `d_saml` | `<@d_saml>base64deflated</@d_saml>` | `<xml>data</xml>` |
| `d_utf7` | `<@d_utf7>+AHQ-est</@d_utf7>` | `test` |
| `auto_decode` | `<@auto_decode>aGVsbG8=</@auto_decode>` | `hello` |
| `auto_decode_no_decrypt` | `<@auto_decode_no_decrypt>%68%65%6c%6c%6f</@auto_decode_no_decrypt>` | `hello` |
| `json_parse` | `<@json_parse("$name")>{"name":"John"}</@json_parse>` | `John` |

## Hash

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `md5` | `<@md5>password</@md5>` | `5f4dcc3b5aa765d61d8327deb882cf99` |
| `sha1` | `<@sha1>password</@sha1>` | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| `sha256` | `<@sha256>password</@sha256>` | `5e884898da28047d9...` (64 chars) |
| `sha384` | `<@sha384>password</@sha384>` | (96 hex chars) |
| `sha512` | `<@sha512>password</@sha512>` | (128 hex chars) |
| `sha3` | `<@sha3>password</@sha3>` | (64 hex chars) |
| `sha3_256` | `<@sha3_256>password</@sha3_256>` | (64 hex chars) |
| `md2` | `<@md2>password</@md2>` | (32 hex chars) |
| `md4` | `<@md4>password</@md4>` | (32 hex chars) |
| `ripemd128` | `<@ripemd128>password</@ripemd128>` | (32 hex chars) |
| `ripemd160` | `<@ripemd160>password</@ripemd160>` | (40 hex chars) |
| `ripemd256` | `<@ripemd256>password</@ripemd256>` | (64 hex chars) |
| `whirlpool` | `<@whirlpool>password</@whirlpool>` | (128 hex chars) |
| `tiger` | `<@tiger>password</@tiger>` | (48 hex chars) |
| `sm3` | `<@sm3>password</@sm3>` | (64 hex chars) |
| `gost3411` | `<@gost3411>password</@gost3411>` | (64 hex chars) |

## HMAC

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `hmac_md5` | `<@hmac_md5("SECRET")>message</@hmac_md5>` | `e9ac05ae749e8...` |
| `hmac_sha1` | `<@hmac_sha1("SECRET")>message</@hmac_sha1>` | `5a3e3cf5a7...` |
| `hmac_sha256` | `<@hmac_sha256("SECRET")>message</@hmac_sha256>` | `a]f8d2e...` (64 chars) |
| `hmac_sha384` | `<@hmac_sha384("SECRET")>message</@hmac_sha384>` | (96 hex chars) |
| `hmac_sha512` | `<@hmac_sha512("SECRET")>message</@hmac_sha512>` | (128 hex chars) |

## String

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `uppercase` | `<@uppercase>hello</@uppercase>` | `HELLO` |
| `lowercase` | `<@lowercase>HELLO</@lowercase>` | `hello` |
| `capitalise` | `<@capitalise>hello world</@capitalise>` | `Hello world` |
| `reverse` | `<@reverse>hello</@reverse>` | `olleh` |
| `length` | `<@length>hello</@length>` | `5` |
| `unique` | `<@unique>aabbcc</@unique>` | `abc` |
| `find` | `<@find("\\d+")>abc123def</@find>` | `123` |
| `replace` | `<@replace("old","new")>old text</@replace>` | `new text` |
| `regex_replace` | `<@regex_replace("(\\d+)","[$1]")>test123</@regex_replace>` | `test[123]` |
| `repeat` | `<@repeat(3)>ab</@repeat>` | `ababab` |
| `substring` | `<@substring(0,5)>hello world</@substring>` | `hello` |
| `split_join` | `<@split_join(",","-")>a,b,c</@split_join>` | `a-b-c` |
| `from_charcode` | `<@from_charcode>72 101 108 108 111</@from_charcode>` | `Hello` |
| `to_charcode` | `<@to_charcode>Hi</@to_charcode>` | `72 105` |
| `space` | `a<@space></@space>b` | `a b` |
| `newline` | `a<@newline></@newline>b` | `a` (newline) `b` |
| `remove_output` | `<@remove_output>hidden</@remove_output>` | (empty) |

## Convert

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `dec2hex` | `<@dec2hex>255</@dec2hex>` | `ff` |
| `hex2dec` | `<@hex2dec>ff</@hex2dec>` | `255` |
| `dec2oct` | `<@dec2oct>64</@dec2oct>` | `100` |
| `oct2dec` | `<@oct2dec>100</@oct2dec>` | `64` |
| `dec2bin` | `<@dec2bin>10</@dec2bin>` | `1010` |
| `bin2dec` | `<@bin2dec>1010</@bin2dec>` | `10` |
| `ascii2hex` | `<@ascii2hex(" ")>AB</@ascii2hex>` | `41 42` |
| `hex2ascii` | `<@hex2ascii>41 42</@hex2ascii>` | `AB` |
| `ascii2bin` | `<@ascii2bin>A</@ascii2bin>` | `01000001` |
| `bin2ascii` | `<@bin2ascii>01000001</@bin2ascii>` | `A` |
| `chunked_dec2hex` | `<@chunked_dec2hex>Hello</@chunked_dec2hex>` | `5\r\nHello\r\n0\r\n\r\n` |

## Math

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `random` | `<@random(5)>abc123</@random>` | `c31ab` (random 5 chars) |
| `random_alpha_lower` | `<@random_alpha_lower(8)></@random_alpha_lower>` | `xkqwmzpl` |
| `random_alpha_upper` | `<@random_alpha_upper(8)></@random_alpha_upper>` | `XKQWMZPL` |
| `random_alphanum_mixed` | `<@random_alphanum_mixed(8)></@random_alphanum_mixed>` | `Xk3wMz9L` |
| `random_num` | `<@random_num(6)></@random_num>` | `847291` |
| `random_hex` | `<@random_hex(8)></@random_hex>` | `a3f2c891` |
| `random_unicode` | `<@random_unicode(0,255,5)></@random_unicode>` | (5 random chars) |
| `uuid` | `<@uuid></@uuid>` | `550e8400-e29b-41d4-a716-446655440000` |
| `range` | `<@range(1,5,1)></@range>` | `1,2,3,4,5` |
| `arithmetic` | `<@arithmetic(10,"+",",")>1,2,3</@arithmetic>` | `11,12,13` |
| `zeropad` | `<@zeropad(",",4)>1,23,456</@zeropad>` | `0001,0023,0456` |
| `total` | `<@total>1,2,3,4,5</@total>` | `15` |

## Encrypt

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `aes_encrypt` | `<@aes_encrypt("secretkey1234567","AES/ECB/PKCS5PADDING")>plaintext</@aes_encrypt>` | (base64 ciphertext) |
| `xor` | `<@xor("key")>secret</@xor>` | (xored bytes) |
| `rotN` | `<@rotN(13)>hello</@rotN>` | `uryyb` |
| `affine_encrypt` | `<@affine_encrypt(5,9)>hello</@affine_encrypt>` | `eziif` |
| `atbash_encrypt` | `<@atbash_encrypt>hello</@atbash_encrypt>` | `svool` |
| `rail_fence_encrypt` | `<@rail_fence_encrypt(3)>HELLO WORLD</@rail_fence_encrypt>` | `HOREL OLLWD` |
| `substitution_encrypt` | `<@substitution_encrypt("phqgiumeaylnofdxjkrcvstzwb")>hello</@substitution_encrypt>` | (substituted) |
| `rotN_bruteforce` | `<@rotN_bruteforce>uryyb</@rotN_bruteforce>` | (all 26 rotations) |

## Decrypt

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `aes_decrypt` | `<@aes_decrypt("secretkey1234567","AES/ECB/PKCS5PADDING")>ciphertext</@aes_decrypt>` | `plaintext` |
| `xor_decrypt` | `<@xor_decrypt(3)>xored_data</@xor_decrypt>` | (attempts key guess) |
| `affine_decrypt` | `<@affine_decrypt(5,9)>eziif</@affine_decrypt>` | `hello` |
| `atbash_decrypt` | `<@atbash_decrypt>svool</@atbash_decrypt>` | `hello` |
| `rail_fence_decrypt` | `<@rail_fence_decrypt(3)>HOREL OLLWD</@rail_fence_decrypt>` | `HELLO WORLD` |
| `substitution_decrypt` | `<@substitution_decrypt("phqgiumeaylnofdxjkrcvstzwb")>encoded</@substitution_decrypt>` | (decrypted) |

## Compression

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `gzip` | `<@gzip>hello world</@gzip>` | (gzip compressed bytes) |
| `d_gzip` | `<@d_gzip>gzipped_data</@d_gzip>` | `hello world` |
| `bzip2` | `<@bzip2>hello world</@bzip2>` | (bzip2 compressed) |
| `d_bzip2` | `<@d_bzip2>bzipped_data</@d_bzip2>` | `hello world` |
| `deflate` | `<@deflate>hello world</@deflate>` | (deflated bytes) |
| `d_deflate` | `<@d_deflate>deflated_data</@d_deflate>` | `hello world` |
| `d_brotli` | `<@d_brotli>brotli_data</@d_brotli>` | (decompressed) |

## Variables

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `set` | `<@set("myvar")>stored value</@set>` | `stored value` (and stores it) |
| `get` | `<@get("myvar")></@get>` | `stored value` |
| `set_variable` | `<@set_variable("x")>123</@set_variable>` | `123` |
| `get_variable` | `<@get_variable("x")></@get_variable>` | `123` |
| `increment_var` | `<@increment_var(0,"counter",true)></@increment_var>` | `0` (then `1`, `2`...) |
| `decrement_var` | `<@decrement_var(10,"counter",true)></@decrement_var>` | `10` (then `9`, `8`...) |

See [Global Variables](global-variables.md) for details.

## Context Tags

Context tags access request data during conversion. They require the tag execution key.

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `context_request` | `<@context_request("EXEC_KEY")></@context_request>` | (full HTTP request) |
| `context_url` | `<@context_url("path","EXEC_KEY")></@context_url>` | `/api/users` |
| `context_header` | `<@context_header("User-Agent","EXEC_KEY")></@context_header>` | `Mozilla/5.0...` |
| `context_body` | `<@context_body("EXEC_KEY")></@context_body>` | (request body) |
| `context_param` | `<@context_param("id","EXEC_KEY")></@context_param>` | `123` |
| `context_cookie` | `<@context_cookie("session","EXEC_KEY")></@context_cookie>` | `abc123...` |
| `context_method` | `<@context_method("EXEC_KEY")></@context_method>` | `POST` |
| `context_path` | `<@context_path("EXEC_KEY")></@context_path>` | `/api/users` |

## Charsets

Convert between character encodings. The charset name is the tag name.

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `UTF-16` | `<@UTF-16>hello</@UTF-16>` | (UTF-16 encoded bytes) |
| `ISO-8859-1` | `<@ISO-8859-1>café</@ISO-8859-1>` | (ISO-8859-1 bytes) |
| `ASCII` | `<@ASCII>hello</@ASCII>` | (ASCII bytes) |

## Date

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `timestamp` | `<@timestamp></@timestamp>` | `1701234567` |
| `timestamp_millis` | `<@timestamp_millis></@timestamp_millis>` | `1701234567890` |
| `date` | `<@date("yyyy-MM-dd","GMT")></@date>` | `2024-11-29` |

## Fake (Data Generation)

Generates fake data using JavaFaker. Tags take no input.

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `name` | `<@name></@name>` | `John Smith` |
| `first_name` | `<@first_name></@first_name>` | `John` |
| `last_name` | `<@last_name></@last_name>` | `Smith` |
| `email` | `<@email></@email>` | `john.smith@example.com` |
| `phone` | `<@phone></@phone>` | `555-123-4567` |
| `address` | `<@address></@address>` | `123 Main St, City, ST 12345` |
| `company` | `<@company></@company>` | `Acme Corporation` |
| `creditcard` | `<@creditcard></@creditcard>` | `4111111111111111` |
| `uuid` | `<@uuid></@uuid>` | `550e8400-e29b-41d4-...` |

## XSS

XSS payload generators. Input is your payload content.

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `behavior` | `<@behavior>alert(1)</@behavior>` | `<html:component...>` |
| `css_expression` | `<@css_expression>alert(1)</@css_expression>` | `x:expression(alert(1))` |
| `eval_fromcharcode` | `<@eval_fromcharcode>alert(1)</@eval_fromcharcode>` | `eval(String.fromCharCode(97,108...))` |
| `iframe_data_url` | `<@iframe_data_url>alert(1)</@iframe_data_url>` | `<iframe src="data:text/html,...">` |
| `script_data` | `<@script_data>alert(1)</@script_data>` | `<script src="data:,...">` |
| `template_eval` | `<@template_eval>alert(1)</@template_eval>` | (template literal payload) |
| `throw_eval` | `<@throw_eval>alert(1)</@throw_eval>` | (throw-based payload) |

## Languages (Custom Code)

See [Code Execution Tags](code-execution-tags.md) for inline usage.

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `javascript` | `<@javascript('output=input.toUpperCase()','KEY')>hello</@javascript>` | `HELLO` |
| `python` | `<@python('output=input[::-1]','KEY')>hello</@python>` | `olleh` |
| `groovy` | `<@groovy('output=input.reverse()','KEY')>hello</@groovy>` | `olleh` |
| `java` | `<@java('output=input.toUpperCase();','KEY')>hello</@java>` | `HELLO` |

## System

Requires "Allow code execution tags" in settings.

| Tag | Example Setup | Example Result |
|-----|---------------|----------------|
| `system` | `<@system>whoami</@system>` | `username` |
| `read_file` | `<@read_file>/etc/hostname</@read_file>` | `myserver` |
| `read_url_burp` | `<@read_url_burp>http://example.com</@read_url_burp>` | (HTTP response body) |
