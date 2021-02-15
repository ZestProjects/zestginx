# Zestginx

Zestginx is a fork of NGINX by Zest Projects Ltd. which improves on NGINX by producing and merging aftermarket patches for performance and security.

Some, but not all, of Zestginx's improvements over NGINX include:

* Dynamic Record Sizing for SSL/TLS.
* HTTP/2 HPACK Compression
* HTTP/3 support via Quiche.
* IO_Uring as the AIO backend.
* OCSP support for BoringSSL.
* Quiet handshake rejection for SNI mismatches.

As well as the above, Zestginx's prebuilds come with a few other changes such as:

* Brotli compression support for NGINX.
* Cloudflare's Zlib for faster GZip.
* PCRE JIT for improved RegEx performance.
* ZStandard compression support for NGINX.

Zestginx's wiki also contains suggestions for your NGINX configuration.

## Credits

Zestginx includes patches from:

https://github.com/cloudflare/quiche

https://github.com/hakasenyang/openssl-patch

https://github.com/kn007/patch

