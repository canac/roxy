// Stand-in for deno_net's TLS helpers; roxy has no Deno.createHttpClient.
(function () {
function loadTlsKeyPair(api) {
  throw new TypeError(`${api} is not supported in roxy`);
}
return { loadTlsKeyPair };
})();
