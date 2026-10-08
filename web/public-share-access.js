// Short-lived in-memory access-token handling for password-protected shares.
(function attachPublicShareAccess(root) {
  "use strict";

  function createController({ passwordInput }) {
    let accessToken = "";

    function clear() {
      accessToken = "";
      if (passwordInput) passwordInput.value = "";
    }

    function accept(token) {
      const next = String(token || "").trim();
      if (!next) return false;
      accessToken = next;
      if (passwordInput) passwordInput.value = "";
      return true;
    }

    function discardUnauthorized(responseOrError) {
      if (Number(responseOrError?.status) !== 401 || !accessToken) return false;
      clear();
      return true;
    }

    function requestHeaders() {
      return accessToken ? { "x-share-access-token": accessToken } : {};
    }

    return Object.freeze({ accept, clear, discardUnauthorized, requestHeaders, token: () => accessToken });
  }

  root.ShellXPublicShareAccess = Object.freeze({ createController });
})(window);
