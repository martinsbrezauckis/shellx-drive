// Short-lived in-memory access-token handling for password-protected Drops.
(function attachPublicDropAccess(root) {
  "use strict";

  function createController({ passwordInput }) {
    let accessToken = "";

    function reject() {
      accessToken = "";
    }

    function clear() {
      reject();
      if (passwordInput) passwordInput.value = "";
    }

    function accept(token) {
      const next = String(token || "").trim();
      if (!next) return false;
      accessToken = next;
      if (passwordInput) passwordInput.value = "";
      return true;
    }

    function requestHeaders() {
      return accessToken ? { "x-shellx-drop-access-token": accessToken } : {};
    }

    return Object.freeze({ accept, clear, reject, requestHeaders, token: () => accessToken });
  }

  root.ShellXPublicDropAccess = Object.freeze({ createController });
})(window);
