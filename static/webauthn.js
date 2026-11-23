// WebAuthn trigger functions the native identity backend's flow nodes name.
(() => {
  "use strict";

  const decode = (text) => {
    const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  };

  const encode = (buffer) => {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const field = (name) => {
    const element = document.getElementsByName(name)[0];
    if (!element) throw new Error(`missing form field ${name}`);
    return element;
  };

  const descriptors = (list) => (list || []).map((c) => ({ ...c, id: decode(c.id) }));

  const creationOptions = (options) => {
    const o = options.publicKey;
    return {
      ...o,
      challenge: decode(o.challenge),
      user: { ...o.user, id: decode(o.user.id) },
      excludeCredentials: descriptors(o.excludeCredentials),
    };
  };

  const requestOptions = (options) => {
    const o = options.publicKey;
    return {
      ...o,
      challenge: decode(o.challenge),
      allowCredentials: descriptors(o.allowCredentials),
    };
  };

  // The JSON shape webauthn-rs reads: binary members base64url without padding.
  const credentialJson = (credential) => {
    const r = credential.response;
    const response = { clientDataJSON: encode(r.clientDataJSON) };
    if (r.attestationObject) {
      response.attestationObject = encode(r.attestationObject);
      if (typeof r.getTransports === "function") response.transports = r.getTransports();
    } else {
      response.authenticatorData = encode(r.authenticatorData);
      response.signature = encode(r.signature);
      if (r.userHandle) response.userHandle = encode(r.userHandle);
    }
    return JSON.stringify({
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      response,
      extensions: credential.getClientExtensionResults(),
    });
  };

  const run = async (source, create, target) => {
    try {
      const options = JSON.parse(field(source).value);
      const credential = create
        ? await navigator.credentials.create({ publicKey: creationOptions(options) })
        : await navigator.credentials.get({ publicKey: requestOptions(options) });
      const hidden = field(target);
      hidden.value = credentialJson(credential);
      hidden.form.submit();
    } catch (e) {
      console.error(e);
    }
  };

  window.oryPasskeyLogin = () => run("passkey_challenge", false, "passkey_login");
  window.oryPasskeyRegistration = () => run("passkey_create_data", true, "passkey_register");
  window.oryPasskeySettingsRegistration = () =>
    run("passkey_create_data", true, "passkey_settings_register");
  window.oryWebAuthnLogin = () => run("webauthn_login_trigger", false, "webauthn_login");
  window.oryWebAuthnRegistration = () =>
    run("webauthn_register_trigger", true, "webauthn_register");
})();
