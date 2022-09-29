import axios from "axios";
import forge, { pki } from "node-forge"

(async() => {
  try {
    const getLocalStorage = (key = null) => new Promise(resolve => {
      chrome.storage.local.get(key, resolve);
    });
    const ctxc = window.location.href.split("/").slice(-1)[0];
    console.log(ctxc)
    const certField = "p12base64_" + ctxc;
    const passField = "pass_" + ctxc
    const {
      [certField]: p12base64, [passField]: pass
    } = (await getLocalStorage([certField, passField]));
    let p12Der = forge.util.decode64(p12base64);
    let p12Asn1 = forge.asn1.fromDer(p12Der);
    let p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass);

    let cert = p12.getBags({ bagType: forge.pki.oids.certBag })[
      forge.pki.oids.certBag
    ][0].cert;
    console.log(cert);

    let privateKey = p12.getBags({
      bagType: forge.pki.oids.pkcs8ShroudedKeyBag
    })[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;

    const signTarget = document.getElementById("msg").innerText;
    const md = forge.md.sha256.create();
    md.update(signTarget, "utf8");
    const signature = privateKey.sign(md);
    const signBase64 = forge.util.encode64(signature);

    const certstr = forge.pki.certificateToPem(cert);

    const data = new URLSearchParams();
    data.append("cert", certstr);
    data.append("msg", signTarget);
    data.append("signatureB64", signBase64);

    let res = await axios.post(window.location.href, data);
    if (res.data.state === "ok") {
      window.location.href = '/';
    }
    console.log(res);
  } catch (error) {
    console.error(error);
  }
})();