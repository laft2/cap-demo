import forge from "node-forge";

document.querySelector("button[type=submit]").addEventListener("click", () => {
  const ctxc = document.getElementById("ctxc-select")
    .selectedOptions[0].getAttribute("name")
  const pass = document.querySelector("input[type=password]").value
  const passField = "pass_" + ctxc
  chrome.storage.local.set({
    [passField]: pass
  })

  const file = document.getElementById("cert").files[0];
  const fileReader = new FileReader();
  fileReader.onload = async e => {
    const p12DataUrl = e.target.result;
    let p12B64 = p12DataUrl.split("base64,")[1];
    let p12Der = forge.util.decode64(p12B64);
    let p12Asn1 = forge.asn1.fromDer(p12Der);
    const getLocalStorage = (key = null) => new Promise(resolve => {
      chrome.storage.local.get(key, resolve);
    });
    // const { pass } = (await getLocalStorage(["pass"]));
    let p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pass);

    let cert = p12.getBags({ bagType: forge.pki.oids.certBag })[
      forge.pki.oids.certBag
    ][0].cert;

    let privateKey = p12.getBags({
      bagType: forge.pki.oids.pkcs8ShroudedKeyBag
    })[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;

    console.log(cert)
    console.log(privateKey)
    console.log(p12DataUrl)
    console.log(typeof p12DataUrl)

    const fieldName = "p12base64_" + ctxc
    chrome.storage.local.set({
      [fieldName]: p12B64
    })
  }
  fileReader.readAsDataURL(file);
})

chrome.storage.local.get(["p12base64_intune", "p12base64_radius"], ({ p12base64_intune, p12base64_radius }) => {
  if (p12base64_intune !== undefined) {
    document.getElementById("curState-intune").textContent += p12base64_intune.substr(0, 10);
  }
  if (p12base64_radius !== undefined) {
    document.getElementById("curState-radius").textContent += p12base64_radius.substr(0, 10);
  }
})