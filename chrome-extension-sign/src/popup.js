import axios from "axios";
import forge from "node-forge"


document.getElementById("btn").addEventListener("click", async() => {
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  let a = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["dist/popup_script.js"]
  });
  console.log(a);
});