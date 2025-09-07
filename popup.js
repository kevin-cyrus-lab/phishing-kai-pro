function updatePopup(){
  chrome.storage.local.get({blockedClicks:0,warningsShown:0}, data=>{
    document.getElementById('blockedClicks').textContent = data.blockedClicks;
    document.getElementById('warningsShown').textContent = data.warningsShown;
  });
}

document.getElementById('clear').addEventListener('click', ()=>{
  chrome.storage.local.set({blockedClicks:0,warningsShown:0}, updatePopup);
});

document.addEventListener('DOMContentLoaded', updatePopup);
