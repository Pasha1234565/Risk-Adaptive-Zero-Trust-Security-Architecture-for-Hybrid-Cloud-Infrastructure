/* Architecture page: load the live inventory into the reference topology. */
(function () {
  "use strict";

  function nodes(items) {
    return items.map(function (item) {
      return '<span class="arch-node ' + window.ZT.escape(item.sensitivity) + '" title="' +
        window.ZT.escape(item.service + " · " + item.category) + '">' +
        window.ZT.escape(item.name) + "</span>";
    }).join("");
  }

  async function init() {
    const privateBox = document.getElementById("arch-private");
    const publicBox = document.getElementById("arch-public");
    if (!privateBox || !publicBox) return;
    try {
      const data = await window.ZT.api("/api/topology");
      privateBox.innerHTML = nodes(data.zones.private);
      publicBox.innerHTML = nodes(data.zones.public);
    } catch (err) {
      privateBox.innerHTML = '<span class="arch-node">Inventory unavailable</span>';
      publicBox.innerHTML = '<span class="arch-node">Inventory unavailable</span>';
      window.ZT.toast(err.message, "error");
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
