const deviceList = document.getElementById("device-list");
const refreshBtn = document.getElementById("refresh-btn");
const filterInput = document.getElementById("filter-input");
const onlineOnly = document.getElementById("online-only");
const toastContainer = document.getElementById("toast-container");
const loginBtn = document.getElementById("login-btn");
const loginModal = document.getElementById("login-modal");
const loginForm = document.getElementById("login-form");
const loginCancel = document.getElementById("login-cancel");
const loginUsername = document.getElementById("login-username");
const loginPassword = document.getElementById("login-password");
const settingsBtn = document.getElementById("settings-btn");
const settingsModal = document.getElementById("settings-modal");
const settingsSave = document.getElementById("settings-save");
const settingsCancel = document.getElementById("settings-cancel");
const policyRows = document.getElementById("policy-rows");
const addPolicyRow = document.getElementById("add-policy-row");
const settingsError = document.getElementById("settings-error");

const STORAGE_KEY = "keenetic-vpn-filters";
const AUTH_KEY = "keenetic-vpn-token";
const pendingPolicies = new Set();
let allDevices = [];
let policies = [];
let fetchGeneration = 0;
let authToken = localStorage.getItem(AUTH_KEY) || null;
let authRequired = true;
let editingPolicies = [];
let routerPolicies = [];
let routerPoliciesData = {};
let routerDnsProfiles = [];
let routerDnsProfilesData = {};

// ── MD5 (vanilla JS) ─────────────────────────────────────────────

const md5 = (function () {
  function safe_add(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  }
  function bit_rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }
  function md5_cmn(q, a, b, x, s, t) {
    return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
  }
  function md5_ff(a, b, c, d, x, s, t) {
    return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
  }
  function md5_gg(a, b, c, d, x, s, t) {
    return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
  }
  function md5_hh(a, b, c, d, x, s, t) {
    return md5_cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function md5_ii(a, b, c, d, x, s, t) {
    return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
  }
  function core_md5(x, len) {
    x[len >> 5] |= 0x80 << ((len) % 32);
    x[(((len + 64) >>> 9) << 4) + 14] = len;
    var a =  1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d =  271733878;
    for (var i = 0; i < x.length; i += 16) {
      var olda = a, oldb = b, oldc = c, oldd = d;
      a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
      d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
      c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
      b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
      a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
      d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
      c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
      b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
      a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
      d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
      c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
      b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
      a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
      d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
      c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
      b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);
      a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
      d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
      c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
      b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
      a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
      d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
      c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
      b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
      a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
      d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
      c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
      b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
      a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
      d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
      c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
      b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);
      a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
      d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
      c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
      b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
      a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
      d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
      c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
      b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
      a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
      d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
      c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
      b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
      a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
      d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
      c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
      b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);
      a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
      d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
      c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
      b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
      a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
      d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
      c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
      b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
      a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
      d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
      c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
      b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
      a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
      d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
      c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
      b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);
      a = safe_add(a, olda);
      b = safe_add(b, oldb);
      c = safe_add(c, oldc);
      d = safe_add(d, oldd);
    }
    return [a, b, c, d];
  }
  function str2binl(s) {
    var bin = [], mask = (1 << 8) - 1;
    for (var i = 0; i < s.length * 8; i += 8)
      bin[i>>5] |= (s.charCodeAt(i / 8) & mask) << (i % 32);
    return bin;
  }
  function binl2hex(arr) {
    var hex = "0123456789abcdef";
    var str = "";
    for (var i = 0; i < arr.length * 4; i++) {
      str += hex.charAt((arr[i>>2] >> ((i%4)*8+4)) & 0xF) +
             hex.charAt((arr[i>>2] >> ((i%4)*8)) & 0xF);
    }
    return str;
  }
  return function md5(s) {
    return binl2hex(core_md5(str2binl(s), s.length * 8));
  };
})();

function sha256(s) {
  var chrsz = 8;
  function S(X, n) { return (X >>> n) | (X << (32 - n)); }
  function R(X, n) { return (X >>> n); }
  function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
  function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
  function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
  function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
  function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
  function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
  function safe_add(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    return (((x >>> 16) + (y >>> 16) + (lsw >>> 16)) << 16) | (lsw & 0xFFFF);
  }
  var K = [0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,0xE49B69C1,0xEFBE4786,0xFC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x6CA6351,0x14292967,0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2];
  var H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
  var W = [], M = [], i, j, len = s.length * chrsz;
  for (i = 0; i < len; i += chrsz) M[i >> 5] |= (s.charCodeAt(i / chrsz) & 0xFF) << (24 - i % 32);
  M[len >> 5] |= 0x80 << (24 - len % 32);
  M[((len + 64 >> 9) << 4) + 15] = len;
  for (i = 0; i < M.length; i += 16) {
    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (j = 0; j < 64; j++) {
      if (j < 16) W[j] = M[j + i] || 0;
      else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
      var T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
      var T2 = safe_add(Sigma0256(a), Maj(a, b, c));
      h = g; g = f; f = e; e = safe_add(d, T1);
      d = c; c = b; b = a; a = safe_add(T1, T2);
    }
    H[0] = safe_add(a, H[0]); H[1] = safe_add(b, H[1]);
    H[2] = safe_add(c, H[2]); H[3] = safe_add(d, H[3]);
    H[4] = safe_add(e, H[4]); H[5] = safe_add(f, H[5]);
    H[6] = safe_add(g, H[6]); H[7] = safe_add(h, H[7]);
  }
  return H.map(function(v) { return ((v >>> 0).toString(16)).padStart(8, '0'); }).join('');
}

function computeKeeneticHash(login, realm, challenge, password) {
  var md5Hash = md5(login + ":" + realm + ":" + password);
  return sha256(challenge + md5Hash);
}
// ── Auth state & UI ──────────────────────────────────────────────

function updateAuthUI() {
  if (!authRequired) {
    // Public mode — login button is present but doesn't gate anything
    document.body.classList.add("public-mode");
    loginBtn.title = "Public mode — login not required";
    if (authToken) {
      loginBtn.textContent = "🔓 Logout";
      document.body.classList.add("authenticated");
    } else {
      loginBtn.textContent = "🔒 Login";
      document.body.classList.remove("authenticated");
    }
    updateGearButtonVisibility();
    return;
  }

  if (authToken) {
    loginBtn.textContent = "🔓 Logout";
    loginBtn.title = "Logout";
    document.body.classList.add("authenticated");
  } else {
    loginBtn.textContent = "🔒 Login";
    loginBtn.title = "Login to manage all devices";
    document.body.classList.remove("authenticated");
  }
  updateGearButtonVisibility();
}

function updateGearButtonVisibility() {
  if (authToken) {
    settingsBtn.classList.remove("hidden");
  } else {
    settingsBtn.classList.add("hidden");
  }
}

function showLoginModal() {
  loginModal.classList.remove("hidden");
  loginUsername.value = "";
  loginPassword.value = "";
  loginUsername.focus();
}

function closeLoginModal() {
  loginModal.classList.add("hidden");
}

// ── Settings modal ────────────────────────────────────────────

function openSettingsModal() {
  settingsError.classList.add("hidden");
  settingsBtn.disabled = true;

  // Fetch router data concurrently
  Promise.all([
    fetchRouterPolicies().catch(() => { routerPolicies = []; routerPoliciesData = {}; }),
    fetchRouterDnsProfiles().catch(() => { routerDnsProfiles = []; routerDnsProfilesData = {}; }),
  ]).then(() => {
    // Deep-clone current policies for editing
    editingPolicies = JSON.parse(JSON.stringify(policies));
    renderPolicyTable();
    settingsModal.classList.remove("hidden");
    settingsBtn.disabled = false;
  });
}

function closeSettingsModal() {
  settingsModal.classList.add("hidden");
  editingPolicies = [];
}

async function fetchRouterPolicies() {
  try {
    const res = await authFetch("/api/router/policies");
    if (res.ok) {
      const data = await res.json();
      // The router may return { policy: { Policy0: {...}, ... } }
      // or return the policy object directly
      const policyMap = data?.policy;
      if (policyMap && typeof policyMap === "object" && !Array.isArray(policyMap)) {
        routerPolicies = Object.keys(policyMap);
        routerPoliciesData = policyMap;
      } else if (data && typeof data === "object" && !Array.isArray(data) && !data.prompt) {
        // Try using the response object directly (no wrapper key)
        const keys = Object.keys(data).filter(k => k !== "prompt");
        if (keys.length > 0 && keys.some(k => data[k] && typeof data[k] === "object")) {
          routerPolicies = keys;
          routerPoliciesData = data;
        } else {
          routerPolicies = [];
          routerPoliciesData = {};
        }
      } else {
        routerPolicies = [];
        routerPoliciesData = {};
      }
    } else {
      console.warn("[settings] fetch router policies failed:", res.status);
      routerPolicies = [];
      routerPoliciesData = {};
    }
  } catch (err) {
    console.warn("[settings] Failed to fetch router policies:", err);
    routerPolicies = [];
    routerPoliciesData = {};
  }
}

async function fetchRouterDnsProfiles() {
  try {
    const res = await authFetch("/api/router/dns-profiles");
    if (res.ok) {
      const data = await res.json();
      // Response may be { profiles: {...} } or directly { DnsProfile0: {...} }
      let profileMap = data?.profiles;
      if (!profileMap || typeof profileMap !== "object" || Array.isArray(profileMap)) {
        const plain = data && typeof data === "object" && !Array.isArray(data) ? data : {};
        const filtered = Object.fromEntries(
          Object.entries(plain).filter(([k]) => k !== "prompt")
        );
        profileMap = Object.keys(filtered).length > 0 ? filtered : null;
      }
      if (profileMap) {
        routerDnsProfiles = Object.keys(profileMap);
        routerDnsProfilesData = profileMap;
      } else {
        routerDnsProfiles = [];
        routerDnsProfilesData = {};
      }
    } else {
      routerDnsProfiles = [];
      routerDnsProfilesData = {};
    }
  } catch (err) {
    console.warn("Failed to fetch DNS profiles:", err);
    routerDnsProfiles = [];
    routerDnsProfilesData = {};
  }
}

function renderPolicyTable() {
  policyRows.innerHTML = editingPolicies
    .map((policy, index) => renderPolicyRow(policy, index))
    .join("");
}

function renderPolicyRow(policy, index) {
  const isFirst = index === 0;

  const policyOptions = routerPolicies
    .map(
      (p) =>
        `<option value="${escapeHtml(p)}"${
          policy.id === p ? " selected" : ""
        }>${escapeHtml(p)}${routerPoliciesData[p]?.description ? " — " + escapeHtml(routerPoliciesData[p].description) : ""}</option>`
    )
    .join("");

  const dnsOptions = ['<option value="">None</option>']
    .concat(
      routerDnsProfiles.map(
        (p) =>
          `<option value="${escapeHtml(p)}"${
            policy.dnsProfile === p ? " selected" : ""
          }>${escapeHtml(p)}${routerDnsProfilesData[p]?.description ? " — " + escapeHtml(routerDnsProfilesData[p].description) : ""}</option>`
      )
    )
    .join("");

  // Auto-fill description from router data if id matches a known policy and label is empty or default
  let descriptionPlaceholder = "";
  if (!isFirst && policy.id && routerPoliciesData[policy.id]?.description) {
    descriptionPlaceholder = routerPoliciesData[policy.id].description;
  }

  return `
    <tr data-index="${index}">
      <td>
        <select class="policy-name-select" data-field="id" ${isFirst ? "disabled" : ""}>
          ${
            isFirst
              ? '<option value="">Default</option>'
              : (routerPolicies.length > 0
                  ? '<option value="">— Select policy —</option>' + policyOptions
                  : '<option value="" disabled>No router policies available</option>')
          }
        </select>
      </td>
      <td class="col-symbol">
        <input type="text" class="policy-symbol-input" data-field="symbol" value="${escapeHtml(policy.symbol)}" maxlength="8" required>
      </td>
      <td class="col-color">
        <input type="color" class="policy-color-input" data-field="color" value="${policy.color}">
      </td>
      <td>
        <input type="text" class="policy-label-input" data-field="label" value="${escapeHtml(policy.label)}"${descriptionPlaceholder ? ` placeholder="${escapeHtml(descriptionPlaceholder)}"` : ""} required>
      </td>
      <td>
        <select class="policy-dns-select" data-field="dnsProfile">
          ${dnsOptions}
        </select>
      </td>
      <td class="col-actions">
        ${isFirst ? "" : '<button class="btn-delete-row" title="Remove policy">&times;</button>'}
      </td>
    </tr>`;
}

function syncRowToEditing(row) {
  const tr = row.closest("tr");
  if (!tr) return;
  const index = parseInt(tr.dataset.index, 10);
  if (isNaN(index) || index < 0 || index >= editingPolicies.length) return;

  const policy = editingPolicies[index];

  if (row.dataset.field === "id") {
    policy.id = row.value;
    // Auto-fill description from router data when policy name changes
    const routerInfo = routerPoliciesData[row.value];
    if (routerInfo && routerInfo.description) {
      policy.label = routerInfo.description;
      const labelInput = tr.querySelector('[data-field="label"]');
      if (labelInput) {
        labelInput.value = routerInfo.description;
        labelInput.placeholder = "";
      }
    }
  } else if (row.dataset.field === "symbol") {
    policy.symbol = row.value;
  } else if (row.dataset.field === "color") {
    policy.color = row.value;
  } else if (row.dataset.field === "label") {
    policy.label = row.value;
  } else if (row.dataset.field === "dnsProfile") {
    policy.dnsProfile = row.value || undefined;
  }
}

function addPolicyRowHandler() {
  editingPolicies.push({
    id: "",
    symbol: "🚀",
    color: "#4ecca3",
    label: "New Policy",
  });
  renderPolicyTable();
  // Scroll to the new row
  const lastRow = policyRows.lastElementChild;
  if (lastRow) lastRow.scrollIntoView({ behavior: "smooth" });
}

function validateEditingPolicies() {
  // Clear previous errors
  policyRows.querySelectorAll(".error").forEach((el) => el.classList.remove("error"));

  if (editingPolicies.length === 0) {
    return "At least one policy is required";
  }

  // First row must have id=""
  if (editingPolicies[0].id !== "") {
    return 'The first policy must be the default option (Policy Name = None)';
  }

  const ids = new Map();
  for (let i = 0; i < editingPolicies.length; i++) {
    const p = editingPolicies[i];

    if (i > 0 && !p.id) {
      return `Row ${i + 1}: policy name is required`;
    }
    if (i > 0 && ids.has(p.id)) {
      return `Row ${i + 1}: duplicate policy name "${p.id}"`;
    }
    if (p.id) ids.set(p.id, i);

    if (!p.symbol || p.symbol.trim() === "") {
      markRowError(i, "symbol");
      return `Row ${i + 1}: button text is required`;
    }
    if (!p.color || !/^#[0-9a-fA-F]{6}$/.test(p.color)) {
      markRowError(i, "color");
      return `Row ${i + 1}: invalid color format (expected #rrggbb)`;
    }
    if (!p.label || p.label.trim() === "") {
      markRowError(i, "label");
      return `Row ${i + 1}: description is required`;
    }
  }

  return null; // no errors
}

function markRowError(index, field) {
  const row = policyRows.querySelector(`tr[data-index="${index}"]`);
  if (!row) return;
  const input = row.querySelector(`[data-field="${field}"]`);
  if (input) input.classList.add("error");
}

async function savePolicies() {
  // Read latest values from DOM into editingPolicies
  policyRows.querySelectorAll("tr").forEach((tr) => {
    const index = parseInt(tr.dataset.index, 10);
    if (isNaN(index) || index < 0 || index >= editingPolicies.length) return;
    tr.querySelectorAll("[data-field]").forEach((el) => {
      if (el.dataset.field === "id") {
        editingPolicies[index].id = el.value;
      } else if (el.dataset.field === "symbol") {
        editingPolicies[index].symbol = el.value;
      } else if (el.dataset.field === "color") {
        editingPolicies[index].color = el.value;
      } else if (el.dataset.field === "label") {
        editingPolicies[index].label = el.value;
      } else if (el.dataset.field === "dnsProfile") {
        editingPolicies[index].dnsProfile = el.value || undefined;
      }
    });
  });

  // Validate
  const error = validateEditingPolicies();
  if (error) {
    settingsError.textContent = error;
    settingsError.classList.remove("hidden");
    return;
  }

  // Save
  settingsSave.disabled = true;
  settingsCancel.disabled = true;
  settingsSave.textContent = "Saving…";

  try {
    const res = await authFetch("/api/policies", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(editingPolicies),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    // Success — reload the page to pick up new policies
    window.location.reload();
  } catch (err) {
    settingsError.textContent = err.message || "Failed to save policies";
    settingsError.classList.remove("hidden");
    settingsSave.disabled = false;
    settingsCancel.disabled = false;
    settingsSave.textContent = "Save";
  }
}

async function submitLogin(login, password) {
  try {
    // 1. Get challenge from router
    const challengeRes = await fetch("/api/session/challenge");
    if (!challengeRes.ok) {
      const err = await challengeRes.json().catch(() => ({}));
      throw new Error(err.error || "Failed to get challenge");
    }
    const { realm, challenge, token: challengeToken } = await challengeRes.json();
    if (!challengeToken) throw new Error("No challenge token received");

    // 2. Compute hash in browser (password never leaves the client)
    const hash = await computeKeeneticHash(login, realm, challenge, password);

    // 3. Send hash to backend
    const res = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ login, hash, token: challengeToken }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Invalid credentials");
    }

    const { token } = await res.json();
    authToken = token;
    localStorage.setItem(AUTH_KEY, token);
    updateAuthUI();
    closeLoginModal();
    showToast("Logged in successfully", "success");
    fetchDevices();
  } catch (err) {
    showToast(err.message || "Login failed", "error");
  }
}

function logout() {
  authToken = null;
  localStorage.removeItem(AUTH_KEY);
  updateAuthUI();
  showToast("Logged out", "success");
  fetchDevices(); // reload in anonymous mode
}

// ── Login event handlers ────────────────────────────────────────

loginBtn.addEventListener("click", () => {
  if (authToken) {
    logout();
    return;
  }
  showLoginModal();
});

loginForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const login = loginUsername.value.trim();
  const password = loginPassword.value;
  if (login && password) {
    submitLogin(login, password);
  }
});

loginCancel.addEventListener("click", closeLoginModal);

// Close login modal on Escape (settings modal only closes via Save/Cancel)
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !loginModal.classList.contains("hidden")) {
    closeLoginModal();
  }
});

// ── Auth-aware fetch ─────────────────────────────────────────────

function authFetch(url, options = {}) {
  const headers = authToken
    ? { ...options.headers, Authorization: `Bearer ${authToken}` }
    : options.headers;
  return fetch(url, { ...options, headers });
}

// ── Filters (persisted) ──────────────────────────────────────────

function loadFilters() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (!saved) {
      onlineOnly.checked = true;
      return;
    }
    if (typeof saved.query === "string") filterInput.value = saved.query;
    onlineOnly.checked = saved.onlineOnly !== false;
  } catch {
    onlineOnly.checked = true;
  }
}

function saveFilters() {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      query: filterInput.value,
      onlineOnly: onlineOnly.checked,
    })
  );
}

loadFilters();

// ── Fetch policies (once on load) ────────────────────────────────

async function fetchPolicies() {
  try {
    const res = await fetch("/api/policies");
    if (res.ok) {
      policies = await res.json();
    }
  } catch (err) {
    console.warn("Failed to load policies:", err);
  }
}

// ── Fetch config (auth mode, once on load) ───────────────────────

async function fetchConfig() {
  try {
    const res = await fetch("/api/config");
    if (res.ok) {
      const cfg = await res.json();
      authRequired = cfg.authRequired !== false;
      updateAuthUI();
    }
  } catch (err) {
    console.warn("Failed to load config:", err);
  }
}

// ── Fetch devices ────────────────────────────────────────────────

async function fetchDevices() {
  const gen = ++fetchGeneration;
  try {
    const res = await authFetch("/api/devices");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (gen !== fetchGeneration) return;
    allDevices = await res.json();
    renderFilteredDevices();
  } catch (err) {
    if (gen !== fetchGeneration) return;
    deviceList.innerHTML = `<div class="error">Failed to load devices: ${escapeHtml(err.message)}</div>`;
  }
}

function renderFilteredDevices() {
  const query = filterInput.value.trim().toLowerCase();
  let filtered = allDevices;

  if (onlineOnly.checked) {
    filtered = filtered.filter((d) => d.active);
  }

  if (query) {
    filtered = filtered.filter((d) => matchesFilter(d, query));
  }

  renderDevices(filtered);
}

function matchesFilter(device, query) {
  return (
    (device.name && device.name.toLowerCase().includes(query)) ||
    (device.hostname && device.hostname.toLowerCase().includes(query)) ||
    (device.mac && device.mac.toLowerCase().includes(query)) ||
    (device.ip && device.ip.includes(query))
  );
}

// ── Render ───────────────────────────────────────────────────────

function renderDevices(devices) {
  if (allDevices.length === 0) {
    deviceList.innerHTML = '<div class="loading">No devices found</div>';
    return;
  }

  if (devices.length === 0) {
    deviceList.innerHTML = '<div class="no-results">No devices match the filter</div>';
    return;
  }

  deviceList.innerHTML = devices
    .map((d) => renderDeviceCard(d))
    .join("");
}

function renderDeviceCard(device) {
  const policyOptions = policies
    .map((p) => renderPolicyOption(device, p))
    .join("");

  return `
    <div class="device-card ${device.active ? "" : "inactive"}">
      <div class="device-info">
        <div class="device-name">
          <span class="status-dot ${device.active ? "online" : "offline"}"></span>
          ${escapeHtml(device.name || device.hostname || "Unknown device")}
        </div>
        <div class="device-meta">
          <span class="device-mac">${escapeHtml(device.mac)}</span>
          ${device.ip ? `<span>${escapeHtml(device.ip)}</span>` : ""}
        </div>
      </div>
      <div class="policy-selector" data-mac="${escapeHtml(device.mac)}">
        ${policyOptions}
      </div>
    </div>
  `;
}

function renderPolicyOption(device, policy) {
  const isActive = device.policy === policy.id;
  const isPending = pendingPolicies.has(device.mac);

  return `
    <button
      class="policy-option ${isActive ? "active" : ""}"
      data-mac="${escapeHtml(device.mac)}"
      data-policy="${escapeHtml(policy.id)}"
      style="color: ${policy.color};"
      title="${escapeHtml(policy.label)}"
      ${isPending ? "disabled" : ""}
    >
      ${policy.symbol}
      <span class="policy-tooltip">${escapeHtml(policy.label)}</span>
    </button>
  `;
}

// ── Event delegation for policy selector clicks ──────────────────

deviceList.addEventListener("click", (e) => {
  const btn = e.target.closest(".policy-option");
  if (!btn || btn.disabled) return;

  const mac = btn.dataset.mac;
  const policyId = btn.dataset.policy;
  const device = allDevices.find((d) => d.mac === mac);

  // If already on this policy, skip
  if (device && device.policy === policyId) return;

  setDevicePolicy(mac, policyId);
});

async function setDevicePolicy(mac, policyId) {
  if (pendingPolicies.has(mac)) return;

  pendingPolicies.add(mac);

  // Disable all buttons for this mac
  document
    .querySelectorAll(`.policy-option[data-mac="${CSS.escape(mac)}"]`)
    .forEach((btn) => {
      btn.disabled = true;
      if (btn.dataset.policy === policyId) {
        btn.classList.add("loading");
      }
    });

  try {
    const res = await authFetch(
      `/api/devices/${encodeURIComponent(mac)}/policy`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ policy: policyId }),
      }
    );

    if (!res.ok) {
      if (res.status === 403) {
        showLoginModal();
        throw new Error("Authentication required to change policies");
      }
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.error || `HTTP ${res.status}`);
    }

    const result = await res.json();

    if (result.verified) {
      // Update local data only when confirmed
      const device = allDevices.find((d) => d.mac === mac);
      if (device) {
        device.policy = result.policy;
        device.policyLabel = result.policyLabel;
      }
      showToast(`${result.policyLabel} ← ${mac}`, "success");
    } else {
      // Refresh from router to revert button state
      showToast(`Policy set but verification failed for ${mac}`, "error");
      fetchDevices();
      return;
    }
  } catch (err) {
    showToast(`Failed: ${err.message}`, "error");
  } finally {
    pendingPolicies.delete(mac);
    renderFilteredDevices();
  }
}

// ── Toast notifications ──────────────────────────────────────────

function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 3000);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ── Event listeners ──────────────────────────────────────────────

filterInput.addEventListener("input", () => {
  saveFilters();
  renderFilteredDevices();
});

onlineOnly.addEventListener("change", () => {
  saveFilters();
  renderFilteredDevices();
});

refreshBtn.addEventListener("click", () => {
  refreshBtn.classList.add("spinning");
  fetchDevices().finally(() => {
    setTimeout(() => refreshBtn.classList.remove("spinning"), 600);
  });
});

// ── Settings modal event listeners ───────────────────────────

settingsBtn.addEventListener("click", openSettingsModal);

settingsCancel.addEventListener("click", closeSettingsModal);

settingsSave.addEventListener("click", savePolicies);

addPolicyRow.addEventListener("click", addPolicyRowHandler);

// Event delegation for table edits and row deletion
policyRows.addEventListener("change", (e) => {
  const target = e.target.closest("[data-field]");
  if (target) syncRowToEditing(target);
});

policyRows.addEventListener("click", (e) => {
  const btn = e.target.closest(".btn-delete-row");
  if (!btn) return;
  const tr = btn.closest("tr");
  if (!tr) return;
  const index = parseInt(tr.dataset.index, 10);
  if (isNaN(index) || index < 0 || index >= editingPolicies.length) return;
  editingPolicies.splice(index, 1);
  renderPolicyTable();
});

// ── Init ─────────────────────────────────────────────────────────

updateAuthUI();

(async () => {
  await fetchPolicies();
  await fetchConfig();
  fetchDevices();
})();

// Auto-refresh every 30 seconds
setInterval(fetchDevices, 30000);
