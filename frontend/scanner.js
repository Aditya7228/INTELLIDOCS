
// --- FILE SECURITY SCANNER ---
async function scanFile() {
  const fileInput = document.getElementById("scanner-file-input");
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    showToast("Please select a file to scan.", "error");
    return;
  }

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append("file", file);

  const btn = document.getElementById("btn-scan-file");
  if (btn) {
    btn.disabled = true;
    btn.innerText = "Scanning...";
  }

  try {
    const data = await apiFetch("/documents/scan", {
      method: "POST",
      body: formData
    });

    const resultContainer = document.getElementById("scanner-result-container");
    const resultTitle = document.getElementById("scanner-result-title");
    const resultContent = document.getElementById("scanner-result-content");
    
    if (resultContainer && resultTitle && resultContent) {
      resultContainer.style.display = "block";
      
      const isDangerous = data.security_assessment?.verdict === "BLOCKED" || data.security_assessment?.verdict === "SUSPICIOUS";
      resultTitle.className = isDangerous ? "text-danger" : "text-success";
      resultTitle.innerText = "Verdict: " + (data.security_assessment?.verdict || "UNKNOWN");
      
      let html = `<p><strong>Risk Score:</strong> ${data.security_assessment?.risk_score || "N/A"}</p>`;
      html += `<p><strong>Risk Level:</strong> ${data.security_assessment?.risk_level || "N/A"}</p>`;
      
      const findings = data.security_assessment?.findings || [];
      if (findings.length > 0) {
        html += `<h5>Findings:</h5><ul style="padding-left:20px; font-size:13px;">`;
        for (const f of findings) {
          if (typeof f === 'string') {
            html += `<li>${escapeHtml(f)}</li>`;
          } else {
            html += `<li>
              <strong>${escapeHtml(f.title || f.check_name || "Finding")}</strong> 
              <span class="badge ${f.severity === 'HIGH' || f.severity === 'CRITICAL' ? 'bg-danger' : 'bg-warning'}">${escapeHtml(f.severity || "INFO")}</span>
              <br/>
              <span class="text-muted">${escapeHtml(f.technical_evidence || f.potential_harm || "")}</span>
            </li>`;
          }
        }
        html += `</ul>`;
      } else {
        html += `<p>No negative findings.</p>`;
      }
      
      resultContent.innerHTML = html;
    }
    
    showToast("Scan complete.");
  } catch (err) {
    showToast(err.message || "Scan failed.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = "Scan File";
    }
  }
}

function resetScannerForm() {
  const fileInput = document.getElementById("scanner-file-input");
  if (fileInput) fileInput.value = "";
  const resultContainer = document.getElementById("scanner-result-container");
  if (resultContainer) resultContainer.style.display = "none";
}
