document.getElementById("p7-verify-integrity").addEventListener("click", async () => {
  const resultNode = document.getElementById("p7-integrity-result");
  resultNode.textContent = "Verifying…";
  try {
    const response = await fetch("/p7/audit/verify", {headers: {Accept: "application/json"}});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Verification failed (${response.status})`);
    resultNode.className = data.ok ? "p7-integrity ok" : "p7-integrity bad";
    resultNode.textContent = data.ok
      ? `INTACT — ${data.records} records verified`
      : `TAMPERED at record #${data.first_broken_index}: ${data.reason}`;
    document.getElementById("p7-integrity-detail").textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    resultNode.className = "p7-integrity bad";
    resultNode.textContent = error.message;
  }
});
