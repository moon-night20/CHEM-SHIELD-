const token = document.querySelector('meta[name="console-token"]').content;
const form = document.getElementById("command-form");
const parameter = document.getElementById("parameter");
const valueInput = document.getElementById("value");
const resultBox = document.getElementById("form-result");
const submitButton = document.getElementById("submit-button");
const criticalLimits = JSON.parse(document.querySelector('meta[name="critical-limits"]').content);
const controls = {
  temperature: { unit: "°C", min: 0, max: 120 },
  power: { unit: "kW", min: 0, max: 20 },
  pressure: { unit: "bar", min: 0, max: 10 },
  speed: { unit: "RPM", min: 0, max: 3000, integer: true },
};

function updateInput() {
  const control = controls[parameter.value];
  document.getElementById("unit").textContent = `(${control.unit})`;
  valueInput.min = control.min;
  valueInput.max = control.max;
  valueInput.step = control.integer ? "1" : "any";
  valueInput.placeholder = `${control.min} to ${control.max}`;
  const limit = criticalLimits[parameter.value];
  const limitNote = limit == null
    ? "No critical threshold is configured."
    : `Above ${limit} ${control.unit} is CRITICAL.`;
  document.getElementById("range-note").textContent =
    `Allowed: ${control.min}–${control.max} ${control.unit}. ${limitNote}`;
}

function showResult(message, isError = false) {
  resultBox.textContent = message;
  resultBox.className = `form-result${isError ? " error" : " success"}`;
}

async function postJson(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Console-Token": token,
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;

  submitButton.disabled = true;
  showResult("Submitting value to the virtual machine…");
  try {
    const data = await postJson("/api/commands", {
      parameter: parameter.value,
      value: Number(valueInput.value),
    });
    showResult(data.message);
    valueInput.value = "";
    valueInput.focus();
  } catch (error) {
    showResult(error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});

document.getElementById("clear-overrides").addEventListener("click", async () => {
  const button = document.getElementById("clear-overrides");
  button.disabled = true;
  try {
    const data = await postJson("/api/overrides/clear", {});
    showResult(data.message);
  } catch (error) {
    showResult(error.message, true);
  } finally {
    button.disabled = false;
  }
});

parameter.addEventListener("change", () => {
  updateInput();
  valueInput.value = "";
  valueInput.focus();
});

updateInput();
