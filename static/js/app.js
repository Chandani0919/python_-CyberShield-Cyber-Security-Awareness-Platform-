(() => {
  "use strict";

  const clock = document.querySelector("[data-clock]");
  const updateClock = () => {
    if (clock) {
      clock.textContent = `${new Date().toISOString().slice(11, 19)} UTC`;
    }
  };
  updateClock();
  window.setInterval(updateClock, 1000);

  const sidebar = document.querySelector(".sidebar");
  const menuButton = document.querySelector(".menu-toggle");
  if (sidebar && menuButton) {
    menuButton.addEventListener("click", () => {
      const isOpen = sidebar.classList.toggle("sidebar-open");
      menuButton.setAttribute("aria-expanded", String(isOpen));
    });
    document.addEventListener("click", (event) => {
      if (!sidebar.contains(event.target) && !menuButton.contains(event.target)) {
        sidebar.classList.remove("sidebar-open");
        menuButton.setAttribute("aria-expanded", "false");
      }
    });
  }

  document.querySelectorAll(".flash-close").forEach((button) => {
    button.addEventListener("click", () => button.closest(".flash").remove());
  });

  const input = document.querySelector("#passwordInput");
  const strengthBar = document.querySelector("[data-strength-bar]");
  const strengthLabel = document.querySelector("[data-strength-label]");
  if (input && strengthBar && strengthLabel) {
    input.addEventListener("input", () => {
      const value = input.value;
      const checks = [
        value.length >= 12,
        value.length >= 16,
        /[a-z]/.test(value) && /[A-Z]/.test(value),
        /\d/.test(value),
        /[^A-Za-z0-9]/.test(value),
        !/(.)\1{2,}/.test(value),
        !/(password|qwerty|letmein|123456|admin)/i.test(value),
      ];
      const score = Math.round(checks.filter(Boolean).length * 100 / checks.length);
      strengthBar.style.width = `${value ? score : 0}%`;
      strengthBar.dataset.level = score >= 86 ? "strong" : score >= 58 ? "medium" : "weak";
      strengthLabel.textContent = value ? `${score}% strength estimate` : "Strength preview";
    });

    const toggle = document.querySelector(".password-toggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const reveal = input.type === "password";
        input.type = reveal ? "text" : "password";
        toggle.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
      });
    }
  }

  const form = document.querySelector("[data-quiz-form]");
  if (form) {
    form.addEventListener("submit", (event) => {
      const unanswered = [...form.querySelectorAll("fieldset")].filter(
        (fieldset) => !fieldset.querySelector("input[type=radio]:checked"),
      );
      if (unanswered.length && !window.confirm(
        `${unanswered.length} question${unanswered.length === 1 ? "" : "s"} unanswered. Submit anyway?`,
      )) {
        event.preventDefault();
        unanswered[0].scrollIntoView({ behavior: "smooth", block: "center" });
      }
    });
  }

  document.querySelectorAll("form[data-confirm]").forEach((confirmForm) => {
    confirmForm.addEventListener("submit", (event) => {
      if (!window.confirm(confirmForm.dataset.confirm)) event.preventDefault();
    });
  });

  const canvas = document.querySelector("#progressChart");
  if (canvas && window.Chart) {
    const scores = JSON.parse(canvas.dataset.scores || "[]");
    const totals = JSON.parse(canvas.dataset.totals || "[]");
    const dates = JSON.parse(canvas.dataset.dates || "[]");
    const results = scores.map((score, index) => Math.round(score * 100 / totals[index])).reverse();
    const labels = dates.map((date) => new Date(`${date.replace(" ", "T")}Z`).toLocaleDateString(
      undefined, { month: "short", day: "numeric" },
    )).reverse();
    new window.Chart(canvas, {
      type: "line",
      data: {
        labels,
        datasets: [{
          data: results,
          borderColor: "#39e8ff",
          backgroundColor: (context) => {
            const chart = context.chart;
            const { ctx, chartArea } = chart;
            if (!chartArea) return "rgba(57, 232, 255, .2)";
            const fill = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
            fill.addColorStop(0, "rgba(57, 232, 255, .28)");
            fill.addColorStop(1, "rgba(57, 232, 255, 0)");
            return fill;
          },
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointHoverRadius: 6,
          pointBackgroundColor: "#ff52c7",
          pointBorderColor: "#090c17",
          pointBorderWidth: 2,
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: "rgba(139, 157, 190, .08)" }, ticks: { color: "#8790a7" } },
          y: { min: 0, max: 100, grid: { color: "rgba(139, 157, 190, .08)" }, ticks: { color: "#8790a7", callback: (value) => `${value}%` } },
        },
      },
    });
  }
})();
