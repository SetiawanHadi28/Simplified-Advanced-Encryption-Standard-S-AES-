/* ==========================================================================
   S-AES Simulator — main.js
   Validasi input biner 16-bit real-time, bit counter, copy-to-clipboard,
   dan util kecil lain untuk UX form Encrypt / Decrypt.
   ========================================================================== */

(function () {
  "use strict";

  /**
   * Pasang validasi real-time pada sebuah input biner 16-bit.
   * - hanya menerima karakter 0/1
   * - menampilkan counter panjang bit (x/16)
   * - memberi warna hijau saat valid, merah saat tidak
   */
  function attachBinaryValidator(inputEl, counterEl, submitBtn) {
    if (!inputEl) return;

    function sanitizeAndValidate() {
      // buang karakter selain 0/1
      let cleaned = inputEl.value.replace(/[^01]/g, "");
      if (cleaned !== inputEl.value) {
        inputEl.value = cleaned;
      }
      const len = cleaned.length;

      if (counterEl) {
        counterEl.textContent = len + " / 16 bit";
        counterEl.classList.remove("text-success", "text-danger");
        if (len === 16) {
          counterEl.classList.add("text-success");
        } else if (len > 0) {
          counterEl.classList.add("text-danger");
        }
      }

      const isValid = len === 16;
      inputEl.classList.remove("is-valid", "is-invalid");
      if (len > 0) {
        inputEl.classList.add(isValid ? "is-valid" : "is-invalid");
      }
      return isValid;
    }

    inputEl.addEventListener("input", sanitizeAndValidate);
    inputEl.addEventListener("keypress", function (e) {
      const char = String.fromCharCode(e.which);
      if (!/[01]/.test(char) && e.which !== 8) {
        // izinkan tombol kontrol (backspace dsb) tetap lewat via keydown default
      }
    });

    // jalankan sekali di awal (untuk value hasil re-render setelah submit)
    sanitizeAndValidate();
  }

  function fillRandomBits(inputEl, counterCallback) {
    if (!inputEl) return;
    let bits = "";
    for (let i = 0; i < 16; i++) {
      bits += Math.round(Math.random());
    }
    inputEl.value = bits;
    inputEl.dispatchEvent(new Event("input"));
  }

  function copyToClipboard(text, btnEl) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(text).then(function () {
      if (btnEl) {
        const original = btnEl.innerHTML;
        btnEl.innerHTML = '<i class="bi bi-check2"></i> Copied';
        setTimeout(function () {
          btnEl.innerHTML = original;
        }, 1500);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    // ---- Validator untuk semua input dengan data-bit-input ----
    document.querySelectorAll("[data-bit-input]").forEach(function (el) {
      const counterId = el.getAttribute("data-counter-target");
      const counterEl = counterId ? document.getElementById(counterId) : null;
      attachBinaryValidator(el, counterEl);
    });

    // ---- Tombol random-fill ----
    document.querySelectorAll("[data-random-fill]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const targetId = btn.getAttribute("data-random-fill");
        const targetEl = document.getElementById(targetId);
        fillRandomBits(targetEl);
      });
    });

    // ---- Tombol copy-to-clipboard ----
    document.querySelectorAll("[data-copy-value]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const text = btn.getAttribute("data-copy-value");
        copyToClipboard(text, btn);
      });
    });

    // ---- Auto-dismiss alert setelah beberapa detik (opsional, alert error tetap) ----
    document.querySelectorAll(".alert-auto-dismiss").forEach(function (alertEl) {
      setTimeout(function () {
        const bsAlert = bootstrap.Alert.getOrCreateInstance(alertEl);
        if (bsAlert) bsAlert.close();
      }, 6000);
    });

    // ---- Smooth-scroll ke hasil setelah submit (jika ada #hasil) ----
    const resultAnchor = document.getElementById("hasil");
    if (resultAnchor && window.location.search.indexOf("scroll") === -1) {
      // hanya auto-scroll jika halaman memuat hasil (form baru saja disubmit)
      if (resultAnchor.getAttribute("data-has-result") === "true") {
        setTimeout(function () {
          resultAnchor.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 150);
      }
    }
  });
})();
