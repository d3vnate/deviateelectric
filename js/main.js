// Deviate Electric — landing page interactions
(function () {
  "use strict";

  // Mobile navigation toggle
  const toggle = document.getElementById("navToggle");
  const nav = document.getElementById("mainNav");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      const open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    nav.querySelectorAll("a").forEach((link) =>
      link.addEventListener("click", () => {
        nav.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      })
    );
  }

  // Scroll reveal
  const reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15 }
    );
    reveals.forEach((el) => io.observe(el));
  } else {
    reveals.forEach((el) => el.classList.add("visible"));
  }

  // Animated counters
  const counters = document.querySelectorAll("[data-count]");
  const animateCount = (el) => {
    const target = parseInt(el.dataset.count, 10);
    const duration = 1400;
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(target * eased).toLocaleString();
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };
  if ("IntersectionObserver" in window) {
    const cio = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            animateCount(entry.target);
            cio.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.5 }
    );
    counters.forEach((el) => cio.observe(el));
  } else {
    counters.forEach((el) => (el.textContent = el.dataset.count));
  }

  // Quote form (real submit -> /send-email -> PrivateEmail)
  const RECAPTCHA_SITE_KEY = "YOUR_RECAPTCHA_SITE_KEY"; // <- replace with your v3 site key
  const form = document.getElementById("quoteForm");
  const note = document.getElementById("formNote");
  const submitBtn = document.getElementById("quoteSubmitBtn");
  if (form) {
    const showNote = (message, isError) => {
      note.hidden = false;
      note.style.color = isError ? "#dc2626" : "";
      note.textContent = message;
    };

    // Basic client-side validation (backend re-validates independently)
    const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    const PHONE_RE = /^[\d\s()+.-]{7,20}$/;
    const validateFields = () => {
      const name = form.name.value.trim();
      const phone = form.phone.value.trim();
      const email = form.email.value.trim();
      if (!name || !phone) return "Please provide your name and phone number.";
      if (!PHONE_RE.test(phone)) return "That phone number looks off — digits, spaces, dashes, parens only.";
      if (email && !EMAIL_RE.test(email)) return "That email address looks off — please double-check it.";
      return null;
    };

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const validationError = validateFields();
      if (validationError) {
        showNote(validationError, true);
        return;
      }

      // reCAPTCHA v3: exchange the implicit challenge for a fresh token
      let captchaToken = "";
      try {
        if (window.grecaptcha?.ready) {
          await window.grecaptcha.ready(() => {});
          captchaToken = await window.grecaptcha.execute(RECAPTCHA_SITE_KEY);
        }
      } catch (_) {
        /* fall through; backend verifies and fails closed */
      }

      const payload = {
        name: form.name.value.trim(),
        phone: form.phone.value.trim(),
        email: form.email.value.trim(),
        service: form.service.value,
        details: form.details.value.trim(),
        captcha_token: captchaToken,
      };

      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Sending\u2026";
      }
      try {
        const res = await fetch("/send-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => ({ ok: false }));
        if (res.ok && data.ok) {
          // Success: collapse the form fields, keep the thank-you note
          form.querySelectorAll("label, button, input[type=hidden]").forEach((el) => {
            el.style.display = "none";
          });
          showNote("Thanks! We\u2019ll reach out within one business day.");
        } else {
          showNote(data.error || "Something went wrong sending your request. Please try again.", true);
        }
      } catch (_) {
        showNote("Network error \u2014 please check your connection and try again.", true);
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = "Request My Free Quote";
        }
      }
    });
  }

  // Footer year
  const yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = new Date().getFullYear();
})();
