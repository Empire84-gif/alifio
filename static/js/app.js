document.addEventListener("DOMContentLoaded", function () {
  const serviceSelect = document.getElementById("service_id");
  const dateInput = document.getElementById("booking_date");
  const timeSelect = document.getElementById("booking_time");

  async function loadAvailableSlots() {
    if (!serviceSelect || !dateInput || !timeSelect) return;

    const serviceId = serviceSelect.value;
    const bookingDate = dateInput.value;

    timeSelect.innerHTML = '<option value="">Ładowanie...</option>';

    if (!serviceId || !bookingDate) {
      timeSelect.innerHTML = '<option value="">Najpierw wybierz usługę i datę</option>';
      return;
    }

    try {
      const response = await fetch(`/api/available-slots?service_id=${serviceId}&booking_date=${bookingDate}`);
      const data = await response.json();

      timeSelect.innerHTML = "";

      if (!data.slots || data.slots.length === 0) {
        timeSelect.innerHTML = '<option value="">Brak wolnych terminów</option>';
        return;
      }

      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = "Wybierz godzinę";
      timeSelect.appendChild(placeholder);

      data.slots.forEach(slot => {
        const option = document.createElement("option");
        option.value = slot;
        option.textContent = slot;
        timeSelect.appendChild(option);
      });
    } catch (error) {
      timeSelect.innerHTML = '<option value="">Błąd ładowania terminów</option>';
    }
  }

  if (serviceSelect) serviceSelect.addEventListener("change", loadAvailableSlots);
  if (dateInput) dateInput.addEventListener("change", loadAvailableSlots);
});



// Hamburger menu toggle (mobile)
(function () {
  const toggle = document.querySelector('.nav-toggle');
  const nav    = document.querySelector('.site-nav');
  if (!toggle || !nav) return;

  toggle.addEventListener('click', function () {
    const open = nav.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', open);
    // Animate bars → X
    const bars = toggle.querySelectorAll('span');
    if (open) {
      bars[0].style.transform = 'translateY(5px) rotate(45deg)';
      bars[1].style.opacity   = '0';
      bars[2].style.transform = 'translateY(-5px) rotate(-45deg)';
    } else {
      bars[0].style.transform = '';
      bars[1].style.opacity   = '';
      bars[2].style.transform = '';
    }
  });

  // Close on outside click
  document.addEventListener('click', function (e) {
    if (!toggle.contains(e.target) && !nav.contains(e.target)) {
      nav.classList.remove('is-open');
      toggle.setAttribute('aria-expanded', false);
      toggle.querySelectorAll('span').forEach(s => {
        s.style.transform = '';
        s.style.opacity   = '';
      });
    }
  });
})();