<script setup lang="ts">
import SettingsView from '@/views/SettingsView.vue'
</script>

<template>
  <header>
    <h1>ATT&amp;CK-pivot Explorer</h1>
  </header>
  <main>
    <SettingsView />
  </main>
  <footer>
    <p>
      MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation. This project is not
      affiliated with or endorsed by MITRE.
    </p>
  </footer>
</template>

<style>
:root {
  --bg: #ffffff;
  --fg: #1c2024;
  --muted: #5b6570;
  --border: #c9d1d9;
  --ok: #1a7f37;
  --info: #0b61a4;
  --bad: #b3261e;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14181d;
    --fg: #e6e9ec;
    --muted: #9aa5b1;
    --border: #3a434c;
    --ok: #4cc26b;
    --info: #5aa9e6;
    --bad: #ff8a80;
  }
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
}
header, main, footer { padding: 1rem 1rem; max-width: 60rem; margin: 0 auto; }
footer { color: var(--muted); font-size: 0.85rem; }
</style>
