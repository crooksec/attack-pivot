<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useSettingsStore } from '@/stores/settings'
import type { OptionInfo, SecretStatus } from '@/api/settings'

const store = useSettingsStore()
const tokenInput = ref(store.token)
const secretInputs = reactive<Record<string, string>>({})

onMounted(() => {
  if (store.token) store.connect(store.token)
})

const groups = computed(() => {
  const byGroup = new Map<string, OptionInfo[]>()
  for (const option of store.options) {
    byGroup.set(option.group, [...(byGroup.get(option.group) ?? []), option])
  }
  return [...byGroup.entries()]
})

const SOURCE_LABEL: Record<SecretStatus['source'], string> = {
  stored: 'Stored',
  environment: 'From deployment',
  missing: 'Not set',
}

function sourceLabel(secret: SecretStatus): string {
  return secret.unreadable ? 'Stored value unreadable' : SOURCE_LABEL[secret.source]
}

async function saveSecret(name: string) {
  const value = secretInputs[name]
  if (!value || !value.trim()) return
  const ok = await store.setSecret(name, value)
  if (ok) secretInputs[name] = ''
}

function onOption(option: OptionInfo, event: Event) {
  const raw = (event.target as HTMLInputElement | HTMLSelectElement).value
  store.setOption(option.key, option.kind === 'int' ? Number(raw) : raw)
}
</script>

<template>
  <section class="settings">
    <h2>Settings</h2>

    <form class="token" @submit.prevent="store.connect(tokenInput)">
      <label for="admin-token">Admin token</label>
      <input
        id="admin-token"
        v-model="tokenInput"
        type="password"
        autocomplete="off"
        placeholder="PIVOT_ADMIN_TOKEN"
      />
      <button type="submit" :disabled="store.busy || !tokenInput.trim()">Connect</button>
    </form>

    <p v-if="store.error" class="error" role="alert">{{ store.error }}</p>

    <template v-if="store.loaded">
      <h3>API keys</h3>
      <p class="note">
        Keys are encrypted on the server and can be replaced or removed here, never read back. A key
        set in the server's environment is used when nothing is stored.
      </p>
      <ul class="secrets">
        <li v-for="secret in store.secrets" :key="secret.name">
          <div class="head">
            <strong>{{ secret.label }}</strong>
            <code>{{ secret.name }}</code>
            <span class="badge" :data-source="secret.unreadable ? 'unreadable' : secret.source">
              {{ sourceLabel(secret) }}
            </span>
          </div>
          <p class="note">{{ secret.purpose }}</p>
          <div class="row">
            <input
              v-model="secretInputs[secret.name]"
              type="password"
              autocomplete="off"
              :aria-label="`New value for ${secret.name}`"
              placeholder="Paste a new key"
            />
            <button
              type="button"
              :disabled="store.busy || !(secretInputs[secret.name] ?? '').trim()"
              @click="saveSecret(secret.name)"
            >
              Save
            </button>
            <button
              v-if="secret.source === 'stored' || secret.unreadable"
              type="button"
              :disabled="store.busy"
              @click="store.deleteSecret(secret.name)"
            >
              Remove
            </button>
          </div>
        </li>
      </ul>

      <template v-for="[group, options] in groups" :key="group">
        <h3>{{ group }}</h3>
        <div v-for="option in options" :key="option.key" class="option">
          <label :for="option.key">{{ option.label }}</label>
          <select
            v-if="option.kind === 'choice'"
            :id="option.key"
            :value="option.value"
            @change="onOption(option, $event)"
          >
            <option v-for="choice in option.choices" :key="choice" :value="choice">
              {{ choice }}
            </option>
          </select>
          <input
            v-else
            :id="option.key"
            type="number"
            :min="option.minimum ?? undefined"
            :max="option.maximum ?? undefined"
            :value="option.value"
            @change="onOption(option, $event)"
          />
          <button
            v-if="!option.is_default"
            type="button"
            :disabled="store.busy"
            @click="store.resetOption(option.key)"
          >
            Reset to {{ option.default }}
          </button>
          <p class="note">{{ option.help }}</p>
        </div>
      </template>
    </template>
  </section>
</template>

<style scoped>
.settings { max-width: 46rem; }
.token, .row, .option { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
.token { margin-bottom: 1rem; }
.option { margin-bottom: 0.75rem; }
.option .note { flex-basis: 100%; margin: 0; }
.option label { min-width: 12rem; font-weight: 600; }
input, select, button { font: inherit; padding: 0.35rem 0.6rem; }
input[type='password'] { min-width: 18rem; }
.secrets { list-style: none; padding: 0; }
.secrets li { border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; margin-bottom: 0.75rem; }
.head { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: baseline; }
.note { color: var(--muted); font-size: 0.9rem; margin: 0.25rem 0 0.5rem; }
.badge { margin-left: auto; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.8rem; border: 1px solid var(--border); }
.badge[data-source='stored'] { border-color: var(--ok); color: var(--ok); }
.badge[data-source='environment'] { border-color: var(--info); color: var(--info); }
.badge[data-source='unreadable'] { border-color: var(--bad); color: var(--bad); }
.error { color: var(--bad); }
</style>
