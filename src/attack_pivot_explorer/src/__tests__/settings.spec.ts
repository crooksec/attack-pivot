import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import SettingsView from '@/views/SettingsView.vue'
import { useSettingsStore } from '@/stores/settings'

const KEY = 'serper-key-0123456789abcdef'

const options = [
  {
    key: 'search.provider', label: 'Search provider', help: 'Which API', kind: 'choice',
    default: 'off', choices: ['off', 'serper', 'brave', 'both'], minimum: null, maximum: null,
    group: 'Search', value: 'off', is_default: true,
  },
  {
    key: 'search.results_per_query', label: 'Results per query', help: 'How many', kind: 'int',
    default: 10, choices: [], minimum: 1, maximum: 20, group: 'Search', value: 10, is_default: true,
  },
]
const secrets = (source: string) => [
  { name: 'SERPER_API_KEY', label: 'Serper', purpose: 'Web search', source, unreadable: false, updated_at: null },
  { name: 'BRAVE_API_KEY', label: 'Brave Search', purpose: 'Web search', source: 'environment', unreadable: false, updated_at: null },
]

type Call = { method: string; url: string; headers: Record<string, string>; body?: string }
let calls: Call[]
let respond: (call: Call) => { status?: number; json: unknown }

beforeEach(() => {
  setActivePinia(createPinia())
  sessionStorage.clear()
  calls = []
  respond = () => ({ json: { options, secrets: secrets('missing') } })
  vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
    const call: Call = {
      method: init.method ?? 'GET',
      url,
      headers: init.headers as Record<string, string>,
      body: init.body as string | undefined,
    }
    calls.push(call)
    const { status = 200, json } = respond(call)
    return new Response(JSON.stringify(json), { status })
  })
})

describe('settings store', () => {
  it('sends the admin token and loads options and secret status', async () => {
    const store = useSettingsStore()
    await store.connect('  tok  ')
    expect(calls[0].url).toBe('/api/v1/pivot/settings')
    expect(calls[0].headers['X-Pivot-Admin-Token']).toBe('tok')
    expect(store.loaded).toBe(true)
    expect(store.options).toHaveLength(2)
  })

  it('explains a refused token', async () => {
    respond = () => ({ status: 403, json: { detail: 'invalid admin token' } })
    const store = useSettingsStore()
    await store.connect('bad')
    expect(store.loaded).toBe(false)
    expect(store.error).toContain('PIVOT_ADMIN_TOKEN')
  })

  it('sends a secret once and never keeps the value', async () => {
    const store = useSettingsStore()
    await store.connect('tok')
    respond = () => ({ json: { secrets: secrets('stored') } })
    expect(await store.setSecret('SERPER_API_KEY', KEY)).toBe(true)
    expect(calls.at(-1)!.method).toBe('PUT')
    expect(JSON.parse(calls.at(-1)!.body!)).toEqual({ value: KEY })
    expect(JSON.stringify(store.$state)).not.toContain(KEY)
    expect(store.secrets[0].source).toBe('stored')
  })

  it('surfaces a validation error', async () => {
    const store = useSettingsStore()
    await store.connect('tok')
    respond = () => ({ status: 422, json: { detail: 'search.provider: choose one of off' } })
    await store.setOption('search.provider', 'bing')
    expect(store.error).toBe('search.provider: choose one of off')
  })
})

describe('SettingsView', () => {
  async function connected() {
    const wrapper = mount(SettingsView)
    await wrapper.get('#admin-token').setValue('tok')
    await wrapper.get('form.token').trigger('submit')
    await flushPromises()
    return wrapper
  }

  it('shows where each key comes from and the options', async () => {
    const wrapper = await connected()
    const text = wrapper.text()
    expect(text).toContain('Not set')
    expect(text).toContain('From deployment')
    expect(text).toContain('Search provider')
    expect(wrapper.find('select#search\\.provider').exists()).toBe(true)
  })

  it('clears the key field after saving and never renders the key', async () => {
    const wrapper = await connected()
    respond = () => ({ json: { secrets: secrets('stored') } })
    const input = wrapper.get('input[aria-label="New value for SERPER_API_KEY"]')
    expect(input.attributes('type')).toBe('password')
    await input.setValue(KEY)
    await wrapper.findAll('button').find((b) => b.text() === 'Save')!.trigger('click')
    await flushPromises()
    expect((input.element as HTMLInputElement).value).toBe('')
    expect(wrapper.html()).not.toContain(KEY)
    expect(wrapper.text()).toContain('Stored')
  })

  it('saves a changed option and offers a reset when it differs from the default', async () => {
    const wrapper = await connected()
    respond = () => ({
      json: { options: [{ ...options[0], value: 'both', is_default: false }, options[1]] },
    })
    await wrapper.get('select#search\\.provider').setValue('both')
    await flushPromises()
    expect(JSON.parse(calls.at(-1)!.body!)).toEqual({ value: 'both' })
    expect(wrapper.text()).toContain('Reset to off')
  })
})
