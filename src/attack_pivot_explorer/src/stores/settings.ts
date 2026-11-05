import { defineStore } from 'pinia'
import * as api from '@/api/settings'
import type { OptionInfo, SecretStatus } from '@/api/settings'

const TOKEN_KEY = 'pivot-admin-token'

function readToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? ''
  } catch {
    return ''
  }
}

function keepToken(token: string) {
  try {
    sessionStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* private window or blocked storage: the token lives in memory only */
  }
}

export const useSettingsStore = defineStore('settings', {
  state: () => ({
    token: readToken(),
    options: [] as OptionInfo[],
    secrets: [] as SecretStatus[],
    loaded: false,
    busy: false,
    error: '',
  }),
  actions: {
    async run<T>(work: () => Promise<T>): Promise<T | undefined> {
      this.busy = true
      this.error = ''
      try {
        return await work()
      } catch (e) {
        if (e instanceof api.SettingsApiError && e.status === 403) {
          this.error =
            'The server refused the admin token. Check it, and that PIVOT_ADMIN_TOKEN is set on the API.'
        } else {
          this.error = e instanceof Error ? e.message : String(e)
        }
        return undefined
      } finally {
        this.busy = false
      }
    },
    async connect(token: string) {
      this.token = token.trim()
      keepToken(this.token)
      const data = await this.run(() => api.fetchSettings(this.token))
      this.loaded = data !== undefined
      if (data) {
        this.options = data.options
        this.secrets = data.secrets
      }
    },
    async setOption(key: string, value: string | number) {
      const data = await this.run(() => api.putOption(this.token, key, value))
      if (data) this.options = data.options
    },
    async resetOption(key: string) {
      const data = await this.run(() => api.resetOption(this.token, key))
      if (data) this.options = data.options
    },
    /** The value is sent and dropped: it is never kept in the store. */
    async setSecret(name: string, value: string): Promise<boolean> {
      const data = await this.run(() => api.putSecret(this.token, name, value))
      if (data) this.secrets = data.secrets
      return data !== undefined
    },
    async deleteSecret(name: string) {
      const data = await this.run(() => api.deleteSecret(this.token, name))
      if (data) this.secrets = data.secrets
    },
  },
})
