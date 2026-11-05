export interface OptionInfo {
  key: string
  label: string
  help: string
  kind: 'choice' | 'int'
  default: string | number
  choices: string[]
  minimum: number | null
  maximum: number | null
  group: string
  value: string | number
  is_default: boolean
}

export interface SecretStatus {
  name: string
  label: string
  purpose: string
  source: 'stored' | 'environment' | 'missing'
  unreadable: boolean
  updated_at: string | null
}

export class SettingsApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

export const apiBase = (): string =>
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1'

async function call<T>(token: string, method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${apiBase()}/pivot/settings${path}`, {
    method,
    headers: {
      'X-Pivot-Admin-Token': token,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    let detail = `HTTP ${response.status}`
    try {
      const data = await response.json()
      if (typeof data?.detail === 'string') detail = data.detail
    } catch {
      /* keep the status text */
    }
    throw new SettingsApiError(response.status, detail)
  }
  return (await response.json()) as T
}

export interface SettingsPayload {
  options: OptionInfo[]
  secrets: SecretStatus[]
}

export const fetchSettings = (token: string) => call<SettingsPayload>(token, 'GET', '')
export const putOption = (token: string, key: string, value: string | number) =>
  call<{ options: OptionInfo[] }>(token, 'PUT', `/options/${encodeURIComponent(key)}`, { value })
export const resetOption = (token: string, key: string) =>
  call<{ options: OptionInfo[] }>(token, 'DELETE', `/options/${encodeURIComponent(key)}`)
export const putSecret = (token: string, name: string, value: string) =>
  call<{ secrets: SecretStatus[] }>(token, 'PUT', `/secrets/${encodeURIComponent(name)}`, { value })
export const deleteSecret = (token: string, name: string) =>
  call<{ secrets: SecretStatus[] }>(token, 'DELETE', `/secrets/${encodeURIComponent(name)}`)
