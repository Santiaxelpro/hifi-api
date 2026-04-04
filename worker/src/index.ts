export interface Env {
  CLIENT_ID?: string
  CLIENT_SECRET?: string
  REFRESH_TOKEN?: string
  USER_ID?: string
  COUNTRY_CODE?: string
  CREDS_JSON?: string
}

const API_VERSION = "2.7"

// ===== TYPES =====
type Cred = {
  clientId: string
  clientSecret: string
  refreshToken: string
  userId?: string
  accessToken?: string
  expiresAt: number
}

// ===== GLOBAL =====
let CREDS: Cred[] | null = null
const refreshMap = new Map<string, Promise<string>>()

// ===== UTILS =====
const json = (data: any, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*"
    }
  })

const pick = (arr: any[]) => arr[Math.floor(Math.random() * arr.length)]

const credKey = (c: Cred) => `${c.clientId}:${c.refreshToken}`

// ===== LOAD CREDS =====
function loadCreds(env: Env): Cred[] {
  if (CREDS) return CREDS

  const list: Cred[] = []

  if (env.CREDS_JSON) {
    const parsed = JSON.parse(env.CREDS_JSON)
    const arr = Array.isArray(parsed) ? parsed : [parsed]

    for (const e of arr) {
      if (!e.refresh_token) continue
      list.push({
        clientId: e.client_ID || env.CLIENT_ID!,
        clientSecret: e.client_secret || env.CLIENT_SECRET!,
        refreshToken: e.refresh_token,
        userId: e.userID,
        expiresAt: 0
      })
    }
  }

  if (env.REFRESH_TOKEN) {
    list.push({
      clientId: env.CLIENT_ID!,
      clientSecret: env.CLIENT_SECRET!,
      refreshToken: env.REFRESH_TOKEN,
      userId: env.USER_ID,
      expiresAt: 0
    })
  }

  CREDS = list
  return list
}

// ===== TOKEN =====
async function getToken(cred: Cred): Promise<string> {
  if (cred.accessToken && Date.now() / 1000 < cred.expiresAt) {
    return cred.accessToken
  }

  const key = credKey(cred)
  if (refreshMap.has(key)) return refreshMap.get(key)!

  const p = (async () => {
    const body = new URLSearchParams({
      client_id: cred.clientId,
      refresh_token: cred.refreshToken,
      grant_type: "refresh_token"
    })

    const res = await fetch("https://auth.tidal.com/v1/oauth2/token", {
      method: "POST",
      headers: {
        authorization: "Basic " + btoa(`${cred.clientId}:${cred.clientSecret}`)
      },
      body
    })

    if (!res.ok) throw new Error("refresh failed")

    const d = await res.json()
    cred.accessToken = d.access_token
    cred.expiresAt = Date.now() / 1000 + d.expires_in - 60

    return cred.accessToken!
  })()

  refreshMap.set(key, p)
  try {
    return await p
  } finally {
    refreshMap.delete(key)
  }
}

// ===== FETCH CORE =====
async function tidal(
  creds: Cred[],
  url: string,
  params?: any,
  retry = true
) {
  const cred = pick(creds)
  let token = await getToken(cred)

  const u = new URL(url)
  if (params) {
    for (const k in params) {
      if (params[k] !== undefined) {
        u.searchParams.append(k, params[k])
      }
    }
  }

  let res = await fetch(u.toString(), {
    headers: { authorization: `Bearer ${token}` }
  })

  if (res.status === 401 && retry) {
    token = await getToken(cred)
    return tidal(creds, url, params, false)
  }

  if (!res.ok) {
    return json({ error: "Upstream", status: res.status }, res.status)
  }

  return res.json()
}

// ===== PARALLEL LIMITER =====
async function limitAll(tasks: (() => Promise<any>)[], limit = 8) {
  const results: any[] = []
  let i = 0

  async function worker() {
    while (i < tasks.length) {
      const idx = i++
      results[idx] = await tasks[idx]()
    }
  }

  await Promise.all(Array.from({ length: limit }, worker))
  return results
}

// ===== ROUTER =====
export default {
  async fetch(req: Request, env: Env) {
    const url = new URL(req.url)
    const p = url.pathname
    const creds = loadCreds(env)
    const cc = env.COUNTRY_CODE || "US"

    try {
      // ROOT
      if (p === "/") return json({ version: API_VERSION })

      // TRACK
      if (p === "/track/") {
        const id = url.searchParams.get("id")
        return json({
          version: API_VERSION,
          data: await tidal(creds,
            `https://api.tidal.com/v1/tracks/${id}/playbackinfo`,
            { audioquality: "HI_RES_LOSSLESS", playbackmode: "STREAM" })
        })
      }

      // INFO
      if (p === "/info/") {
        const id = url.searchParams.get("id")
        return json({
          version: API_VERSION,
          data: await tidal(creds,
            `https://api.tidal.com/v1/tracks/${id}`,
            { countryCode: cc })
        })
      }

      // TRACK MANIFEST
      if (p === "/trackManifests/") {
        const id = url.searchParams.get("id")
        const data = await tidal(creds,
          `https://openapi.tidal.com/v2/trackManifests/${id}`,
          { adaptive: true })

        if (data?.data?.attributes?.drmData) {
          const base = url.origin + "/widevine"
          data.data.attributes.drmData.licenseUrl = base
          data.data.attributes.drmData.certificateUrl = base
        }

        return json({ version: API_VERSION, data })
      }

      // WIDEVINE
      if (p === "/widevine") {
        const cred = pick(creds)
        const token = await getToken(cred)

        const res = await fetch("https://api.tidal.com/v2/widevine", {
          method: req.method,
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": req.headers.get("content-type") || ""
          },
          body: await req.arrayBuffer()
        })

        return new Response(res.body, res)
      }

      // SEARCH
      if (p === "/search/") {
        const q = url.searchParams.get("s")
        return json({
          version: API_VERSION,
          data: await tidal(creds,
            "https://api.tidal.com/v1/search/tracks",
            { query: q, limit: 50, countryCode: cc })
        })
      }

      // ALBUM FULL (FAST)
      if (p === "/album/") {
        const id = url.searchParams.get("id")

        const meta = tidal(creds, `https://api.tidal.com/v1/albums/${id}`, { countryCode: cc })

        const pages = []
        for (let i = 0; i < 5; i++) {
          pages.push(() =>
            tidal(creds,
              `https://api.tidal.com/v1/albums/${id}/items`,
              { countryCode: cc, limit: 100, offset: i * 100 })
          )
        }

        const results = await limitAll(pages, 5)
        const items = results.flatMap(r => r?.items || [])

        return json({
          version: API_VERSION,
          data: { ...(await meta), items }
        })
      }

      // PLAYLIST
      if (p === "/playlist/") {
        const id = url.searchParams.get("id")

        const [meta, items] = await Promise.all([
          tidal(creds, `https://api.tidal.com/v1/playlists/${id}`, { countryCode: cc }),
          tidal(creds, `https://api.tidal.com/v1/playlists/${id}/items`, { countryCode: cc, limit: 100 })
        ])

        return json({ version: API_VERSION, playlist: meta, items: items.items })
      }

      // ARTIST
      if (p === "/artist/") {
        const id = url.searchParams.get("id")

        return json({
          version: API_VERSION,
          artist: await tidal(creds,
            `https://api.tidal.com/v1/artists/${id}`,
            { countryCode: cc })
        })
      }

      // LYRICS
      if (p === "/lyrics/") {
        const id = url.searchParams.get("id")

        return json({
          version: API_VERSION,
          lyrics: await tidal(creds,
            `https://api.tidal.com/v1/tracks/${id}/lyrics`,
            { countryCode: cc })
        })
      }

      // VIDEO
      if (p === "/video/") {
        const id = url.searchParams.get("id")

        return json({
          version: API_VERSION,
          video: await tidal(creds,
            `https://api.tidal.com/v1/videos/${id}/playbackinfo`)
        })
      }

      return json({ error: "Not found" }, 404)

    } catch (e) {
      return json({ error: "Internal error" }, 500)
    }
  }
}