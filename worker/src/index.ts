export interface Env {
  CREDS_JSON?: string;
  TOKEN_JSON?: string;
  CLIENT_ID?: string;
  CLIENT_SECRET?: string;
  REFRESH_TOKEN?: string;
  USER_ID?: string;
  COUNTRY_CODE?: string;
}

interface Credential {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  userId?: string;
  accessToken?: string;
  expiresAt?: number; // epoch seconds
}

const API_VERSION = "2.5";
const REPO_URL = "https://github.com/santiaxelpro/hifi-api";
const DEFAULT_CLIENT_ID = "zU4XHVVkc2tDPo4t";
const DEFAULT_CLIENT_SECRET = "VJKhDFqJPqvsPVNBV6ukXTJmwlvbttP7wlMlrc72se4=";

let _creds: Credential[] | null = null;
const _refreshPromises = new Map<string, Promise<string>>();

class HttpError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "*",
    "access-control-allow-methods": "*",
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...corsHeaders(),
    },
  });
}

function emptyResponse(status = 204): Response {
  return new Response(null, { status, headers: corsHeaders() });
}

function normalizeTokenField(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? trimmed : undefined;
  }
  if (value && typeof value === "object" && "data" in value) {
    const maybe = (value as { data?: unknown }).data;
    if (typeof maybe === "string" && maybe.trim()) {
      return maybe.trim();
    }
  }
  return undefined;
}

function parseCredEntry(entry: unknown, env: Env): Credential | null {
  if (!entry || typeof entry !== "object") {
    return null;
  }

  const obj = entry as Record<string, unknown>;
  const refreshToken = normalizeTokenField(obj.refresh_token ?? obj.refreshToken);
  if (!refreshToken) {
    return null;
  }

  const clientId =
    normalizeTokenField(obj.client_ID ?? obj.client_id ?? obj.clientId) ||
    env.CLIENT_ID ||
    DEFAULT_CLIENT_ID;

  const clientSecret =
    normalizeTokenField(obj.client_secret ?? obj.clientSecret) ||
    env.CLIENT_SECRET ||
    DEFAULT_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return null;
  }

  const rawUserId = obj.userID ?? obj.user_id ?? obj.userId;
  const userId =
    typeof rawUserId === "number" || typeof rawUserId === "string"
      ? String(rawUserId)
      : undefined;

  return {
    clientId,
    clientSecret,
    refreshToken,
    userId,
    accessToken: undefined,
    expiresAt: 0,
  };
}

function loadCreds(env: Env): Credential[] {
  if (_creds) {
    return _creds;
  }

  const creds: Credential[] = [];
  const raw = env.CREDS_JSON || env.TOKEN_JSON;

  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      const entries = Array.isArray(parsed) ? parsed : [parsed];
      for (const entry of entries) {
        const cred = parseCredEntry(entry, env);
        if (cred && !creds.some((c) => c.refreshToken === cred.refreshToken)) {
          creds.push(cred);
        }
      }
    } catch (err) {
      throw new HttpError(500, "Invalid CREDS_JSON/TOKEN_JSON format");
    }
  }

  if (env.REFRESH_TOKEN) {
    const envCred: Credential = {
      clientId: env.CLIENT_ID || DEFAULT_CLIENT_ID,
      clientSecret: env.CLIENT_SECRET || DEFAULT_CLIENT_SECRET,
      refreshToken: env.REFRESH_TOKEN,
      userId: env.USER_ID,
      accessToken: undefined,
      expiresAt: 0,
    };
    if (!creds.some((c) => c.refreshToken === envCred.refreshToken)) {
      creds.push(envCred);
    }
  }

  _creds = creds;
  return creds;
}

function pickCredential(creds: Credential[]): Credential {
  if (!creds.length) {
    throw new HttpError(
      500,
      "No Tidal credentials available; set CREDS_JSON or REFRESH_TOKEN",
    );
  }
  const idx = Math.floor(Math.random() * creds.length);
  return creds[idx];
}

function credKey(cred: Credential): string {
  return `${cred.clientId}:${cred.refreshToken}`;
}

async function refreshTidalToken(cred: Credential): Promise<string> {
  if (cred.accessToken && cred.expiresAt && Date.now() / 1000 < cred.expiresAt) {
    return cred.accessToken;
  }

  const key = credKey(cred);
  const existing = _refreshPromises.get(key);
  if (existing) {
    return existing;
  }

  const promise = (async () => {
    const body = new URLSearchParams({
      client_id: cred.clientId,
      refresh_token: cred.refreshToken,
      grant_type: "refresh_token",
      scope: "r_usr+w_usr+w_sub",
    });
    const auth = btoa(`${cred.clientId}:${cred.clientSecret}`);

    const res = await fetch("https://auth.tidal.com/v1/oauth2/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${auth}`,
      },
      body,
    });

    if (!res.ok) {
      throw new HttpError(401, `Token refresh failed: ${res.status}`);
    }

    const data = (await res.json()) as Record<string, unknown>;
    const accessToken = data.access_token as string | undefined;
    if (!accessToken) {
      throw new HttpError(401, "Token refresh failed: missing access_token");
    }

    const expiresIn =
      typeof data.expires_in === "number" ? data.expires_in : 3600;

    cred.accessToken = accessToken;
    cred.expiresAt = Math.floor(Date.now() / 1000) + expiresIn - 60;

    return accessToken;
  })();

  _refreshPromises.set(key, promise);
  try {
    return await promise;
  } finally {
    _refreshPromises.delete(key);
  }
}

async function getTidalTokenForCred(
  creds: Credential[],
  cred?: Credential,
  force = false,
): Promise<{ token: string; cred: Credential }> {
  const target = cred ?? pickCredential(creds);
  if (
    !force &&
    target.accessToken &&
    target.expiresAt &&
    Date.now() / 1000 < target.expiresAt
  ) {
    return { token: target.accessToken, cred: target };
  }
  const token = await refreshTidalToken(target);
  return { token, cred: target };
}

function buildUrl(base: string, params?: Record<string, unknown>): string {
  if (!params) {
    return base;
  }
  const url = new URL(base);
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) {
      continue;
    }
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

async function authedGetJson(
  creds: Credential[],
  url: string,
  params?: Record<string, unknown>,
  token?: string,
  cred?: Credential,
): Promise<{ data: any; token: string; cred: Credential }> {
  let currentToken = token;
  let currentCred = cred ?? pickCredential(creds);

  if (!currentToken) {
    const result = await getTidalTokenForCred(creds, currentCred);
    currentToken = result.token;
    currentCred = result.cred;
  }

  const doFetch = async (bearer: string) =>
    fetch(buildUrl(url, params), {
      headers: { authorization: `Bearer ${bearer}` },
    });

  let res = await doFetch(currentToken);
  if (res.status === 401) {
    const refreshed = await getTidalTokenForCred(creds, currentCred, true);
    currentToken = refreshed.token;
    currentCred = refreshed.cred;
    res = await doFetch(currentToken);
  }

  if (!res.ok) {
    if (res.status === 404) {
      throw new HttpError(404, "Resource not found");
    }
    if (res.status === 429) {
      throw new HttpError(429, "Upstream rate limited");
    }
    throw new HttpError(res.status, "Upstream API error");
  }

  const data = await res.json();
  return { data, token: currentToken, cred: currentCred };
}

async function makeRequest(
  creds: Credential[],
  url: string,
  params?: Record<string, unknown>,
): Promise<Response> {
  const result = await authedGetJson(creds, url, params);
  return jsonResponse({ version: API_VERSION, data: result.data });
}

function getIntParam(
  url: URL,
  name: string,
  opts: { required?: boolean; defaultValue?: number; min?: number; max?: number },
): number {
  const value = url.searchParams.get(name);
  if (value === null || value === "") {
    if (opts.required) {
      throw new HttpError(400, `Missing required param: ${name}`);
    }
    if (opts.defaultValue !== undefined) {
      return opts.defaultValue;
    }
    throw new HttpError(400, `Missing required param: ${name}`);
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new HttpError(400, `${name} must be a number`);
  }
  if (opts.min !== undefined && parsed < opts.min) {
    throw new HttpError(400, `${name} must be >= ${opts.min}`);
  }
  if (opts.max !== undefined && parsed > opts.max) {
    throw new HttpError(400, `${name} must be <= ${opts.max}`);
  }
  return parsed;
}

function getStringParam(url: URL, name: string, required = false): string {
  const value = url.searchParams.get(name);
  if ((value === null || value === "") && required) {
    throw new HttpError(400, `Missing required param: ${name}`);
  }
  return value ?? "";
}

function getBoolParam(url: URL, name: string): boolean {
  const value = url.searchParams.get(name);
  if (!value) {
    return false;
  }
  const normalized = value.toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes";
}

function extractUuidFromTidalUrl(href: string | undefined): string | null {
  if (!href) {
    return null;
  }
  const parts = href.split("/");
  if (parts.length < 9) {
    return null;
  }
  return parts.slice(4, 9).join("-");
}

async function handleRequest(request: Request, env: Env): Promise<Response> {
  if (request.method === "OPTIONS") {
    return emptyResponse(204);
  }
  if (request.method !== "GET") {
    return jsonResponse({ detail: "Method not allowed" }, 405);
  }

  const url = new URL(request.url);
  const path = url.pathname.endsWith("/") || url.pathname === "/" ? url.pathname : `${url.pathname}/`;
  const countryCode = env.COUNTRY_CODE || "US";
  const creds = loadCreds(env);

  try {
    switch (path) {
      case "/":
        return jsonResponse({ version: API_VERSION, Repo: REPO_URL });
      case "/info/": {
        const id = getIntParam(url, "id", { required: true });
        return await makeRequest(creds, `https://api.tidal.com/v1/tracks/${id}/`, {
          countryCode,
        });
      }
      case "/track/": {
        const id = getIntParam(url, "id", { required: true });
        const quality = getStringParam(url, "quality") || "HI_RES_LOSSLESS";
        return await makeRequest(creds, `https://tidal.com/v1/tracks/${id}/playbackinfo`, {
          audioquality: quality,
          playbackmode: "STREAM",
          assetpresentation: "FULL",
        });
      }
      case "/recommendations/": {
        const id = getIntParam(url, "id", { required: true });
        return await makeRequest(
          creds,
          `https://tidal.com/v1/tracks/${id}/recommendations`,
          { limit: "20", countryCode: "US" },
        );
      }
      case "/search/": {
        const s = url.searchParams.get("s");
        const a = url.searchParams.get("a");
        const al = url.searchParams.get("al");
        const v = url.searchParams.get("v");
        const p = url.searchParams.get("p");

        if (s) {
          return await makeRequest(creds, "https://api.tidal.com/v1/search/tracks", {
            query: s,
            limit: 25,
            offset: 0,
            countryCode,
          });
        }
        if (a) {
          return await makeRequest(creds, "https://api.tidal.com/v1/search/top-hits", {
            query: a,
            limit: 25,
            offset: 0,
            types: "ARTISTS,TRACKS",
            countryCode,
          });
        }
        if (al) {
          return await makeRequest(creds, "https://api.tidal.com/v1/search/top-hits", {
            query: al,
            limit: 25,
            offset: 0,
            types: "ALBUMS",
            countryCode,
          });
        }
        if (v) {
          return await makeRequest(creds, "https://api.tidal.com/v1/search/top-hits", {
            query: v,
            limit: 25,
            offset: 0,
            types: "VIDEOS",
            countryCode,
          });
        }
        if (p) {
          return await makeRequest(creds, "https://api.tidal.com/v1/search/top-hits", {
            query: p,
            limit: 25,
            offset: 0,
            types: "PLAYLISTS",
            countryCode,
          });
        }
        throw new HttpError(400, "Provide one of s, a, al, v, or p");
      }
      case "/album/": {
        const id = getIntParam(url, "id", { required: true });
        const limit = getIntParam(url, "limit", { defaultValue: 100, min: 1, max: 500 });
        const offset = getIntParam(url, "offset", { defaultValue: 0, min: 0 });

        const tokenResult = await getTidalTokenForCred(creds);
        let token = tokenResult.token;
        let cred = tokenResult.cred;

        const fetchAlbum = async (params: Record<string, unknown>) => {
          const res = await authedGetJson(creds, `https://api.tidal.com/v1/albums/${id}`, params, token, cred);
          token = res.token;
          cred = res.cred;
          return res.data;
        };

        const fetchItems = async (params: Record<string, unknown>) => {
          const res = await authedGetJson(
            creds,
            `https://api.tidal.com/v1/albums/${id}/items`,
            params,
            token,
            cred,
          );
          token = res.token;
          cred = res.cred;
          return res.data;
        };

        const tasks: Promise<any>[] = [];
        tasks.push(fetchAlbum({ countryCode }));

        let remaining = limit;
        let currentOffset = offset;
        const chunk = 100;
        while (remaining > 0) {
          const size = Math.min(remaining, chunk);
          tasks.push(fetchItems({ countryCode, limit: size, offset: currentOffset }));
          currentOffset += size;
          remaining -= size;
        }

        const results = await Promise.all(tasks);
        const albumData = results[0] ?? {};
        const itemsPages = results.slice(1);
        const items: any[] = [];
        for (const page of itemsPages) {
          const pageItems = Array.isArray(page?.items) ? page.items : page;
          if (Array.isArray(pageItems)) {
            items.push(...pageItems);
          }
        }
        albumData.items = items;

        return jsonResponse({ version: API_VERSION, data: albumData });
      }
      case "/mix/": {
        const id = getStringParam(url, "id", true);
        const result = await authedGetJson(
          creds,
          "https://api.tidal.com/v1/pages/mix",
          {
            mixId: id,
            countryCode,
            deviceType: "BROWSER",
          },
        );

        const rows = result.data?.rows ?? [];
        let header: Record<string, unknown> = {};
        let items: any[] = [];

        for (const row of rows) {
          const modules = row?.modules ?? [];
          for (const module of modules) {
            if (module?.type === "MIX_HEADER") {
              header = module.mix ?? {};
            } else if (module?.type === "TRACK_LIST") {
              const pagedList = module.pagedList ?? {};
              items = pagedList.items ?? [];
            }
          }
        }

        return jsonResponse({
          version: API_VERSION,
          mix: header,
          items: items.map((item: any) => item?.item ?? item),
        });
      }
      case "/playlist/": {
        const id = getStringParam(url, "id", true);
        const limit = getIntParam(url, "limit", { defaultValue: 100, min: 1, max: 500 });
        const offset = getIntParam(url, "offset", { defaultValue: 0, min: 0 });

        const tokenResult = await getTidalTokenForCred(creds);
        const token = tokenResult.token;
        const cred = tokenResult.cred;

        const [playlistRes, itemsRes] = await Promise.all([
          authedGetJson(creds, `https://api.tidal.com/v1/playlists/${id}`, { countryCode }, token, cred),
          authedGetJson(
            creds,
            `https://api.tidal.com/v1/playlists/${id}/items`,
            { countryCode, limit, offset },
            token,
            cred,
          ),
        ]);

        return jsonResponse({
          version: API_VERSION,
          playlist: playlistRes.data,
          items: itemsRes.data?.items ?? itemsRes.data,
        });
      }
      case "/artist/similar/": {
        const id = getIntParam(url, "id", { required: true });
        const cursor = url.searchParams.get("cursor");

        const result = await authedGetJson(
          creds,
          `https://openapi.tidal.com/v2/artists/${id}/relationships/similarArtists`,
          {
            "page[cursor]": cursor ?? undefined,
            countryCode,
            include: "similarArtists,similarArtists.profileArt",
          },
        );

        const included = result.data?.included ?? [];
        const artistsMap = new Map<string, any>();
        const artworksMap = new Map<string, any>();
        for (const item of included) {
          if (item?.type === "artists") {
            artistsMap.set(item.id, item);
          } else if (item?.type === "artworks") {
            artworksMap.set(item.id, item);
          }
        }

        const artists = (result.data?.data ?? []).map((entry: any) => {
          const aid = entry.id;
          const inc = artistsMap.get(aid) ?? {};
          const attr = inc.attributes ?? {};

          let picId: string | null = null;
          const rel = inc.relationships?.profileArt?.data;
          if (Array.isArray(rel) && rel.length > 0) {
            const artwork = artworksMap.get(rel[0]?.id);
            const files = artwork?.attributes?.files;
            if (Array.isArray(files) && files.length > 0) {
              picId = extractUuidFromTidalUrl(files[0]?.href);
            }
          }

          return {
            ...attr,
            id: Number.isFinite(Number(aid)) ? Number(aid) : aid,
            picture: picId || attr.selectedAlbumCoverFallback,
            url: `http://www.tidal.com/artist/${aid}`,
            relationType: "SIMILAR_ARTIST",
          };
        });

        return jsonResponse({ version: API_VERSION, artists });
      }
      case "/album/similar/": {
        const id = getIntParam(url, "id", { required: true });
        const cursor = url.searchParams.get("cursor");

        const result = await authedGetJson(
          creds,
          `https://openapi.tidal.com/v2/albums/${id}/relationships/similarAlbums`,
          {
            "page[cursor]": cursor ?? undefined,
            countryCode,
            include: "similarAlbums,similarAlbums.coverArt,similarAlbums.artists",
          },
        );

        const included = result.data?.included ?? [];
        const albumsMap = new Map<string, any>();
        const artworksMap = new Map<string, any>();
        const artistsMap = new Map<string, any>();

        for (const item of included) {
          if (item?.type === "albums") {
            albumsMap.set(item.id, item);
          } else if (item?.type === "artworks") {
            artworksMap.set(item.id, item);
          } else if (item?.type === "artists") {
            artistsMap.set(item.id, item);
          }
        }

        const albums = (result.data?.data ?? []).map((entry: any) => {
          const aid = entry.id;
          const inc = albumsMap.get(aid) ?? {};
          const attr = inc.attributes ?? {};

          let coverId: string | null = null;
          const artRel = inc.relationships?.coverArt?.data;
          if (Array.isArray(artRel) && artRel.length > 0) {
            const artwork = artworksMap.get(artRel[0]?.id);
            const files = artwork?.attributes?.files;
            if (Array.isArray(files) && files.length > 0) {
              coverId = extractUuidFromTidalUrl(files[0]?.href);
            }
          }

          const artistList: Array<{ id: string | number; name: string }> = [];
          const artistRel = inc.relationships?.artists?.data;
          if (Array.isArray(artistRel)) {
            for (const aEntry of artistRel) {
              const aObj = artistsMap.get(aEntry.id);
              if (aObj) {
                const aId = aObj.id;
                artistList.push({
                  id: Number.isFinite(Number(aId)) ? Number(aId) : aId,
                  name: aObj.attributes?.name,
                });
              }
            }
          }

          return {
            ...attr,
            id: Number.isFinite(Number(aid)) ? Number(aid) : aid,
            cover: coverId,
            artists: artistList,
            url: `http://www.tidal.com/album/${aid}`,
          };
        });

        return jsonResponse({ version: API_VERSION, albums });
      }
      case "/artist/": {
        const id = url.searchParams.get("id");
        const f = url.searchParams.get("f");
        const skipTracks = getBoolParam(url, "skip_tracks");

        if (!id && !f) {
          throw new HttpError(400, "Provide id or f query param");
        }

        if (id) {
          const artistId = Number(id);
          if (!Number.isFinite(artistId)) {
            throw new HttpError(400, "id must be a number");
          }
          const result = await authedGetJson(
            creds,
            `https://api.tidal.com/v1/artists/${artistId}`,
            { countryCode },
          );

          const artistData = result.data ?? {};
          if (!artistData.picture && artistData.selectedAlbumCoverFallback) {
            artistData.picture = artistData.selectedAlbumCoverFallback;
          }

          let cover = null;
          if (artistData.picture) {
            const slug = String(artistData.picture).replace(/-/g, "/");
            cover = {
              id: artistData.id,
              name: artistData.name,
              "750": `https://resources.tidal.com/images/${slug}/750x750.jpg`,
            };
          }

          return jsonResponse({ version: API_VERSION, artist: artistData, cover });
        }

        const artistId = Number(f);
        if (!Number.isFinite(artistId)) {
          throw new HttpError(400, "f must be a number");
        }

        const tokenResult = await getTidalTokenForCred(creds);
        const token = tokenResult.token;
        const cred = tokenResult.cred;

        const albumsUrl = `https://api.tidal.com/v1/artists/${artistId}/albums`;
        const commonParams = { countryCode, limit: 100 };

        const tasks: Array<Promise<{ data: any; token: string; cred: Credential }>> = [
          authedGetJson(creds, albumsUrl, commonParams, token, cred),
          authedGetJson(
            creds,
            albumsUrl,
            { ...commonParams, filter: "EPSANDSINGLES" },
            token,
            cred,
          ),
        ];

        if (skipTracks) {
          tasks.push(
            authedGetJson(
              creds,
              `https://api.tidal.com/v1/artists/${artistId}/toptracks`,
              { countryCode, limit: 15 },
              token,
              cred,
            ),
          );
        }

        const results = await Promise.allSettled(tasks);
        const uniqueReleases: any[] = [];
        const seenIds = new Set<number>();

        const firstTwo = results.slice(0, 2);
        for (const res of firstTwo) {
          if (res.status !== "fulfilled") {
            continue;
          }
          const data = res.value.data ?? {};
          for (const item of data.items ?? []) {
            if (item?.id && !seenIds.has(item.id)) {
              seenIds.add(item.id);
              uniqueReleases.push(item);
            }
          }
        }

        const pageData = { items: uniqueReleases };

        if (skipTracks) {
          let topTracks: any[] = [];
          const res = results[2];
          if (res && res.status === "fulfilled") {
            topTracks = res.value.data?.items ?? [];
          }
          return jsonResponse({ version: API_VERSION, albums: pageData, tracks: topTracks });
        }

        if (!uniqueReleases.length) {
          return jsonResponse({ version: API_VERSION, albums: pageData, tracks: [] });
        }

        const semLimit = 6;
        let active = 0;
        const queue: Array<() => Promise<any[]>> = [];

        const fetchAlbumTracks = async (albumId: number): Promise<any[]> => {
          const res = await authedGetJson(
            creds,
            "https://api.tidal.com/v1/pages/album",
            {
              albumId,
              countryCode,
              deviceType: "BROWSER",
            },
          );
          const rows = res.data?.rows ?? [];
          if (rows.length < 2) {
            return [];
          }
          const modules = rows[1]?.modules ?? [];
          if (!modules.length) {
            return [];
          }
          const pagedList = modules[0]?.pagedList ?? {};
          const items = pagedList.items ?? [];
          return items.map((track: any) => track?.item ?? track);
        };

        const runWithSemaphore = <T>(task: () => Promise<T>): Promise<T> =>
          new Promise((resolve, reject) => {
            const run = async () => {
              active += 1;
              try {
                const result = await task();
                resolve(result);
              } catch (err) {
                reject(err);
              } finally {
                active -= 1;
                const next = queue.shift();
                if (next) {
                  void next();
                }
              }
            };
            if (active < semLimit) {
              void run();
            } else {
              queue.push(run);
            }
          });

        const trackTasks = uniqueReleases.map((item) =>
          runWithSemaphore(() => fetchAlbumTracks(item.id)),
        );

        const trackResults = await Promise.allSettled(trackTasks);
        const tracks: any[] = [];
        for (const res of trackResults) {
          if (res.status === "fulfilled") {
            tracks.push(...res.value);
          }
        }

        return jsonResponse({ version: API_VERSION, albums: pageData, tracks });
      }
      case "/cover/": {
        const idParam = url.searchParams.get("id");
        const qParam = url.searchParams.get("q");

        if (!idParam && !qParam) {
          throw new HttpError(400, "Provide id or q query param");
        }

        const buildCoverEntry = (coverSlug: string, name?: string, trackId?: number) => {
          const slug = coverSlug.replace(/-/g, "/");
          return {
            id: trackId,
            name,
            "1280": `https://resources.tidal.com/images/${slug}/1280x1280.jpg`,
            "640": `https://resources.tidal.com/images/${slug}/640x640.jpg`,
            "80": `https://resources.tidal.com/images/${slug}/80x80.jpg`,
          };
        };

        if (idParam) {
          const trackId = Number(idParam);
          if (!Number.isFinite(trackId)) {
            throw new HttpError(400, "id must be a number");
          }

          const res = await authedGetJson(
            creds,
            `https://api.tidal.com/v1/tracks/${trackId}/`,
            { countryCode },
          );
          const album = res.data?.album ?? {};
          const coverSlug = album.cover;
          if (!coverSlug) {
            throw new HttpError(404, "Cover not found");
          }
          const entry = buildCoverEntry(
            coverSlug,
            album.title ?? res.data?.title,
            album.id ?? trackId,
          );
          return jsonResponse({ version: API_VERSION, covers: [entry] });
        }

        const res = await authedGetJson(
          creds,
          "https://api.tidal.com/v1/search/tracks",
          { countryCode, query: qParam, limit: 10 },
        );

        const items = res.data?.items ?? [];
        if (!items.length) {
          throw new HttpError(404, "Cover not found");
        }

        const covers: any[] = [];
        for (const track of items.slice(0, 10)) {
          const album = track?.album ?? {};
          const coverSlug = album.cover;
          if (!coverSlug) {
            continue;
          }
          covers.push(buildCoverEntry(coverSlug, track.title, track.id));
        }

        if (!covers.length) {
          throw new HttpError(404, "Cover not found");
        }

        return jsonResponse({ version: API_VERSION, covers });
      }
      case "/lyrics/": {
        const id = getIntParam(url, "id", { required: true });
        const result = await authedGetJson(
          creds,
          `https://api.tidal.com/v1/tracks/${id}/lyrics`,
          { countryCode, locale: "en_US", deviceType: "BROWSER" },
        );

        if (!result.data) {
          throw new HttpError(404, "Lyrics not found");
        }

        return jsonResponse({ version: API_VERSION, lyrics: result.data });
      }
      default:
        return jsonResponse({ detail: "Not found" }, 404);
    }
  } catch (err) {
    if (err instanceof HttpError) {
      return jsonResponse({ detail: err.detail }, err.status);
    }
    return jsonResponse({ detail: "Internal server error" }, 500);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
};
