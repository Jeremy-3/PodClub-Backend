# PodClub API

This document describes the browser upload flow and current WebSocket contract.
Use the generated [OpenAPI export](openapi.json) for the complete request and
response schemas.

## Authentication

Call `POST /auth/login` with form data (`username` and `password`) and send the
returned JWT as `Authorization: Bearer <access_token>` on protected requests.
WebSockets use the same JWT as the `token` query parameter.

## Signed media uploads

The browser must never receive the Supabase service-role key. The server creates
signed upload URLs and returns only the upload URL/token, object path, public
URL, bucket name, and size limit.

1. Authenticate.
2. Call `POST /uploads/sign` with `kind`, `podclub_id` when required,
   `filename`, and `content_type`.
3. Upload the file using plain HTTP. The expected method is a `PUT` to the
   returned `signed_url`, with the file bytes as the request body and
   `Content-Type` equal to the signed file's MIME type.
4. Send the returned `path` or `public_url` to the matching media write endpoint
   (`audio_url`, `cover_url`, `avatar_url`, or `image_url`).

Example:

```javascript
const signResponse = await fetch("/uploads/sign", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    kind: "audio",
    podclub_id: podclubId,
    filename: "episode.mp3",
    content_type: "audio/mpeg",
  }),
});

if (!signResponse.ok) throw new Error("Could not sign upload");

const { data } = await signResponse.json();
const file = fileInput.files[0];

const uploadResponse = await fetch(data.signed_url, {
  method: "PUT",
  headers: {
    "Content-Type": file.type,
  },
  body: file,
});

if (!uploadResponse.ok) throw new Error("Supabase upload failed");

await fetch(`/episodes`, {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    podcast_id: podcastId,
    title: "Episode title",
    audio_url: data.path,
    duration: 120,
  }),
});
```

The frontend does not need a Supabase key with this plain-fetch flow. Use
`supabase-js` only if real project verification proves the REST PUT flow cannot
be used; in that case the frontend would need only Supabase's public
publishable/anon key, never the service-role key.

Before this flow is used against a real Supabase project, verify the exact
signed upload URL and upload method against that project's dev bucket.

## Media validation

The server only accepts media references produced for the correct kind, user,
and club:

- `audio`: `audio/{podclub_id}/{user_id}/{uuid}.{ext}`
- `image`: `images/{podclub_id}/{user_id}/{uuid}.{ext}`
- `club_cover`: `covers/{podclub_id}/{uuid}.{ext}`
- `avatar`: `avatars/{user_id}/{uuid}.{ext}`

The object must exist, pass the kind-specific size limit, and have an allowed
MIME type. The server stores the public URL in PostgreSQL. External media URLs
are allowed only in local development when
`ALLOW_EXTERNAL_MEDIA_URLS=true`; they are forbidden in production.

## Private-club media limitation

Private-club media is stored in the same public bucket as other media. The UUID
object paths are unguessable, so these files are **unlisted**, not secret.
Anyone who obtains the public URL can access the file. Private-club authorization
must not be inferred from the bucket or object URL. This API does not provide
private-bucket signed read URLs.

## WebSockets

Connect with:

```text
ws://localhost:8000/ws/podclubs/{podclub_uid}?token=<JWT>
```

Use `wss://` over HTTPS in production. The connection is push-only; send no
application messages. The server pushes JSON events such as:

```json
{"type":"message.created","data":{"id":1,"uid":"..."}}
{"type":"message.updated","data":{"id":1,"uid":"..."}}
{"type":"message.deleted","data":{"id":1,"uid":"..."}}
{"type":"episode.created","data":{"id":1,"uid":"..."}}
{"type":"episode.updated","data":{"id":1,"uid":"..."}}
{"type":"episode.deleted","data":{"id":1,"uid":"..."}}
```

WebSocket state is in memory. The deployment must use **one worker**; events
are not shared across processes.
