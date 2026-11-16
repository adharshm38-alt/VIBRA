import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import createApp from '../src/app.js'
import User from '../src/models/User.js'
import Otp from '../src/models/Otp.js'

function makeRequest(server, method, path, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const addr = server.address()
    const options = {
      hostname: '127.0.0.1',
      port: addr.port,
      path,
      method,
      headers: {
        ...headers,
      },
    }

    if (body) {
      const data = typeof body === 'string' ? body : JSON.stringify(body)
      options.headers['Content-Type'] = options.headers['Content-Type'] || 'application/json'
      options.headers['Content-Length'] = Buffer.byteLength(data)
    }

    const req = http.request(options, (res) => {
      let data = ''
      res.on('data', (chunk) => {
        data += chunk
      })
      res.on('end', () => {
        let json = null
        try {
          json = JSON.parse(data)
        } catch {
          json = data
        }
        resolve({ status: res.statusCode, headers: res.headers, body: json })
      })
    })

    req.on('error', reject)
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body))
    }
    req.end()
  })
}

test('Proton Mail OTP & Cloud Library Routes', async (t) => {
  process.env.NODE_ENV = 'test'
  process.env.JWT_SECRET = 'test-secret-proton-auth-1234567890'
  process.env.RESEND_API_KEY = 're_test_mock_api_key_12345'
  process.env.RESEND_FROM_EMAIL = 'MUSICA <onboarding@resend.dev>'

  // Mock globalThis.fetch for Resend API calls
  const originalFetch = globalThis.fetch
  let resendMockResponse = {
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ id: 'msg_resend_mock_id_999' }),
    json: async () => ({ id: 'msg_resend_mock_id_999' }),
  }

  globalThis.fetch = async (url, options) => {
    if (String(url).includes('api.resend.com')) {
      return resendMockResponse
    }
    return originalFetch(url, options)
  }

  const app = createApp()
  const server = http.createServer(app)

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => {
    server.close()
    globalThis.fetch = originalFetch
  })

  await t.test('POST /api/auth/proton/send-otp rejects non-Proton emails', async () => {
    const res = await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, {
      email: 'hacker@gmail.com',
    })
    assert.equal(res.status, 400)
    assert.equal(res.body.success, false)
    assert.equal(res.body.error, 'invalid_email')
  })

  await t.test('POST /api/auth/proton/send-otp fails when RESEND_API_KEY is missing', async () => {
    const savedKey = process.env.RESEND_API_KEY
    delete process.env.RESEND_API_KEY
    const res = await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, {
      email: 'missing.key@proton.me',
    })
    process.env.RESEND_API_KEY = savedKey
    assert.equal(res.status, 503)
    assert.equal(res.body.success, false)
    assert.equal(res.body.error, 'resend_key_missing')
  })

  await t.test('POST /api/auth/proton/send-otp does not return success when Resend rejects (403 Forbidden)', async () => {
    resendMockResponse = {
      ok: false,
      status: 403,
      text: async () => JSON.stringify({
        statusCode: 403,
        name: 'validation_error',
        message: 'You can only send testing emails to your own email address (adharshm38@gmail.com). To send to other domains, please verify a domain at resend.com/domains',
      }),
      json: async () => ({
        statusCode: 403,
        name: 'validation_error',
        message: 'You can only send testing emails to your own email address (adharshm38@gmail.com). To send to other domains, please verify a domain at resend.com/domains',
      }),
    }

    const res = await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, {
      email: 'unverified@proton.me',
    })
    assert.equal(res.status, 403)
    assert.equal(res.body.success, false)
    assert.equal(res.body.error, 'validation_error')
    assert.ok(res.body.message.includes('verify a domain'))
  })

  await t.test('POST /api/auth/proton/send-otp accepts valid Proton email when Resend succeeds', async () => {
    resendMockResponse = {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ id: 'msg_success_abc123' }),
      json: async () => ({ id: 'msg_success_abc123' }),
    }

    const res = await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, {
      email: 'musica.tester@proton.me',
    })
    assert.equal(res.status, 200)
    assert.equal(res.body.success, true)
    assert.equal(res.body.cooldownSeconds, 60)
    assert.equal(res.body.expiresInSeconds, 600)
    assert.equal(res.body.messageId, 'msg_success_abc123')
  })

  await t.test('POST /api/auth/proton/send-otp triggers cooldown on immediate retry', async () => {
    const res = await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, {
      email: 'musica.tester@proton.me',
    })
    assert.equal(res.status, 429)
    assert.equal(res.body.success, false)
    assert.equal(res.body.error, 'cooldown_active')
    assert.ok(res.body.retryAfter > 0)
  })

  await t.test('POST /api/auth/proton/verify-otp fails on incorrect code', async () => {
    const res = await makeRequest(server, 'POST', '/api/auth/proton/verify-otp', {}, {
      email: 'musica.tester@proton.me',
      code: '000000',
    })
    assert.equal(res.status, 400)
    assert.equal(res.body.success, false)
    assert.equal(res.body.error, 'incorrect_code')
    assert.equal(res.body.remainingAttempts, 4)
  })

  await t.test('POST /api/auth/proton/verify-otp succeeds with token, profile, and library sync', async () => {
    // Send to a new email to avoid cooldown
    const testEmail = 'musica.flow@proton.me'
    await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, { email: testEmail })

    // Find the in-memory OTP record to test verification with valid hash
    const { memoryOtps } = await import('../src/controllers/protonAuth.controller.js')
    const record = memoryOtps.get(testEmail)
    assert.ok(record, 'Memory OTP record exists')

    // Generate known valid hash
    const crypto = await import('node:crypto')
    const validCode = '882244'
    record.codeHash = crypto.default.createHmac('sha256', record.salt).update(validCode).digest('hex')

    const res = await makeRequest(server, 'POST', '/api/auth/proton/verify-otp', {}, {
      email: testEmail,
      code: validCode,
    })
    assert.equal(res.status, 200)
    assert.equal(res.body.success, true)
    assert.ok(res.body.token, 'Token present')
    assert.equal(res.body.user.email, testEmail)
    assert.equal(res.body.user.provider, 'proton')
    assert.ok(res.body.user.id, 'User ID present')

    // Test GET /api/user/profile
    const profRes = await makeRequest(server, 'GET', '/api/user/profile', {
      Authorization: `Bearer ${res.body.token}`,
    })
    assert.equal(profRes.status, 200)
    assert.equal(profRes.body.success, true)
    assert.equal(profRes.body.user.email, testEmail)

    // Test POST /api/user/library/sync
    const syncRes = await makeRequest(server, 'POST', '/api/user/library/sync', {
      Authorization: `Bearer ${res.body.token}`,
    }, {
      playlists: [{ id: 'p1', title: 'Top Hits' }],
      likedSongs: ['song1', 'song2'],
    })
    assert.equal(syncRes.status, 200)
    assert.equal(syncRes.body.success, true)
    assert.equal(syncRes.body.library.playlists.length, 1)
    assert.equal(syncRes.body.library.likedSongs.length, 2)

    // Test GET /api/user/library
    const libRes = await makeRequest(server, 'GET', '/api/user/library', {
      Authorization: `Bearer ${res.body.token}`,
    })
    assert.equal(libRes.status, 200)
    assert.equal(libRes.body.success, true)
    assert.equal(libRes.body.library.likedSongs.length, 2)
  })
})
