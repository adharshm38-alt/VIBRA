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
  process.env.ALLOW_DEV_CONSOLE_OTP = 'true'
  process.env.JWT_SECRET = 'test-secret-proton-auth-1234567890'

  const app = createApp()
  const server = http.createServer(app)

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => server.close())

  await t.test('POST /api/auth/proton/send-otp rejects non-Proton emails', async () => {
    const res = await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, {
      email: 'hacker@gmail.com',
    })
    assert.equal(res.status, 400)
    assert.equal(res.body.success, false)
    assert.equal(res.body.error, 'invalid_email')
  })

  await t.test('POST /api/auth/proton/send-otp accepts valid Proton email', async () => {
    const res = await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, {
      email: 'musica.tester@proton.me',
    })
    assert.equal(res.status, 200)
    assert.equal(res.body.success, true)
    assert.equal(res.body.cooldownSeconds, 60)
    assert.equal(res.body.expiresInSeconds, 600)
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

  await t.test('POST /api/auth/proton/verify-otp succeeds and returns token and user', async () => {
    // Send OTP to get fresh code
    let capturedCode = null
    const origLog = console.log
    const origWarn = console.warn
    console.warn = (msg) => {
      const match = String(msg).match(/OTP for .+ is: (\d{6})/)
      if (match) capturedCode = match[1]
    }

    // Reset cooldown by using a new email
    const testEmail = 'musica.success@proton.me'
    await makeRequest(server, 'POST', '/api/auth/proton/send-otp', {}, { email: testEmail })
    console.warn = origWarn
    assert.ok(capturedCode, 'Captured OTP code')

    const res = await makeRequest(server, 'POST', '/api/auth/proton/verify-otp', {}, {
      email: testEmail,
      code: capturedCode,
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
