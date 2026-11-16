import crypto from 'node:crypto'
import mongoose from 'mongoose'
import User from '../models/User.js'
import Otp from '../models/Otp.js'
import ApiError from '../utils/ApiError.js'
import asyncHandler from '../utils/asyncHandler.js'
import { signToken } from '../services/token.service.js'

function isMongoConnected() {
  return mongoose.connection?.readyState === 1
}

const PROTON_DOMAINS = new Set([
  'proton.me',
  'protonmail.com',
  'pm.me',
  'protonmail.ch',
])

const OTP_EXPIRY_MS = 10 * 60 * 1000 // 10 minutes
const OTP_COOLDOWN_MS = 60 * 1000 // 60 seconds
const MAX_VERIFY_ATTEMPTS = 5
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000 // 10 minutes
const MAX_SEND_PER_WINDOW = 5

// In-memory send rate limiter per IP / email
const sendRateLimits = new Map()

// In-memory fallback datastore for OTPs and users when MongoDB is unavailable
export const memoryOtps = new Map()
export const memoryUsers = new Map()

function checkSendRateLimit(key) {
  const now = Date.now()
  const entry = sendRateLimits.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS }
  if (now > entry.resetAt) {
    entry.count = 0
    entry.resetAt = now + RATE_LIMIT_WINDOW_MS
  }
  if (entry.count >= MAX_SEND_PER_WINDOW) {
    const waitSec = Math.ceil((entry.resetAt - now) / 1000)
    return { allowed: false, waitSec }
  }
  entry.count += 1
  sendRateLimits.set(key, entry)
  return { allowed: true }
}

export function isValidProtonEmail(email) {
  if (!email || typeof email !== 'string') return false
  const clean = email.trim().toLowerCase()
  const parts = clean.split('@')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false
  return PROTON_DOMAINS.has(parts[1])
}

function hashOtp(code, salt) {
  return crypto.createHmac('sha256', salt).update(code.toString()).digest('hex')
}

async function sendOtpEmail(email, code) {
  const apiKey = (process.env.RESEND_API_KEY || '').trim()
  const fromEmail = (process.env.RESEND_FROM_EMAIL || 'MUSICA <onboarding@resend.dev>').trim()
  const recipient = (email || '').trim().toLowerCase()

  // 1. Verify RESEND_API_KEY is present without printing or exposing its value
  if (!apiKey) {
    console.error('[Resend] Delivery aborted: RESEND_API_KEY is not configured in backend environment.')
    return {
      ok: false,
      status: 503,
      error: 'resend_key_missing',
      message: 'Email delivery service is not configured (RESEND_API_KEY missing on server).',
    }
  }

  // 2. Check and log configured sender and recipient without leaking secrets
  console.log(`[Resend] Dispatching verification email from "${fromEmail}" to "${recipient}"`)

  try {
    const htmlBody = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>MUSICA Verification Code</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0b0f; color: #ffffff; margin: 0; padding: 24px; }
        .card { max-width: 440px; margin: 0 auto; background: #181824; border-radius: 20px; padding: 36px 28px; border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: 0 12px 36px rgba(0,0,0,0.4); text-align: center; }
        .logo { font-size: 26px; font-weight: 800; letter-spacing: 2px; color: #a78bfa; margin-bottom: 8px; }
        .subtitle { font-size: 14px; color: #9ca3af; margin-bottom: 28px; }
        .code-box { background: #262438; border-radius: 12px; padding: 18px 24px; margin: 24px 0; font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #6d4aff; border: 1px solid #6d4aff88; }
        .footer { font-size: 12px; color: #6b7280; line-height: 1.5; margin-top: 28px; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="logo">MUSICA</div>
        <div class="subtitle">Proton Mail Authentication</div>
        <p style="font-size: 15px; color: #e5e7eb; margin: 0 0 16px 0;">Use the verification code below to sign in to your MUSICA account:</p>
        <div class="code-box">${code}</div>
        <p style="font-size: 13px; color: #9ca3af; margin: 0;">This code expires in 10 minutes. If you did not request this code, you can safely ignore this email.</p>
        <div class="footer">
          MUSICA • High-Fidelity Music Streaming<br/>
          Protected with Proton End-to-End Privacy
        </div>
      </div>
    </body>
    </html>
    `

    const payload = JSON.stringify({
      from: fromEmail,
      to: [recipient],
      subject: `Your MUSICA verification code: ${code}`,
      html: htmlBody,
    })

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: payload,
    })

    const resText = await res.text()
    let resData = null
    try {
      resData = JSON.parse(resText)
    } catch {
      resData = { message: resText }
    }

    if (!res.ok) {
      const status = res.status
      const errName = resData?.name || 'ResendError'
      const errMsg = resData?.message || resText || `HTTP ${status}`
      console.error(`[Resend] Resend API error (${status} ${errName}): ${errMsg}`)
      return {
        ok: false,
        status: status === 403 ? 403 : 502,
        error: errName,
        message: errMsg,
      }
    }

    const messageId = resData?.id || 'unknown'
    console.log(`[Resend] Email accepted by Resend. Message ID: ${messageId}`)
    return {
      ok: true,
      id: messageId,
    }
  } catch (err) {
    console.error('[Resend] Email dispatch error:', err.message)
    return {
      ok: false,
      status: 502,
      error: 'network_error',
      message: `Failed to connect to Resend API: ${err.message}`,
    }
  }
}

const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  path: '/',
}

/**
 * POST /api/auth/proton/send-otp
 */
export const sendOtp = asyncHandler(async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase()
  if (!email || !isValidProtonEmail(email)) {
    return res.status(400).json({
      success: false,
      error: 'invalid_email',
      message: 'Please provide a valid Proton email address (@proton.me, @protonmail.com, @pm.me)',
    })
  }

  const clientIp = req.ip || req.headers['x-forwarded-for'] || 'unknown'
  const rateLimit = checkSendRateLimit(`send_${email}_${clientIp}`)
  if (!rateLimit.allowed) {
    return res.status(429).json({
      success: false,
      error: 'rate_limited',
      message: 'Too many verification requests. Please try again later.',
      retryAfter: rateLimit.waitSec,
    })
  }

  // Check cooldown from previous request
  let existingOtp = null
  if (isMongoConnected()) {
    try {
      existingOtp = await Otp.findOne({ email })
    } catch (err) {
      existingOtp = memoryOtps.get(email) || null
    }
  } else {
    existingOtp = memoryOtps.get(email) || null
  }

  const now = Date.now()
  if (existingOtp && existingOtp.lastSentAt) {
    const lastSentTime = new Date(existingOtp.lastSentAt).getTime()
    if (now - lastSentTime < OTP_COOLDOWN_MS) {
      const retryAfter = Math.ceil((OTP_COOLDOWN_MS - (now - lastSentTime)) / 1000)
      return res.status(429).json({
        success: false,
        error: 'cooldown_active',
        message: `Please wait ${retryAfter} seconds before requesting a new code.`,
        retryAfter,
      })
    }
  }

  // Generate 6-digit cryptographic OTP code
  const code = crypto.randomInt(100000, 1000000).toString()
  const salt = crypto.randomBytes(16).toString('hex')
  const codeHash = hashOtp(code, salt)
  const expiresAt = new Date(now + OTP_EXPIRY_MS)
  const lastSentAt = new Date(now)

  // Dispatch email via Resend
  const sendResult = await sendOtpEmail(email, code)
  if (!sendResult.ok) {
    return res.status(sendResult.status || 502).json({
      success: false,
      error: sendResult.error || 'email_delivery_failed',
      message: sendResult.message || 'Failed to dispatch verification email via Resend.',
    })
  }

  // Persist OTP only after Resend confirms the email was accepted
  const record = {
    email,
    codeHash,
    salt,
    attempts: 0,
    lastSentAt,
    expiresAt,
    messageId: sendResult.id,
  }

  if (isMongoConnected()) {
    try {
      await Otp.findOneAndUpdate({ email }, record, { upsert: true, new: true })
    } catch (err) {
      console.warn('[ProtonAuth] MongoDB save failed, using in-memory store:', err.message)
      memoryOtps.set(email, record)
    }
  } else {
    memoryOtps.set(email, record)
  }

  return res.status(200).json({
    success: true,
    message: 'Verification code sent to your Proton email.',
    cooldownSeconds: 60,
    expiresInSeconds: 600,
    messageId: sendResult.id,
  })
})

/**
 * POST /api/auth/proton/verify-otp
 */
export const verifyOtp = asyncHandler(async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase()
  const code = (req.body?.code || '').trim()

  if (!email || !isValidProtonEmail(email)) {
    return res.status(400).json({
      success: false,
      error: 'invalid_email',
      message: 'Please provide a valid Proton email address.',
    })
  }

  if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    return res.status(400).json({
      success: false,
      error: 'invalid_code',
      message: 'Please provide a valid 6-digit verification code.',
    })
  }

  let otpRecord = null
  if (isMongoConnected()) {
    try {
      otpRecord = await Otp.findOne({ email })
    } catch (err) {
      otpRecord = memoryOtps.get(email) || null
    }
  } else {
    otpRecord = memoryOtps.get(email) || null
  }

  if (!otpRecord) {
    return res.status(400).json({
      success: false,
      error: 'code_not_found',
      message: 'No verification code found. Please request a new code.',
    })
  }

  const now = Date.now()
  const expiryTime = new Date(otpRecord.expiresAt).getTime()
  if (now > expiryTime) {
    try {
      await Otp.deleteOne({ email })
    } catch {
      memoryOtps.delete(email)
    }
    return res.status(400).json({
      success: false,
      error: 'code_expired',
      message: 'Verification code has expired. Please request a new one.',
    })
  }

  if (otpRecord.attempts >= MAX_VERIFY_ATTEMPTS) {
    try {
      await Otp.deleteOne({ email })
    } catch {
      memoryOtps.delete(email)
    }
    return res.status(400).json({
      success: false,
      error: 'too_many_attempts',
      message: 'Too many incorrect attempts. Please request a new verification code.',
    })
  }

  const candidateHash = hashOtp(code, otpRecord.salt)
  if (candidateHash !== otpRecord.codeHash) {
    otpRecord.attempts = (otpRecord.attempts || 0) + 1
    if (isMongoConnected()) {
      try {
        await Otp.updateOne({ email }, { $set: { attempts: otpRecord.attempts } })
      } catch {
        if (memoryOtps.has(email)) memoryOtps.get(email).attempts = otpRecord.attempts
      }
    } else {
      if (memoryOtps.has(email)) memoryOtps.get(email).attempts = otpRecord.attempts
    }
    const remainingAttempts = Math.max(0, MAX_VERIFY_ATTEMPTS - otpRecord.attempts)
    return res.status(400).json({
      success: false,
      error: 'incorrect_code',
      message: `Incorrect code. ${remainingAttempts} attempts remaining.`,
      remainingAttempts,
    })
  }

  // Code verified successfully - remove OTP
  if (isMongoConnected()) {
    try {
      await Otp.deleteOne({ email })
    } catch {
      memoryOtps.delete(email)
    }
  } else {
    memoryOtps.delete(email)
  }

  // Create or retrieve user
  let user = null
  let isNewUser = false
  if (isMongoConnected()) {
    try {
      user = await User.findOne({ email })
    } catch {
      user = null
    }
  }

  const emailPrefix = email.split('@')[0].replace(/[^a-z0-9_]/g, '_').slice(0, 20)

  if (!user) {
    isNewUser = true
    let username = emailPrefix.length >= 3 ? emailPrefix : `user_${emailPrefix}`

    if (isMongoConnected()) {
      try {
        const existingUser = await User.findOne({ username })
        if (existingUser) {
          username = `${username.slice(0, 20)}_${crypto.randomBytes(3).toString('hex')}`
        }

        const randomPassword = crypto.randomBytes(32).toString('hex')
        user = await User.create({
          username,
          displayName: emailPrefix,
          email,
          password: randomPassword,
          authProvider: 'proton',
        })
      } catch (err) {
        console.warn('[ProtonAuth] User creation in MongoDB failed, using simulated user:', err.message)
      }
    }

    if (!user) {
      const mockId = new mongoose.Types.ObjectId().toString()
      user = {
        _id: mockId,
        id: mockId,
        username,
        displayName: emailPrefix,
        email,
        avatarUrl: '',
        role: 'user',
        isActive: true,
        authProvider: 'proton',
        save: async () => {},
      }
      memoryUsers.set(mockId, user)
    }
  } else {
    user.lastActiveAt = new Date()
    await user.save({ validateBeforeSave: false })
  }

  const token = signToken(user)
  res.cookie('token', token, COOKIE_OPTIONS)

  return res.status(200).json({
    success: true,
    token,
    isNewUser,
    user: {
      id: user._id.toString(),
      email: user.email,
      name: user.displayName || user.username,
      avatarUrl: user.avatarUrl || '',
      provider: 'proton',
    },
  })
})
