import mongoose from 'mongoose'
import User from '../models/User.js'
import ApiError from '../utils/ApiError.js'
import asyncHandler from '../utils/asyncHandler.js'
import { verifyToken } from '../services/token.service.js'
import { memoryUsers } from '../controllers/protonAuth.controller.js'

/** Pulls the raw JWT out of the Authorization header or the auth cookie. */
function extractToken(req) {
  const header = req.headers.authorization || ''
  if (header.startsWith('Bearer ')) return header.slice(7).trim()
  return req.cookies?.token || null
}

/**
 * Verifies the token and attaches the user to `req.user`.
 * Use on routes that work for guests but behave better when signed in.
 */
export const optionalAuth = asyncHandler(async (req, _res, next) => {
  const token = extractToken(req)
  if (!token) return next()

  try {
    const payload = verifyToken(token)
    const user = await User.findById(payload.sub)
    if (user?.isActive) {
      req.user = user
      req.token = token
    }
  } catch {
    // Invalid/expired token on an optional route is simply ignored.
  }
  return next()
})

/** Hard gate: 401 when there is no valid session. */
export const requireAuth = asyncHandler(async (req, _res, next) => {
  const token = extractToken(req)
  if (!token) throw ApiError.unauthorized('You need to log in to do that')

  let payload
  try {
    payload = verifyToken(token)
  } catch (error) {
    throw ApiError.unauthorized(error.name === 'TokenExpiredError' ? 'Your session expired, please log in again' : 'Invalid session, please log in again')
  }

  let user = null
  if (mongoose.connection?.readyState === 1 && mongoose.isValidObjectId(payload.sub)) {
    try {
      user = await User.findById(payload.sub)
    } catch {
      user = null
    }
  }
  if (!user && memoryUsers?.has(payload.sub)) {
    user = memoryUsers.get(payload.sub)
  }

  if (!user) throw ApiError.unauthorized('Your account no longer exists')
  if (!user.isActive) throw ApiError.forbidden('This account has been deactivated')

  req.user = user
  req.token = token
  return next()
})

/** Admin gate. Must run after requireAuth. */
export const requireAdmin = (req, _res, next) => {
  if (!req.user) return next(ApiError.unauthorized())
  if (req.user.role !== 'admin') return next(ApiError.forbidden('Admins only'))
  return next()
}
