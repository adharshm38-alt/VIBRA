import mongoose from 'mongoose'
import User from '../models/User.js'
import UserLibrary from '../models/UserLibrary.js'
import asyncHandler from '../utils/asyncHandler.js'

function isMongoConnected() {
  return mongoose.connection?.readyState === 1
}

// In-memory fallback library store
const memoryLibraries = new Map()

/**
 * GET /api/user/profile
 */
export const getProfile = asyncHandler(async (req, res) => {
  const user = req.user
  return res.status(200).json({
    success: true,
    user: {
      id: user._id.toString(),
      email: user.email,
      name: user.displayName || user.username,
      avatarUrl: user.avatarUrl || '',
      provider: user.authProvider || 'proton',
    },
  })
})

/**
 * PUT /api/user/profile
 */
export const updateProfile = asyncHandler(async (req, res) => {
  const user = req.user
  const { name, avatarUrl } = req.body

  if (name !== undefined) {
    user.displayName = String(name).trim()
  }
  if (avatarUrl !== undefined) {
    user.avatarUrl = String(avatarUrl).trim()
  }

  user.lastActiveAt = new Date()
  await user.save({ validateBeforeSave: false })

  return res.status(200).json({
    success: true,
    user: {
      id: user._id.toString(),
      email: user.email,
      name: user.displayName || user.username,
      avatarUrl: user.avatarUrl || '',
      provider: user.authProvider || 'proton',
    },
  })
})

/**
 * GET /api/user/library
 */
export const getLibrary = asyncHandler(async (req, res) => {
  const userId = req.user._id.toString()
  let lib = null
  if (isMongoConnected()) {
    try {
      lib = await UserLibrary.findOne({ userId })
    } catch (err) {
      lib = memoryLibraries.get(userId) || null
    }
  } else {
    lib = memoryLibraries.get(userId) || null
  }

  const defaultLib = {
    userId,
    playlists: [],
    likedSongs: [],
    history: [],
    preferences: {},
  }

  return res.status(200).json({
    success: true,
    library: lib
      ? {
          userId: lib.userId,
          playlists: lib.playlists || [],
          likedSongs: lib.likedSongs || [],
          history: lib.history || [],
          preferences: lib.preferences || {},
          updatedAt: lib.updatedAt || Date.now(),
        }
      : defaultLib,
  })
})

/**
 * POST /api/user/library/sync
 */
export const syncLibrary = asyncHandler(async (req, res) => {
  const userId = req.user._id.toString()
  const body = req.body || {}

  let existing = null
  if (isMongoConnected()) {
    try {
      existing = await UserLibrary.findOne({ userId })
    } catch (err) {
      existing = memoryLibraries.get(userId) || null
    }
  } else {
    existing = memoryLibraries.get(userId) || null
  }

  const existingPlaylists = existing?.playlists || []
  const existingLikedSongs = existing?.likedSongs || []
  const existingHistory = existing?.history || []
  const existingPrefs = existing?.preferences || {}

  const updatedRecord = {
    userId,
    playlists: Array.isArray(body.playlists) ? body.playlists : existingPlaylists,
    likedSongs: Array.isArray(body.likedSongs) ? body.likedSongs : existingLikedSongs,
    history: Array.isArray(body.history) ? body.history : existingHistory,
    preferences: body.preferences && typeof body.preferences === 'object' ? body.preferences : existingPrefs,
    updatedAt: new Date(),
  }

  if (isMongoConnected()) {
    try {
      await UserLibrary.findOneAndUpdate({ userId }, updatedRecord, { upsert: true, new: true })
    } catch (err) {
      console.warn('[UserCloud] MongoDB library sync failed, saving in memory:', err.message)
      memoryLibraries.set(userId, updatedRecord)
    }
  } else {
    memoryLibraries.set(userId, updatedRecord)
  }

  return res.status(200).json({
    success: true,
    library: updatedRecord,
  })
})
