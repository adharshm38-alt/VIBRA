import { Router } from 'express'
import * as userCloud from '../controllers/userCloud.controller.js'
import { requireAuth } from '../middleware/auth.js'

const router = Router()

// GET /api/user/profile
router.get('/profile', requireAuth, userCloud.getProfile)

// PUT /api/user/profile
router.put('/profile', requireAuth, userCloud.updateProfile)

// GET /api/user/library
router.get('/library', requireAuth, userCloud.getLibrary)

// POST /api/user/library/sync
router.post('/library/sync', requireAuth, userCloud.syncLibrary)

export default router
