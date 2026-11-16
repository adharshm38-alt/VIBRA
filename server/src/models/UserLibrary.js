import mongoose from 'mongoose'

const userLibrarySchema = new mongoose.Schema(
  {
    userId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    playlists: {
      type: Array,
      default: [],
    },
    likedSongs: {
      type: Array,
      default: [],
    },
    history: {
      type: Array,
      default: [],
    },
    preferences: {
      type: Object,
      default: {},
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  },
)

const UserLibrary = mongoose.model('UserLibrary', userLibrarySchema)

export default UserLibrary
