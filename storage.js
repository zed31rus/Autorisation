import { __dirname } from "./App.js";
import multer from "multer";
import fs from "fs";
import path from "path";
import { AVATAR_UPLOAD_DIR } from "./App.js"

export const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync(AVATAR_UPLOAD_DIR)) {
            fs.mkdirSync(AVATAR_UPLOAD_DIR, {recursive: true})
        }
        cb(null, AVATAR_UPLOAD_DIR)
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname)
        cb(null, `${req.user.id}${req.user.login}${ext}`)
    }
})

export const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true)
    } else {
        cb(new Error('Invalid file type. Only images are allowed'), false)
    }
}

export const avatarUpload = multer({
    storage: storage,
    limits: {fileSize: 32 * 1024 * 1024 },
    fileFilter: fileFilter
})