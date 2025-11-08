import express from "express";
import http from 'http';
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";
import cors from 'cors';
import dotenv from 'dotenv';
import { addRefreshToken, prisma, registerUser, removeRefreshToken, patchUser } from "./db.js";
import bcrypt from "bcrypt";
import { createAccessToken, createRefreshToken, sendTokens, clearTokens } from "./tokenMaster.js";
import Joi, { optional } from "joi";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { initSchedule } from "./schedule.js";

dotenv.config()

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const server = http.createServer(app);
const PORT = 3003

const registerSchema = Joi.object({
    login: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    nickname: Joi.string().min(3).max(50).required()
})

const patchSchema = Joi.object({
    email: Joi.string().email().optional(),
    password: Joi.string().min(8).optional(),
    nickname: Joi.string().min(3).max(50).optional()
}).min(1).messages({
    'object.min': 'Request body must contain at least one field to update (email, password, or nickname).'
});

const allowedOrigins = [
  "https://zed31rus.ru",
  "https://nodes.zed31rus.ru",
  "https://api.zed31rus.ru",
];

export const netOptions = {
    base: {
        domain: ".zed31rus.ru",
        sameSite: "None",
        secure: true,
        path: "/",
    },

    cookies: {
        accessToken: {
            name: "accessToken",
            httpOnly: false,
            maxAge: 15 * 60 * 1000, // 15 минут
        },
        refreshToken: {
            name: "refreshToken",
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
        },
    },
};

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin) || origin.endsWith(".zed31rus.ru")) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};

app.use(express.json());
app.use(cors(corsOptions));
app.use(cookieParser());
app.set('trust proxy', 1);

app.post("/register", async (req, res) => {
    const {error} = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json({status:400, message: error.details[0].message})
        }
    try {

        const {login, email, password, nickname} = req.body;

        const result = await registerUser(login, nickname, email, password)

        if (result.status === false) {
            return res.status(400).json(result);
        }

        return res.status(201).json({
            status: true,
            message: "User registered successfully",
            user: { id: result.data.id, login: result.data.login, email: result.data.email }
        })

    } catch(e) {
        console.error("Registration error: ", e);
        return res.status(500).json({
            status: false,
            message: "Server error during registration"
        });
    }
});

app.post("/login", async(req, res) => {
    const {login, password} = req.body;

    if (!login || !password) {
        return res.status(400).json({status:false, message: "Missing login or password" })
    }

    const user = await prisma.user.findUnique({where: {login}});
    if (!user) {
        return res.status(401).json({status:false, message: "Invalid login or password" })
    }

    const passwordMatches = await bcrypt.compare(password, user.password)
    if (!passwordMatches) {
        return res.status(401).json({status: false, message: "Invalid login or password" })
    }

    const accessToken = createAccessToken(user, process.env.JWT_SECRET)
    const refreshToken = createRefreshToken()
    const expiresAt = new Date(Date.now() + netOptions.cookies.refreshToken.maxAge);

    await addRefreshToken(user.id, refreshToken, expiresAt);

    sendTokens(res, "BOTH", accessToken, refreshToken)

    return res.json({
        status: true,
        message: "Logged in successfully"
    })
})

app.post("/logout", async (req, res) => {
    const {refreshToken} = req.cookies;
    if (refreshToken) {
        await removeRefreshToken(refreshToken);
    }
    clearTokens(res, "BOTH")
    return res.json({status: true, message: "Logged out"})
})

app.use(verifyUser)

app.patch("/me", async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ status: false, message: "Authentication required"})
    }
    
    const {error, value: patchData} = patchSchema.validate(req.body);
    if (error) {
        return res.status(400).json({status: false, message:error.details[0].message })
    }

    const result = await patchUser(req.user, patchData);

    if (result.status === false) {
        if (result.type === "duplicate") {
            return res.status(409).json(result);
        }
        return res.status(500).json(result)
    }
    if (patchData.password) {
       
        const user = result.data;
        const newAccessToken = createAccessToken(user, process.env.JWT_SECRET);

        sendTokens(res, "access", newAccessToken)
    }

    return res.json({
        status: true,
        message: "User profile updated successfully",
        user: result.data
    });
})

app.get("/me", (req, res) => {
    const user = req.user;
    
    if (!user) {
         return res.status(401).json({ status: false, message: "Authentication required" });
    }
    
    try {
        return res.json({
            status: true,
            user: {
                id: user.id,
                login: user.login,
                nickname: user.nickname,
                email: user.email,
                isAdmin: user.isAdmin,
                isCheckedByAdmin: user.isCheckedByAdmin
            }
        });
    } catch(e) {
        console.log(e)
        return res.status(500).json({status: false, message: "Server error retrieving user data" })
    }
})

async function verifyUser(req, res, next) {
    const { accessToken, refreshToken } = req.cookies;

    if (!refreshToken) {
        clearTokens(res, "BOTH")
        return res.status(401).json({ status: false, message: "Authentication required (no refresh token)" });
    }

    let user = null;
    let accessValid = false;

    if (accessToken) {
        try {
            const payload = jwt.verify(accessToken, process.env.JWT_SECRET);
            user = await prisma.user.findUnique({ where: { login: payload.login } });
            if (user) {
                req.user = user;
                accessValid = true;
            }
        } catch (e) {
            console.log("Access Token expired or invalid.");
        }
    }

    if (!accessValid) {
        try {
            const hashedToken = crypto.createHash("sha256").update(refreshToken).digest("hex");
            const rtInDb = await prisma.refreshToken.findFirst({
                where: { hashedToken, expiresAt: { gt: new Date() } },
                include: { user: true }
            });

            if (!rtInDb) {
                clearTokens(res, "BOTH")
                return res.status(401).json({ status: false, message: "Invalid or expired session (refresh token failed)" });
            }

            user = rtInDb.user;
            const newAccessToken = createAccessToken(user, process.env.JWT_SECRET);
            sendTokens(res, "access", newAccessToken);
            req.user = user;
        } catch (e) {
            console.error("Refresh token validation error:", e.message);
            return res.status(500).json({ status: false, message: "Server error during session check" });
        }
    }
    
    if (req.user) {
        return next();
    } else {
        return res.status(401).json({ status: false, message: "User not found" });
    }
}

initSchedule()

server.listen(PORT, (error) => {
    error ? console.log(error) : console.log(`OK, port: ${PORT}`);
});