import express from "express";
import http from 'http';
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";
import cors from 'cors';
import dotenv from 'dotenv';
import { addRefreshToken, prisma, registerUser, removeRefreshToken } from "./db.js";
import bcrypt from "bcrypt";
import { createAccessToken, createRefreshToken, sendTokens } from "./tokenMaster.js";
import Joi from "joi";
import crypto from "crypto";
import jwt from "jsonwebtoken";

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

const corsOptions =  {origin:[
    "https://zed31rus.ru",
    "https://nodes.zed31rus.ru"
    ], credentials: true};

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
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000 )

    await addRefreshToken(user.id, refreshToken, expiresAt);

    sendTokens(res, accessToken, refreshToken)

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
    res.clearCookie("accessToken", {domain: ".zed31rus.ru", path: "/", sameSite: 'None'})
    res.clearCookie("refreshToken", {httpOnly: true, domain: ".zed31rus.ru", path: "/", sameSite: 'None'})
    return res.json({status: true, message: "Logged out"})
})

app.post("/refresh", async (req, res) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken) {
        return res.status(401).json({status: false, message: "No refresh token provided"})
    }

    try {
        const hashedToken = crypto.createHash("sha256").update(refreshToken).digest("hex");
        const token = await prisma.refreshToken.findFirst({
            where: {hashedToken, expiresAt: {gt: new Date()}},
            include: {user: true}
        });

        if (!token) {
            return res.status(401).json({status: false, message: "Invalid or expired refresh token"})
        }

        const accessToken = createAccessToken(token.user, process.env.JWT_SECRET);
        sendTokens(res, accessToken, refreshToken);

        return res.status(200).json({status: true, message: "Token successfully refreshed"})
    } catch (e) {
        console.error("Refresh token error:", e.message)
        return res.status(500).json({status: false, message: "Server error during token refresh"})
    }
})

//todo /changeAvatar, changeEmail

app.get("/me", (req, res) => {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({ status: false, message: "No token" })

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        return res.json({
            status: true,
            user: {
                id: payload.id,
                login: payload.login,
                nickname: payload.nickname,
                email: payload.email,
                isAdmin: payload.isAdmin,
                isCheckedByAdmin: payload.isCheckedByAdmin
            }
        });
    } catch(e) {
        console.log(e)
        return res.status(401).json({status: false, message: "Invalid token" })
    }
})

server.listen(PORT, (error) => {
    error ? console.log(error) : console.log(`OK, port: ${PORT}`);
});