import jwt from "jsonwebtoken";
import crypto from "crypto";;

export function createAccessToken(user, JWT_SECRET) {
    return jwt.sign({id: user.id, login: user.login, nickname: user.nickname, email: user.email, isAdmin: user.isAdmin, isCheckedByAdmin: user.isCheckedByAdmin }, JWT_SECRET, {expiresIn: '15m'})
}

export function createRefreshToken() {
    return crypto.randomBytes(64).toString("hex");
}

export function sendTokens(res, accessToken, refreshToken) {
    res.cookie('accessToken', accessToken, {secure: true, domain: ".zed31rus.ru", path: "/", sameSite: 'None', maxAge: 15 * 60 * 1000})
    res.cookie('refreshToken', refreshToken, {httpOnly: true, secure: true, domain: ".zed31rus.ru", sameSite: 'None', path: "/", maxAge: 7 * 24 * 60 * 60 * 1000})
}