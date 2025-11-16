import jwt from "jsonwebtoken";
import crypto from "crypto";
import { netOptions } from "./App.js"

export function createAccessToken(user, JWT_SECRET) {
    return jwt.sign({id: user.id, login: user.login, nickname: user.nickname, isAdmin: user.isAdmin, isCheckedByAdmin: user.isCheckedByAdmin }, JWT_SECRET, {expiresIn: '15m'})
}

export function createRefreshToken() {
    return crypto.randomBytes(64).toString("hex");
}

export function sendTokens(res, type, accessToken, refreshToken) {
    const base = netOptions.base

    if (type == "access" || type == "BOTH") {
        res.cookie(netOptions.cookies.accessToken.name, accessToken, {
        ...base,
        httpOnly: netOptions.cookies.accessToken.httpOnly,
        maxAge: netOptions.cookies.accessToken.maxAge,
        });
    }

    if (type == "refresh" || type == "BOTH") {
        res.cookie(netOptions.cookies.refreshToken.name, refreshToken, {
        ...base,
        httpOnly: netOptions.cookies.refreshToken.httpOnly,
        maxAge: netOptions.cookies.refreshToken.maxAge,
        });
    }
}

export function clearTokens(res, type) {
    const base = netOptions.base
    if (type == "access" || type == "BOTH") {
        res.clearCookie(netOptions.cookies.accessToken.name, {...base, httpOnly: netOptions.cookies.accessToken.httpOnly})
    }
    if (type == "refresh" || type == "BOTH") {
        res.clearCookie(netOptions.cookies.refreshToken.name, {...base, httpOnly: netOptions.cookies.refreshToken.httpOnly})
    }
}