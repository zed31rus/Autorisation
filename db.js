import { PrismaClient } from "./generated/prisma/index.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

export const prisma = new PrismaClient();

export async function registerUser(login, nickname, email, password) {
    try {
        const loginExists = await prisma.user.findFirst({ where: { login } });
        if (loginExists) return { status: false, type: "loginExists", message: "Login already exists", data: {} };

        const emailExists = await prisma.user.findFirst({ where: { email } });
        if (emailExists) return { status: false, type: "emailExists", message: "Email already exists", data: {} };

        const hashedPassword = await bcrypt.hash(password, Number(process.env.BCRYPT_SALT_ROUNDS));
        const user = await prisma.user.create({
            data: {
                login,
                nickname,
                email,
                password: hashedPassword
            },
            select: {
                id: true,
                login: true,
                nickname: true,
                email: true,
                isAdmin: true,
                isCheckedByAdmin: true,
            }
        });



        return { status: true, type: "success", message: "User registered successfully", data: user };

    } catch (e) {
        console.error("Register error:", e.message);
        return { status: false, type: "error", message: "Server error during registration", data: {} };
    }
}

export async function addRefreshToken(userId, token, expiresAt) {
    try {
        const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

        const newToken = await prisma.refreshToken.create({
            data: {
                hashedToken,
                expiresAt,
                user: { connect: { id: userId } }
            }
        });

        return { status: true, type: "success", message: "Refresh token added", data: newToken };

    } catch (e) {
        console.error("Add token error:", e.message);
        return { status: false, type: "error", message: "Failed to add refresh token", data: {} };
    }
}

export async function removeRefreshToken(token) {
    try {
        const  hashedToken = crypto.createHash("sha256").update(token).digest("hex");
        const rt = await prisma.refreshToken.findFirst({ where: { hashedToken: hashedToken } });

        if (!rt) return { status: false, type: "notFound", message: "Refresh token not found", data: {} };

        const deleted = await prisma.refreshToken.delete({ where: { id: rt.id } });

        return { status: true, type: "success", message: "Refresh token removed", data: deleted };

    } catch (e) {
        console.error("Remove token error:", e.message);
        return { status: false, type: "error", message: "Failed to remove refresh token", data: {} };
    }
}

export async function listUsers() {
    try {
        const users = await prisma.user.findMany({
            select: { id: true, login: true, email: true, isAdmin: true }
        });

        return { status: true, type: "success", message: "User list fetched", data: users };

    } catch (e) {
        console.error("List users error:", e.message);
        return { status: false, type: "error", message: "Failed to fetch users", data: [] };
    }
}
