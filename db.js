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
        await prisma.user.create({
            data: {
                login,
                nickname,
                email,
                password: hashedPassword
            },
        });

        return { status: true, type: "success", message: "User registered successfully", data: {}};

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

export async function patchUser(user, patchData) {
    try {
        const updateData = {}

        if (patchData.password) {
            updateData.password = await bcrypt.hash(patchData.password, Number(process.env.BCRYPT_SALT_ROUNDS));
        }

        if (patchData.nickname) {
            updateData.nickname = patchData.nickname;
        }

        if (patchData.email) {
            updateData.email = patchData.email;
        }

        if (patchData.avatar) {
            updateData.avatar = patchData.avatar;
        }

        if (Object.keys(updateData).length === 0) {
            return { status: true, type: "noChange", message: "No fields to update", data: user };
        }

        await prisma.user.update({
            where: {id: user.id},
            data: updateData
        })

        return { status: true, type: "success", message: "User updated successfully", data: {}};
    } catch(e) {
        console.error("Patch user error:", e.message)
        if (e.code === 'P2002') { 
             return { status: false, type: "duplicate", message: `The field already exists`, data: {} };
        }
        return {status: false, type: "error", message: "Failed to patch user", data: {}}
    }
}

export async function listUsers() {
    try {
        const users = await prisma.user.findMany({
            select: { id: true, login: true, email: true, isAdmin: true }
        });

        return { status: true, type: "success", message: "User list fetched", data: {users} };

    } catch (e) {
        console.error("List users error:", e.message);
        return { status: false, type: "error", message: "Failed to fetch users", data: [] };
    }
}

export async function cleanupExpiredRefreshTokens() {
    try {
        const result = await prisma.refreshToken.deleteMany({
            where: {
                expiresAt: { 
                    lt: new Date()
                }
            }
        });
        console.log(`Очистка Refresh Tokens завершена. Удалено записей: ${result.count}`);
    } catch (e) {
        console.error("Ошибка при удалении просроченных токенов:", e.message);
    }
}