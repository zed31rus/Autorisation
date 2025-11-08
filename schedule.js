import cron from "node-cron";
import { cleanupExpiredRefreshTokens } from "./db.js"

export async function initSchedule() {
    cron.schedule('0 0 * * *', async () => {
        cleanupExpiredRefreshTokens()
    }, {
        scheduled: true,
        timezone: "Europe/Moscow"
    });
}