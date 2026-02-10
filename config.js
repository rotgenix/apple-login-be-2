require("dotenv").config();

// const {
//     PORT = 4000,
//     APP_JWT_SECRET,
//     APPLE_TEAM_ID,
//     APPLE_KEY_ID,
//     APPLE_PRIVATE_KEY, // store with \n in env, we'll fix it
//     APPLE_WEB_CLIENT_ID, // Service ID
// } = process.env;

// if (!APP_JWT_SECRET) throw new Error("Missing APP_JWT_SECRET");
// if (!APPLE_TEAM_ID || !APPLE_KEY_ID || !APPLE_PRIVATE_KEY || !APPLE_WEB_CLIENT_ID) {
//     throw new Error("Missing Apple env vars");
// }

module.exports = {
    PORT: process.env.PORT,
    APP_JWT_SECRET: process.env.APP_JWT_SECRET,
    APPLE_TEAM_ID: process.env.APPLE_TEAM_ID,
    APPLE_KEY_ID: process.env.APPLE_KEY_ID,
    APPLE_PRIVATE_KEY: process.env.APPLE_PRIVATE_KEY,
    APPLE_WEB_CLIENT_ID: process.env.APPLE_WEB_CLIENT_ID,
    WEB_PUBLIC_ORIGIN: process.env.WEB_PUBLIC_ORIGIN,
};
