// import express from "express";
// import cookieParser from "cookie-parser";
// import axios from "axios";
// import jwt from "jsonwebtoken";
// import jwksClient from "jwks-rsa";
// import crypto from "crypto";
const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
    cors({
        origin: "*",
        credentials: false,
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);

const {
    PORT = 4000,
    APP_JWT_SECRET,
    APPLE_TEAM_ID,
    APPLE_KEY_ID,
    APPLE_PRIVATE_KEY,
    APPLE_WEB_CLIENT_ID,
    WEB_PUBLIC_ORIGIN,
    BACKEND_PUBLIC_ORIGIN,
} = require("./config.js");

if (!APP_JWT_SECRET) throw new Error("Missing APP_JWT_SECRET");
if (!APPLE_TEAM_ID || !APPLE_KEY_ID || !APPLE_PRIVATE_KEY) throw new Error("Missing Apple key env");
if (!APPLE_WEB_CLIENT_ID) throw new Error("Missing APPLE_WEB_CLIENT_ID (Services ID)");
if (!WEB_PUBLIC_ORIGIN) throw new Error("Missing WEB_PUBLIC_ORIGIN");
if (!BACKEND_PUBLIC_ORIGIN) throw new Error("Missing BACKEND_PUBLIC_ORIGIN");

// --- Apple JWKS (verify id_token) ---
const appleJwks = jwksClient({
    jwksUri: "https://appleid.apple.com/auth/keys",
    cache: true,
    cacheMaxEntries: 5,
    cacheMaxAge: 60 * 60 * 1000,
});

function getAppleSigningKey(header, cb) {
    appleJwks.getSigningKey(header.kid, (err, key) => {
        if (err) return cb(err);
        cb(null, key.getPublicKey());
    });
}

function makeClientSecret({ clientId }) {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 60 * 60 * 24 * 180; // 180 days

    return jwt.sign(
        {
            iss: APPLE_TEAM_ID,
            iat: now,
            exp,
            aud: "https://appleid.apple.com",
            sub: clientId,
        },
        APPLE_PRIVATE_KEY.replace(/\\n/g, "\n"),
        { algorithm: "ES256", keyid: APPLE_KEY_ID }
    );
}

async function exchangeCodeForTokens({ code, clientId }) {
    const clientSecret = makeClientSecret({ clientId });

    const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        client_secret: clientSecret,
    });

    const res = await axios.post("https://appleid.apple.com/auth/token", body, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    return res.data; // { id_token, access_token, refresh_token, ... }
}

function verifyIdToken({ idToken, expectedAud }) {
    return new Promise((resolve, reject) => {
        jwt.verify(
            idToken,
            getAppleSigningKey,
            {
                algorithms: ["RS256"],
                issuer: "https://appleid.apple.com",
                audience: expectedAud,
            },
            (err, decoded) => (err ? reject(err) : resolve(decoded))
        );
    });
}

// --- Demo "user upsert" ---
async function upsertUser({ appleSub, email }) {
    return { id: `user_${appleSub.slice(0, 8)}`, appleSub, email: email ?? null };
}

function issueAppTokens(user) {
    const accessToken = jwt.sign({ userId: user.id }, APP_JWT_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ userId: user.id, type: "refresh" }, APP_JWT_SECRET, { expiresIn: "30d" });
    return { accessToken, refreshToken };
}

// 

app.get("/", (req, res) => {
    return res.json({
        success: true,
        message: "Server is live",
    })
})
/**
 * STEP A: Start login (backend creates Apple authorize URL)
 * Frontend will just redirect user to /api/auth/apple/start
 */
app.get("/api/apple/auth/web", (req, res) => {
    try {
        console.log("/auth/apple/start");
        const nonce = crypto.randomBytes(16).toString("hex");
        const state = jwt.sign({ nonce }, APP_JWT_SECRET, { expiresIn: "10m" });

        // For response_mode=form_post, Apple posts to the backend callback.
        const redirectUri = `${BACKEND_PUBLIC_ORIGIN}/auth/apple/callback`;
        console.log("redirectUri:", redirectUri);

        const authorizeUrl =
            "https://appleid.apple.com/auth/authorize?" +
            new URLSearchParams({
                response_type: "code",
                response_mode: "form_post",
                client_id: APPLE_WEB_CLIENT_ID,   // Services ID
                redirect_uri: redirectUri,
                scope: "name email",
                state,
            }).toString();
        console.log("authorizeUrl:", authorizeUrl);
        // Return URL + state so frontend can store state and redirect
        res.json({ authorizeUrl, state });
    } catch (error) {
        console.log(error);
    }
});

/**
 * STEP B: Complete login (frontend callback page sends code+state here)
 * Backend exchanges code -> verifies id_token -> creates session.
 */

// pi/apple/auth/web/complete
app.post("/api/apple/auth/web/complete", async (req, res) => {
    try {
        const { code, state } = req.body;
        if (!code) return res.status(400).json({ message: "code is required" });
        if (!state) return res.status(400).json({ message: "state is required" });

        try {
            jwt.verify(state, APP_JWT_SECRET);
        } catch (e) {
            return res.status(401).json({ message: "Invalid state (CSRF check failed)" });
        }

        // Exchange code at Apple token endpoint
        const tokenData = await exchangeCodeForTokens({ code, clientId: APPLE_WEB_CLIENT_ID });
        if (!tokenData?.id_token) return res.status(401).json({ message: "Apple did not return id_token" });

        // Verify id_token
        const claims = await verifyIdToken({ idToken: tokenData.id_token, expectedAud: APPLE_WEB_CLIENT_ID });

        const appleSub = claims.sub;
        const email = claims.email; // may be missing later

        const user = await upsertUser({ appleSub, email });

        const { accessToken, refreshToken } = issueAppTokens(user);
        // With allow-all-origins, cookies won't work cross-origin.
        res.json({ user, accessToken, refreshToken });
    } catch (err) {
        console.log("err:", err);
        const msg =
            err?.response?.data?.error_description ||
            err?.response?.data?.error ||
            err?.message ||
            "Apple auth failed";
        res.status(401).json({ message: msg, err });
    }
});

/**
 * STEP B1 (form_post): Apple POSTs code+state to backend.
 * We redirect to the frontend callback with query params.
 */
app.post("/auth/apple/callback", (req, res) => {
    try {
        console.log("/auth/apple/callback");
        const { code, state } = req.body;
        if (!code || !state) {
            return res.status(400).send("Missing code/state from Apple");
        }
        const redirectTo = `${WEB_PUBLIC_ORIGIN}/auth/apple/callback?` +
            new URLSearchParams({ code, state }).toString();
        return res.redirect(redirectTo);
    } catch (err) {
        console.log("callback err:", err);
        return res.status(500).send("Callback error");
    }
});

const now = new Date();
const fmt = new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    weekday: "long",
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
});
console.log(fmt.format(now)); // e.g., "Feb 10, Tuesday, 2:20 PM"

app.listen(PORT, () => {
    console.log(fmt.format(now)); //
    console.log(`Backend running on http://localhost:${PORT}`);
});
