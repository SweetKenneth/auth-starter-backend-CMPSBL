import { Context } from "hono";
import { getCookie } from "hono/cookie";

import { governExistingSession } from "../CMPSBL/auth-governance";
import { orm } from "../db/index";
import { userTable, sessionTable } from "../db/schema";
import { sql } from "drizzle-orm";

import { isSessionExpired } from "../utils/sessionhelpers";
const governed = governExistingSession(c, sessionId);

if (!governed.verification.valid) {
  return c.json(
    {
      ok: false,
      loggedIn: false,
      error: "Session trust verification failed.",
      anomalies: governed.verification.anomalies,
    },
    401
  );
}

if (!governed.allowed) {
  return c.json(
    { ok: false, error: "Adaptive rate limit exceeded." },
    429
  );
}
export const checkauth = async (c: Context) => {
  const sessionId = getCookie(c, "sessionId");
  if (!sessionId) {
    return c.json(
      { ok: false, loggedIn: false, error: "No session cookie." },
      401
    );
  } else {
    try {
      const sessions = await orm
        .select()
        .from(sessionTable)
        .where(sql`${sessionTable.id} = ${sessionId}`)
        .all(); // Use .all() to get an array of results

      if (sessions.length === 0) {
        return c.json({ ok: false, error: "Invalid sessionId" }, 400);
      }
      console.log("sessions[0].expiresAt:", sessions[0].expiresAt);
      console.log("isSessionExpired:", isSessionExpired(sessions[0].expiresAt));
      if (isSessionExpired(sessions[0].expiresAt)) {
        return c.json(
          { ok: false, error: "Session expired, sign out and sign in." },
          400
        );
      }
      return c.json({
  ok: true,
  loggedIn: true,
  trustScore: governed.verification.trustScore,
});
    } catch (e) {
      if (e instanceof Error) {
        return c.json({ ok: false, error: e.message }, 400);
      }
      return c.json({ ok: false, error: "Uknown error." }, 500);
    }
  }
};
