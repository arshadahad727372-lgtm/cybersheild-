import { Fragment, createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  BrowserRouter, Routes, Route, Navigate, NavLink, Link, Outlet,
  useNavigate, useLocation, useOutletContext, useInRouterContext,
} from "react-router-dom";
import {
  registerUser, loginUser, getCurrentUser,
  getDashboardData, getSecurityEvents, getSecurityAlerts,
} from "./api";
import "./App.css";

/* ================================ CONSTANTS ================================ */
/* Only UI constants live here. No security data is hardcoded anywhere. */

const TOKEN_KEY = "token";
const PAGE_SIZE = 10;
const EMPTY = [];
const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES = ["open", "investigating", "resolved"];
const RANGES = { today: "Today", week: "7 Days", month: "30 Days" };

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: "⌂" },
  { to: "/threats", label: "Threat Monitoring", icon: "◈" },
  { to: "/security-events", label: "Security Events", icon: "◉" },
  { to: "/analytics", label: "Analytics", icon: "▦" },
  { to: "/profile", label: "Profile", icon: "☺" },
  { to: "/settings", label: "Settings", icon: "⚙" },
];

const FEATURES = [
  { icon: "◎", title: "Threat Detection", text: "Rule-based checks flag risky behavior as it is recorded." },
  { icon: "⚑", title: "Suspicious Activity Monitoring", text: "Surface unusual sign-ins and repeated authentication failures." },
  { icon: "▣", title: "Secure Authentication", text: "Hashed passwords and signed tokens protect every account." },
  { icon: "▤", title: "Security Event Logging", text: "Important actions are recorded with time, IP address and severity." },
  { icon: "◈", title: "Real-Time Security Insights", text: "Dashboards turn recorded events into information you can act on." },
  { icon: "◆", title: "Account Protection", text: "Role-based access keeps sensitive areas restricted." },
];

const STEPS = [
  ["01", "Detect", "Security-relevant activity is captured as it happens."],
  ["02", "Analyze", "Each event is classified by type and severity."],
  ["03", "Alert", "Items that need attention are surfaced for review."],
  ["04", "Protect", "Review, investigate and resolve from one place."],
];

const MONITORED = ["Sign-in activity", "Failed authentication", "Account status", "Administrator actions", "Session security"];

// Decorative nodes for the landing illustration (labels only, no data).
const NODES = [
  { x: 360, y: 180, l: "Sign-ins" },
  { x: 285, y: 280, l: "Events" },
  { x: 135, y: 280, l: "Alerts" },
  { x: 60, y: 180, l: "Accounts" },
  { x: 135, y: 80, l: "Admin actions" },
  { x: 285, y: 80, l: "Sessions" },
];

const SEV_COLOR = { critical: "var(--red)", high: "var(--orange)", medium: "var(--amber)", low: "var(--green)" };
const STATUS_COLOR = { open: "var(--red)", investigating: "var(--amber)", resolved: "var(--green)" };
const STRENGTH = [null, { l: "Weak", c: "#ef4444" }, { l: "Fair", c: "#f97316" }, { l: "Good", c: "#f59e0b" }, { l: "Strong", c: "#22c55e" }];

// A null title means "Unable to load <what>".
const ERROR_COPY = {
  network: ["Can't reach the server", "Check that the CyberShield backend is running at http://localhost:5000 and try again."],
  forbidden: ["Access restricted", "Your account doesn't have permission to view this data. Some security data is limited to administrator accounts."],
  unavailable: [null, "The server didn't return the data in the expected format, or this endpoint isn't available yet."],
  unauthorized: ["Session expired", "Please sign in again."],
  server: [null, "The server couldn't complete this request. Please try again."],
};

/* ================================= HELPERS ================================= */

const low = (v, d = "") => (typeof v === "string" && v ? v.toLowerCase() : d);
const label = (s) => (s ? s.replace(/_/g, " ") : "—");
const fmt = (n) => (n === null || n === undefined ? "--" : Number(n).toLocaleString());
const ms = (t) => { const v = Date.parse(t); return Number.isNaN(v) ? 0 : v; };
const isOpen = (e) => e.status !== "resolved";
const newest = (a, b) => ms(b.time) - ms(a.time);
const toNum = (v) =>
  v !== undefined && v !== null && v !== "" && typeof v !== "boolean" && Number.isFinite(Number(v)) ? Number(v) : null;

const fmtDate = (t) => {
  const d = t ? new Date(t) : null;
  if (!d || Number.isNaN(d.getTime())) return null;
  return {
    date: d.toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" }),
    time: d.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" }),
  };
};

const initials = (u) =>
  (u.name || u.email || "U").split(" ").filter(Boolean).map((p) => p[0]).slice(0, 2).join("").toUpperCase();

const tokenExpiry = (t) => {
  try {
    const p = JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return p.exp ? new Date(p.exp * 1000).toLocaleString() : "Not set";
  } catch {
    return "Unknown";
  }
};

const strengthOf = (p) => {
  let s = 0;
  if (p.length >= 8) s++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
  if (/\d/.test(p)) s++;
  if (/[^A-Za-z0-9]/.test(p)) s++;
  return p ? Math.max(s, 1) : 0;
};

// api.js throws Error(message) only, so errors are classified from the message.
// Raw messages are never shown to the user (except auth form messages from the API).
const classify = (err) => {
  if (err && err.kind) return err.kind;
  const m = String((err && err.message) || "").toLowerCase();
  if (/failed to fetch|networkerror|network request|load failed/.test(m)) return "network";
  if (/unexpected token|not valid json|unexpected end of json|<!doctype/.test(m)) return "unavailable";
  if (/not authorized|unauthorized|jwt|token|expired|user not found/.test(m)) return "unauthorized";
  if (/forbidden|deactivated|permission/.test(m)) return "forbidden";
  if (/not found|cannot (get|post)/.test(m)) return "unavailable";
  return "server";
};

/* --------------------- response normalizers (real shapes) --------------------- */
/*   getCurrentUser    -> { data: { user } }
     loginUser         -> { data: { token, user } }
     getDashboardData  -> { data: { stats, recentEvents, alerts } }
     getSecurityEvents -> { data: { events, pagination? } }
     getSecurityAlerts -> { data: { alerts } }                                    */

const unexpected = () => {
  const e = new Error("Unexpected response shape");
  e.kind = "unavailable";
  throw e;
};

const tally = (items) => {
  const out = { critical: 0, high: 0, medium: 0, low: 0 };
  items.forEach((e) => { if (Object.prototype.hasOwnProperty.call(out, e.severity)) out[e.severity] += 1; });
  return out;
};

const normalizeEvent = (e, i) => {
  const o = e && typeof e === "object" ? e : {};
  const user = o.user && typeof o.user === "object" ? o.user : null;
  const meta = o.metadata && typeof o.metadata === "object" && Object.keys(o.metadata).length ? o.metadata : null;
  return {
    id: String(o._id ?? o.id ?? `row-${i}`),
    type: low(o.type),
    severity: low(o.severity),
    status: low(o.status),
    ip: o.ipAddress ?? null,
    email: o.email ?? (user && user.email) ?? null,
    userName: (user && user.name) ?? null,
    userRole: (user && user.role) ?? null,
    userAgent: o.userAgent ?? null,
    message: o.message ?? "",
    time: o.createdAt ?? null,
    metadata: meta,
  };
};

const listFrom = (res, key) => {
  const arr = res && res.data && res.data[key];
  if (!Array.isArray(arr)) unexpected();
  return arr.map(normalizeEvent);
};

const normalizeEventsResponse = (res) => {
  const items = listFrom(res, "events");
  const total = toNum(res.data.pagination && res.data.pagination.total);
  return { items, total, complete: total !== null && items.length >= total };
};

const normalizeAlertsResponse = (res) => ({ items: listFrom(res, "alerts") });

const STAT_KEYS = [
  "totalEvents", "openEvents", "investigatingEvents", "resolvedEvents",
  "criticalEvents", "highEvents", "failedLogins", "successfulLogins",
];

const normalizeDashboard = (res) => {
  const d = res && res.data;
  if (!d || typeof d !== "object" || !d.stats || typeof d.stats !== "object") unexpected();
  const stats = {};
  STAT_KEYS.forEach((k) => { stats[k] = toNum(d.stats[k]); });
  return {
    stats,
    recentEvents: Array.isArray(d.recentEvents) ? d.recentEvents.map(normalizeEvent) : [],
  };
};

const extractUser = (res) => {
  const u = res && res.data && res.data.user;
  if (!u || !u.email) unexpected();
  return u;
};

/* ------------------------- derived security values ------------------------- */

function computeStatus(events, alerts) {
  const src = alerts.status === "ready" ? alerts.data.items : events.status === "ready" ? events.data.items : null;
  if (!src) {
    const waiting = [events, alerts].some((r) => r.status === "loading");
    return waiting
      ? { level: "loading", label: "Checking", title: "Checking security status", text: "Loading the latest security data." }
      : { level: "unknown", label: "Unknown", title: "Security Status: Unavailable", text: "Status can't be determined because security data is unavailable." };
  }
  const urgent = src.filter((e) => isOpen(e) && (e.severity === "critical" || e.severity === "high")).length;
  if (urgent > 0) {
    return {
      level: "attention", label: "Attention", title: "Security Status: Attention Required",
      text: `${urgent} active high or critical ${urgent === 1 ? "item needs" : "items need"} review.`,
    };
  }
  return { level: "normal", label: "Normal", title: "Security Status: Normal", text: "No active high or critical alerts were found in the data loaded." };
}

function buildSeries(items, range) {
  const DAY = 86400000;
  const n = new Date();
  const today = new Date(n.getFullYear(), n.getMonth(), n.getDate()).getTime();
  const cfg = {
    today: { start: today, size: DAY / 6, n: 6 },
    week: { start: today - 6 * DAY, size: DAY, n: 7 },
    month: { start: today - 29 * DAY, size: 3 * DAY, n: 10 },
  }[range];
  const end = cfg.start + cfg.size * cfg.n;
  const rows = Array.from({ length: cfg.n }, (_, i) => {
    const d = new Date(cfg.start + i * cfg.size);
    const l = range === "today"
      ? `${String(d.getHours()).padStart(2, "0")}h`
      : range === "week"
        ? d.toLocaleDateString("en-US", { weekday: "short" })
        : d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
    return { l, all: 0, failed: 0, success: 0, suspicious: 0 };
  });
  const inRange = [];
  items.forEach((e) => {
    const t = ms(e.time);
    if (!t || t < cfg.start || t >= end) return;
    const row = rows[Math.min(cfg.n - 1, Math.floor((t - cfg.start) / cfg.size))];
    row.all += 1;
    if (e.type === "login_failed") row.failed += 1;
    if (e.type === "login_success") row.success += 1;
    if (e.type === "suspicious_activity") row.suspicious += 1;
    inRange.push(e);
  });
  return { rows, inRange };
}

/* ================================== AUTH ================================== */

const AuthCtx = createContext(null);
const useAuth = () => useContext(AuthCtx);

function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY));
  const [user, setUser] = useState(null);
  const [status, setStatus] = useState(token ? "loading" : "anon"); // loading | ready | anon | error
  const [authError, setAuthError] = useState(null);
  const [attempt, setAttempt] = useState(0);
  const userRef = useRef(null);

  const applyUser = useCallback((u) => { userRef.current = u; setUser(u); }, []);

  const signOut = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    applyUser(null);
    setStatus("anon");
  }, [applyUser]);

  // Login response: { data: { token, user } }. The user is shown immediately;
  // the effect below still re-verifies the token with getCurrentUser.
  const signIn = useCallback((t, u) => {
    localStorage.setItem(TOKEN_KEY, t);
    setToken(t);
    if (u && u.email) {
      applyUser(u);
      setStatus("ready");
    } else {
      applyUser(null);
      setStatus("loading");
    }
  }, [applyUser]);

  const retry = useCallback(() => setAttempt((a) => a + 1), []);

  // Restore the session on startup (and after login) with getCurrentUser(token).
  useEffect(() => {
    if (!token) {
      applyUser(null);
      setStatus("anon");
      return undefined;
    }
    let cancelled = false;
    if (!userRef.current) setStatus("loading");
    getCurrentUser(token)
      .then((res) => {
        if (cancelled) return;
        applyUser(extractUser(res));
        setAuthError(null);
        setStatus("ready");
      })
      .catch((err) => {
        if (cancelled) return;
        const kind = classify(err);
        if (kind === "network" || kind === "server" || kind === "unavailable") {
          setAuthError(kind);
          setStatus("error");
        } else {
          // Invalid or expired token: clear it and send the user to /login.
          signOut();
        }
      });
    return () => { cancelled = true; };
  }, [token, attempt, signOut, applyUser]);

  const value = useMemo(
    () => ({ token, user, status, authError, signIn, signOut, retry }),
    [token, user, status, authError, signIn, signOut, retry]
  );
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

/* ============================ SECURITY DATA STORE ============================ */
/* Calls the real API once for all protected pages. Failures stay failures:
   they are never replaced with substitute data. The store is unmounted on
   logout, which clears all dashboard, event and alert state. */

const SecurityDataCtx = createContext(null);
const useSecurityData = () => useContext(SecurityDataCtx);
const LOADING = { status: "loading", data: null, error: null };

function SecurityDataProvider({ children }) {
  const { token, signOut } = useAuth();

  const [state, setState] = useState({
    dashboard: LOADING,
    events: LOADING,
    alerts: LOADING,
  });

  const [tick, setTick] = useState(0);

  useEffect(() => {
    /*
      Do not request protected security APIs without a token.

      When the user logs out, immediately clear the old security
      data so dashboard/events/alerts cannot remain visible.
    */
    if (!token) {
      setState({
        dashboard: {
          status: "error",
          data: null,
          error: "unauthorized",
        },
        events: {
          status: "error",
          data: null,
          error: "unauthorized",
        },
        alerts: {
          status: "error",
          data: null,
          error: "unauthorized",
        },
      });

      return undefined;
    }

    let cancelled = false;

    /*
      Every refresh starts from a clean loading state.
    */
    setState({
      dashboard: LOADING,
      events: LOADING,
      alerts: LOADING,
    });

    /*
      Run one protected API request and normalize its response.
      Failed requests remain failed — no fake/demo data is inserted.
    */
    const run = (key, request, normalize) => {
      Promise.resolve()
        .then(request)
        .then((res) => {
          if (cancelled) return;

          const data = normalize(res);

          if (cancelled) return;

          setState((current) => ({
            ...current,
            [key]: {
              status: "ready",
              data,
              error: null,
            },
          }));
        })
        .catch((err) => {
          if (cancelled) return;

          setState((current) => ({
            ...current,
            [key]: {
              status: "error",
              data: null,
              error: classify(err),
            },
          }));
        });
    };

    /*
      REAL BACKEND DATA ONLY
    */
    run(
      "dashboard",
      () => getDashboardData(token),
      normalizeDashboard
    );

    run(
      "events",
      () => getSecurityEvents(token),
      normalizeEventsResponse
    );

    run(
      "alerts",
      () => getSecurityAlerts(token),
      normalizeAlertsResponse
    );

    /*
      Prevent state updates after unmount/token change.
    */
    return () => {
      cancelled = true;
    };
  }, [token, tick]);

  /*
    If any protected API says the JWT is unauthorized,
    clear the session.
  */
  const unauthorized = Object.values(state).some(
    (resource) => resource.error === "unauthorized"
  );

  useEffect(() => {
    if (unauthorized && token) {
      signOut();
    }
  }, [unauthorized, token, signOut]);

  /*
    Force all three security API requests to run again.
  */
  const reload = useCallback(() => {
    setTick((current) => current + 1);
  }, []);

  const value = useMemo(
    () => ({
      ...state,
      reload,
    }),
    [state, reload]
  );

  return (
    <SecurityDataCtx.Provider value={value}>
      {children}
    </SecurityDataCtx.Provider>
  );
}

/* ============================ REUSABLE COMPONENTS ============================ */

const Logo = () => (
  <Link to="/" className="brand-link">
    <span className="logo-icon" aria-hidden="true">◈</span>
    <span className="logo-text">Cyber<strong>Shield</strong></span>
  </Link>
);

const Skeleton = ({ w = "100%", h = 18 }) => <div className="skeleton" style={{ width: w, height: h }} aria-hidden="true" />;

const SeverityBadge = ({ level }) => <span className={`badge badge-${level || "unknown"}`}>{level || "unknown"}</span>;

const StatusBadge = ({ status }) =>
  status ? <span className={`status-${status}`}>{status}</span> : <span className="mono">—</span>;

function Timestamp({ t }) {
  const f = fmtDate(t);
  return f ? <span className="ts">{f.date}<small>{f.time}</small></span> : <span>—</span>;
}

function LoadingState({ label: text = "Loading...", full, compact }) {
  return (
    <div className={`state ${full ? "full" : ""} ${compact ? "compact" : ""}`} role="status" aria-live="polite">
      <span className="spinner" />
      <p>{text}</p>
    </div>
  );
}

function EmptyState({ title, text }) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true">◌</span>
      <h3>{title}</h3>
      {text && <p>{text}</p>}
    </div>
  );
}

function ErrorState({ kind = "server", label: what, onRetry, compact, full }) {
  const [title, text] = ERROR_COPY[kind] || ERROR_COPY.server;
  return (
    <div className={`state state-error ${compact ? "compact" : ""} ${full ? "full" : ""}`} role="alert">
      <span className="state-icon" aria-hidden="true">!</span>
      <h3>{title || `Unable to load ${what || "security data"}.`}</h3>
      <p>{text}</p>
      {onRetry && <button type="button" className="btn btn-ghost" onClick={onRetry}>Try again</button>}
    </div>
  );
}

// Renders an error, a skeleton, or the data. Never substitutes other data.
function Async({ res, onRetry, label: what, skeleton, children }) {
  if (res.status === "error") return <ErrorState kind={res.error} label={what} onRetry={onRetry} compact />;
  if (res.status !== "ready") return skeleton || <LoadingState compact />;
  return children(res.data);
}

function StatCard({ label: name, value, note, tone = "info", icon }) {
  return (
    <article className={`stat-card stat-${tone}`}>
      <div className="stat-card-header"><span className="stat-icon" aria-hidden="true">{icon}</span></div>
      <p className="stat-value">{value}</p>
      <h3 className="stat-label">{name}</h3>
      <p className="stat-note">{note}</p>
    </article>
  );
}

const SkeletonCards = ({ count = 4 }) => (
  <section className="stats-grid" aria-label="Loading statistics">
    {Array.from({ length: count }).map((_, i) => (
      <article className="stat-card" key={i}>
        <Skeleton w="40px" h={40} /><div style={{ height: 16 }} /><Skeleton w="55%" h={30} /><div style={{ height: 10 }} /><Skeleton w="70%" />
      </article>
    ))}
  </section>
);

const AlertSkeletons = () => (
  <ul className="alert-list" aria-hidden="true">
    {[0, 1, 2].map((i) => <li className="alert-item" key={i}><div style={{ flex: 1, display: "grid", gap: 10 }}><Skeleton w="50%" /><Skeleton /><Skeleton w="30%" /></div></li>)}
  </ul>
);

function SecurityStatus({ status }) {
  return (
    <section className={`card sec-status sec-${status.level}`}>
      <span className="sec-shield" aria-hidden="true">◈</span>
      <div>
        <h2 className="card-title">{status.title}</h2>
        <p className="card-subtitle">{status.text}</p>
      </div>
      <span className={`protected-badge pb-${status.level}`}>
        <span className={`status-dot dot-${status.level}`} aria-hidden="true" />{status.label}
      </span>
    </section>
  );
}

function EventTable({ events, loading, onSelect }) {
  const heads = ["Event", "Type", "Severity", "IP Address", "Status", "Timestamp"];
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead><tr>{heads.map((h) => <th key={h} scope="col">{h}</th>)}</tr></thead>
        <tbody>
          {loading
            ? Array.from({ length: 5 }).map((_, i) => <tr key={i}><td colSpan={6}><Skeleton /></td></tr>)
            : events.map((e) => (
              <tr key={e.id}>
                <td>
                  {onSelect
                    ? <button type="button" className="row-link" onClick={() => onSelect(e)}>{e.message || label(e.type)}</button>
                    : <strong>{e.message || label(e.type)}</strong>}
                  <div className="mono">{e.email || e.id.slice(-8)}</div>
                </td>
                <td className="cap">{label(e.type)}</td>
                <td><SeverityBadge level={e.severity} /></td>
                <td className="mono">{e.ip || "—"}</td>
                <td><StatusBadge status={e.status} /></td>
                <td><Timestamp t={e.time} /></td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}

function AlertCard({ alert }) {
  return (
    <li className={`alert-item alert-${alert.severity || "unknown"}`}>
      <div className="alert-indicator" aria-hidden="true" />
      <div className="alert-body">
        <div className="alert-top">
          <h3 className="alert-title">{alert.message || label(alert.type) || "Security alert"}</h3>
          <SeverityBadge level={alert.severity} />
        </div>
        <div className="alert-meta">
          <StatusBadge status={alert.status} />
          {alert.type && <span className="alert-source cap">{label(alert.type)}</span>}
          {alert.ip && <span className="mono">{alert.ip}</span>}
          <Timestamp t={alert.time} />
        </div>
      </div>
    </li>
  );
}

const SearchBar = ({ value, onChange, placeholder, label: aria }) => (
  <div className="search-box">
    <span className="search-icon" aria-hidden="true">⌕</span>
    <input type="search" className="search-input" placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} aria-label={aria} />
  </div>
);

function NotificationPanel({ alerts, onClose }) {
  const open = alerts.status === "ready" ? alerts.data.items.filter(isOpen).slice(0, 5) : [];
  return (
    <div className="notification-panel" role="dialog" aria-label="Notifications">
      <div className="notification-header">
        <h3>Active alerts</h3>
        <Link to="/threats" className="link-button" onClick={onClose}>View all</Link>
      </div>
      {alerts.status === "ready" && open.length > 0 ? (
        <ul className="notification-list">
          {open.map((a) => (
            <li key={a.id} className="notification-item notification-unread">
              <p className="notification-title">{a.message || label(a.type)}</p>
              <span className="notification-time"><SeverityBadge level={a.severity} /> &nbsp;<Timestamp t={a.time} /></span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="notification-list">
          {alerts.status === "loading" && <LoadingState compact />}
          {alerts.status === "error" && <ErrorState kind={alerts.error} label="security alerts" compact />}
          {alerts.status === "ready" && <EmptyState title="No active security alerts." />}
        </div>
      )}
    </div>
  );
}

const PageHeader = ({ title, subtitle, children }) => (
  <div className="page-header">
    <div>
      <h1 className="page-title">{title}</h1>
      <p className="page-subtitle">{subtitle}</p>
    </div>
    {children}
  </div>
);

function PasswordField({ id, label: text, value, onChange, onBlur, error, autoComplete }) {
  const [show, setShow] = useState(false);
  return (
    <div className="field">
      <label htmlFor={id}>{text}</label>
      <div className="pw-wrap">
        <input id={id} type={show ? "text" : "password"} value={value} onChange={onChange} onBlur={onBlur} autoComplete={autoComplete} placeholder="••••••••" />
        <button type="button" className="pw-toggle" onClick={() => setShow((s) => !s)} aria-label={show ? "Hide password" : "Show password"}>
          {show ? "Hide" : "Show"}
        </button>
      </div>
      {error && <span className="field-err">{error}</span>}
    </div>
  );
}

function Bars({ data, series }) {
  const max = Math.max(...data.flatMap((d) => series.map(([k]) => d[k])), 1);
  return (
    <div className="bars" role="img" aria-label="Bar chart">
      {data.map((d) => (
        <div className="bar-col" key={d.l}>
          <div className="bar-stack">
            {series.map(([k, cls]) => (
              <span key={k} className={`bar ${cls}`} style={{ height: `${(d[k] / max) * 100}%` }} title={`${d.l}: ${d[k]}`} />
            ))}
          </div>
          <span className="bar-label">{d.l}</span>
        </div>
      ))}
    </div>
  );
}

// rows: [{ key, badge, value (number or null), color }]. A null value shows "--".
function Meters({ rows, wide }) {
  const max = Math.max(...rows.map((r) => r.value || 0), 1);
  return (
    <div>
      {rows.map((r) => (
        <div className={`meter-row ${wide ? "wide" : ""}`} key={r.key}>
          {r.badge}
          <div className="progress-track"><div className="progress-fill" style={{ width: `${((r.value || 0) / max) * 100}%`, background: r.color }} /></div>
          <b>{fmt(r.value)}</b>
        </div>
      ))}
    </div>
  );
}

const severityRows = (counts) =>
  SEVERITIES.map((s) => ({ key: s, badge: <SeverityBadge level={s} />, value: counts[s], color: SEV_COLOR[s] }));

const statusRows = (counts) =>
  STATUSES.map((s) => ({ key: s, badge: <StatusBadge status={s} />, value: counts[s], color: STATUS_COLOR[s] }));

function Pager({ page, pages, onPage }) {
  if (pages <= 1) return null;
  return (
    <nav className="pager" aria-label="Pagination">
      <button type="button" className="btn btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
      <span>Page {page} of {pages}</span>
      <button type="button" className="btn btn-ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </nav>
  );
}

function EventDrawer({ event, onClose }) {
  useEffect(() => {
    const esc = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", esc);
    return () => document.removeEventListener("keydown", esc);
  }, [onClose]);
  const f = fmtDate(event.time);
  const rows = [
    ["Event ID", event.id], ["Type", label(event.type)], ["Severity", event.severity || "—"], ["Status", event.status || "—"],
    ["Timestamp", f ? `${f.date}, ${f.time}` : "—"], ["IP address", event.ip || "—"], ["Email", event.email || "—"],
    ["User", event.userName ? `${event.userName}${event.userRole ? ` (${event.userRole})` : ""}` : "—"],
    ["User agent", event.userAgent || "—"],
  ];
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Event details">
        <div className="card-header">
          <div><h2 className="card-title">Event details</h2><p className="card-subtitle">{event.message || label(event.type)}</p></div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close details">✕</button>
        </div>
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}><SeverityBadge level={event.severity} /><StatusBadge status={event.status} /></div>
        <dl className="kv one">
          {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className={k === "Type" || k === "Severity" || k === "Status" ? "cap" : ""}>{v}</dd></div>)}
        </dl>
        {event.metadata && (
          <>
            <h3 className="drawer-sub">Metadata</h3>
            <pre className="code">{JSON.stringify(event.metadata, null, 2)}</pre>
          </>
        )}
      </aside>
    </>
  );
}

/* ================================== LAYOUT ================================== */

function Sidebar({ open, onClose, onLogout, user }) {
  return (
    <aside className={`sidebar ${open ? "sidebar-open" : ""}`}>
      <div className="sidebar-logo">
        <Logo />
        <button type="button" className="sidebar-close" onClick={onClose} aria-label="Close menu">✕</button>
      </div>
      <nav className="sidebar-nav" aria-label="Main navigation">
        <ul>
          {NAV.map((n) => (
            <li key={n.to}>
              <NavLink to={n.to} className={({ isActive }) => `nav-item ${isActive ? "nav-item-active" : ""}`}>
                <span className="nav-icon" aria-hidden="true">{n.icon}</span>
                <span className="nav-label">{n.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="sidebar-bottom">
        <div className="sidebar-user">
          <span className="user-avatar" aria-hidden="true">{initials(user)}</span>
          <div><p className="user-name">{user.name || "User"}</p><p className="user-role">{user.email}</p></div>
        </div>
        <button type="button" className="nav-item" onClick={onLogout}>
          <span className="nav-icon" aria-hidden="true">⏻</span>
          <span className="nav-label">Logout</span>
        </button>
      </div>
    </aside>
  );
}

function Navbar({ user, query, setQuery, onMenu, status, alerts, panel, setPanel, onSearch }) {
  const wrapRef = useRef(null);
  useEffect(() => {
    if (!panel) return undefined;
    const outside = (e) => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setPanel(false); };
    const esc = (e) => { if (e.key === "Escape") setPanel(false); };
    document.addEventListener("mousedown", outside);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("keydown", esc);
    };
  }, [panel, setPanel]);

  const count = alerts.status === "ready" ? alerts.data.items.filter(isOpen).length : 0;
  return (
    <header className="topbar">
      <button type="button" className="menu-button" onClick={onMenu} aria-label="Open menu">☰</button>
      <form className="topbar-search" role="search" onSubmit={onSearch}>
        <SearchBar value={query} onChange={setQuery} placeholder="Search security events..." label="Search security events" />
      </form>
      <div className="topbar-actions">
        <div className={`security-status ss-${status.level}`}>
          <span className={`status-dot dot-${status.level}`} aria-hidden="true" />
          <span className="security-status-text">{status.label}</span>
        </div>
        <div className="notification-wrapper" ref={wrapRef}>
          <button type="button" className="icon-button" onClick={() => setPanel((p) => !p)} aria-label="Toggle notifications" aria-expanded={panel}>
            ♢{count > 0 && <span className="notification-badge">{count > 9 ? "9+" : count}</span>}
          </button>
          {panel && <NotificationPanel alerts={alerts} onClose={() => setPanel(false)} />}
        </div>
        <div className="user-profile">
          <span className="user-avatar" aria-hidden="true">{initials(user)}</span>
          <div className="user-info"><p className="user-name">{user.name || "User"}</p><p className="user-role">{user.role || "user"}</p></div>
        </div>
      </div>
    </header>
  );
}

function AppShell() {
  const { user, signOut } = useAuth();
  const { events, alerts } = useSecurityData();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const [panel, setPanel] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    setOpen(false);
    setPanel(false);
    window.scrollTo(0, 0);
  }, [pathname]);

  const logout = () => {
    if (window.confirm("Log out of CyberShield?")) {
      signOut();
      navigate("/login", { replace: true });
    }
  };
  const onSearch = (e) => { e.preventDefault(); navigate("/security-events"); };
  const status = computeStatus(events, alerts);

  return (
    <div className="app-shell">
      <Sidebar open={open} onClose={() => setOpen(false)} onLogout={logout} user={user} />
      {open && <div className="sidebar-backdrop" onClick={() => setOpen(false)} />}
      <div className="main-area">
        <Navbar user={user} query={query} setQuery={setQuery} onMenu={() => setOpen(true)} status={status} alerts={alerts} panel={panel} setPanel={setPanel} onSearch={onSearch} />
        <main className="main-content"><Outlet context={{ query, setQuery, logout }} /></main>
        <footer className="app-footer"><p>© 2026 CyberShield · Intelligent protection for your digital world.</p></footer>
      </div>
    </div>
  );
}

function ProtectedRoute() {
  const { token, status, authError, retry } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  if (status === "loading") return <LoadingState full label="Verifying your session..." />;
  if (status === "error") return <ErrorState full kind={authError} label="your session" onRetry={retry} />;
  if (status !== "ready") return <Navigate to="/login" replace />;
  return <SecurityDataProvider><AppShell /></SecurityDataProvider>;
}

/* ================================ PUBLIC PAGES ================================ */

function NetworkVisual() {
  return (
    <svg className="net" viewBox="0 0 420 340" role="img" aria-label="Illustration of CyberShield connecting security signals">
      <defs>
        <radialGradient id="coreGlow">
          <stop offset="0%" stopColor="#22c55e" stopOpacity="0.45" />
          <stop offset="100%" stopColor="#22c55e" stopOpacity="0" />
        </radialGradient>
      </defs>
      <circle cx="210" cy="180" r="100" fill="url(#coreGlow)" />
      {NODES.map((n, i) => {
        const next = NODES[(i + 1) % NODES.length];
        return <line key={`r${n.l}`} className="net-ring" x1={n.x} y1={n.y} x2={next.x} y2={next.y} />;
      })}
      {NODES.map((n) => <line key={`s${n.l}`} className="net-line" x1="210" y1="180" x2={n.x} y2={n.y} />)}
      {NODES.map((n, i) => (
        <g key={n.l}>
          <circle className="net-node" cx={n.x} cy={n.y} r="7" style={{ animationDelay: `${i * 0.4}s` }} />
          <text className="net-label" x={n.x} y={n.y < 180 ? n.y - 16 : n.y + 24} textAnchor="middle">{n.l}</text>
        </g>
      ))}
      <circle className="net-core" cx="210" cy="180" r="30" />
      <text className="net-core-icon" x="210" y="191" textAnchor="middle">◈</text>
    </svg>
  );
}

function Home() {
  const { token } = useAuth();
  return (
    <div className="lp" id="top">
      <header className="lp-nav">
        <div className="wrap">
          <Logo />
          <nav className="lp-links" aria-label="Primary">
            <a href="#features">Features</a><a href="#security">Security</a><a href="#how">How It Works</a>
          </nav>
          <div className="lp-cta">
            {token ? (
              <Link className="btn btn-primary" to="/dashboard">Dashboard</Link>
            ) : (
              <>
                <Link className="btn btn-ghost" to="/login">Login</Link>
                <Link className="btn btn-primary" to="/register">Get Started</Link>
              </>
            )}
          </div>
        </div>
      </header>

      <section className="lp-hero">
        <div className="wrap hero-grid">
          <div>
            <span className="eyebrow"><span className="status-dot" aria-hidden="true" />Security systems operational</span>
            <h1>Stay Ahead of<br /><span className="accent">Every Threat.</span></h1>
            <p className="hero-p">CyberShield provides intelligent security monitoring, suspicious activity detection, secure authentication, and real-time security visibility.</p>
            <div className="hero-btns">
              <Link className="btn btn-primary" to="/register">Get Started</Link>
              <a className="btn btn-ghost" href="#security">Explore Security</a>
            </div>
          </div>
          <div className="lp-preview">
            <NetworkVisual />
            <p className="fine" style={{ textAlign: "center" }}>Illustration: signals CyberShield connects in one command center</p>
          </div>
        </div>
      </section>

      <section className="lp-section" id="features">
        <div className="wrap">
          <div className="sec-head"><h2>Everything you need to stay protected.</h2><p>A focused set of defensive tools that work together.</p></div>
          <div className="feat-grid">
            {FEATURES.map((f) => (
              <article className="feat" key={f.title}>
                <span className="feat-icon" aria-hidden="true">{f.icon}</span>
                <h3>{f.title}</h3><p>{f.text}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section" id="how">
        <div className="wrap">
          <div className="sec-head"><h2>How CyberShield works</h2><p>From the first signal to a resolved issue in four steps.</p></div>
          <ol className="steps">
            {STEPS.map(([n, t, d]) => (
              <li className="step" key={n}><span className="step-num">{n}</span><h3>{t}</h3><p>{d}</p></li>
            ))}
          </ol>
        </div>
      </section>

      <section className="lp-section" id="security">
        <div className="wrap">
          <div className="sec-split">
            <div>
              <h2>Your security. One intelligent command center.</h2>
              <ul className="ticks">
                {["Real-time monitoring", "Security event visibility", "Suspicious activity detection", "Secure authentication", "Account protection"].map((t) => <li key={t}>{t}</li>)}
              </ul>
            </div>
            <div className="card">
              <div className="card-header"><h3 className="card-title">What CyberShield records</h3></div>
              <ul className="recs">{MONITORED.map((m) => <li key={m}>{m}</li>)}</ul>
            </div>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="wrap">
          <div className="lp-final">
            <h2>Ready to take control of your security?</h2>
            <Link className="btn btn-primary" to="/register">Launch CyberShield →</Link>
          </div>
        </div>
      </section>

      <footer className="lp-footer">
        <div className="wrap"><Logo /><span>© 2026 CyberShield · Intelligent protection for your digital world.</span></div>
      </footer>
    </div>
  );
}

function Login() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (!email.trim() || !password) { setError("Please enter your email and password."); return; }
    setLoading(true);
    try {
      // loginUser resolves to { success, message, data: { token, user } }
      const res = await loginUser({ email: email.trim().toLowerCase(), password });
      const token = res && res.data && res.data.token;
      if (!token) throw new Error("Login failed. No token was received.");
      signIn(token, res.data.user);
      navigate("/dashboard");
    } catch (err) {
      setError(classify(err) === "network" ? ERROR_COPY.network[1] : (err && err.message) || "Login failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="auth-page">
      <div className="auth-card">
        <Logo />
        <h1>Welcome back</h1>
        <p className="auth-sub">Sign in to your security command center.</p>
        {error && <div className="form-msg err" role="alert">{error}</div>}
        <form onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="email">Email</label>
            <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" placeholder="you@example.com" />
          </div>
          <PasswordField id="password" label="Password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
            {loading ? <><span className="spinner spinner-small" /> Signing in...</> : "Login"}
          </button>
        </form>
        <div className="auth-foot"><span>No account? <Link to="/register">Register</Link></span><Link to="/">← Back to home</Link></div>
      </div>
    </main>
  );
}

function Register() {
  const navigate = useNavigate();
  const timer = useRef(null);
  const [form, setForm] = useState({ name: "", email: "", password: "", confirm: "" });
  const [touched, setTouched] = useState({});
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => () => clearTimeout(timer.current), []);

  const errors = {};
  if (!form.name.trim()) errors.name = "Name is required.";
  if (!/^\S+@\S+\.\S+$/.test(form.email.trim())) errors.email = "Enter a valid email address.";
  if (form.password.length < 6) errors.password = "Password must be at least 6 characters.";
  else if (form.password.length > 72) errors.password = "Password must be at most 72 characters.";
  if (form.confirm !== form.password) errors.confirm = "Passwords do not match.";

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const blur = (k) => () => setTouched((t) => ({ ...t, [k]: true }));
  const show = (k) => ((touched[k] || submitted) ? errors[k] : undefined);
  const score = strengthOf(form.password);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitted(true);
    setError("");
    if (Object.keys(errors).length) return;
    setLoading(true);
    try {
      // No role is ever sent from the frontend.
      await registerUser({ name: form.name.trim(), email: form.email.trim().toLowerCase(), password: form.password });
      setSuccess("Account created successfully. Redirecting to login...");
      timer.current = setTimeout(() => navigate("/login"), 1500);
    } catch (err) {
      setError(classify(err) === "network" ? ERROR_COPY.network[1] : (err && err.message) || "Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="auth-page">
      <div className="auth-card">
        <Logo />
        <h1>Create your account</h1>
        <p className="auth-sub">Start monitoring your security in minutes.</p>
        {error && <div className="form-msg err" role="alert">{error}</div>}
        {success && <div className="form-msg ok" role="status">{success}</div>}
        <form onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="name">Name</label>
            <input id="name" value={form.name} onChange={set("name")} onBlur={blur("name")} autoComplete="name" placeholder="Alex Morgan" />
            {show("name") && <span className="field-err">{show("name")}</span>}
          </div>
          <div className="field">
            <label htmlFor="reg-email">Email</label>
            <input id="reg-email" type="email" value={form.email} onChange={set("email")} onBlur={blur("email")} autoComplete="email" placeholder="you@example.com" />
            {show("email") && <span className="field-err">{show("email")}</span>}
          </div>
          <PasswordField id="reg-password" label="Password" value={form.password} onChange={set("password")} onBlur={blur("password")} error={show("password")} autoComplete="new-password" />
          {form.password && (
            <div style={{ marginTop: -6, marginBottom: 16 }}>
              <div className="strength" style={{ "--s": STRENGTH[score].c }}>
                {[1, 2, 3, 4].map((i) => <i key={i} className={i <= score ? "on" : ""} />)}
              </div>
              <span className="field-err" style={{ color: STRENGTH[score].c }}>Password strength: {STRENGTH[score].l}</span>
            </div>
          )}
          <PasswordField id="confirm" label="Confirm password" value={form.confirm} onChange={set("confirm")} onBlur={blur("confirm")} error={show("confirm")} autoComplete="new-password" />
          <button type="submit" className="btn btn-primary btn-block" disabled={loading || Boolean(success)}>
            {loading ? <><span className="spinner spinner-small" /> Creating account...</> : "Create account"}
          </button>
        </form>
        <div className="auth-foot"><span>Have an account? <Link to="/login">Login</Link></span><Link to="/">← Back to home</Link></div>
      </div>
    </main>
  );
}

/* ================================== APP PAGES ================================== */

// Every card reads one field from data.stats returned by getDashboardData().
const STAT_CARDS = [
  { key: "totalEvents", label: "Total Security Events", note: "All recorded events", tone: "info", icon: "◉" },
  { key: "failedLogins", label: "Failed Login Attempts", note: "Failed sign-ins recorded", tone: "warning", icon: "⚠" },
  { key: "successfulLogins", label: "Successful Logins", note: "Successful sign-ins recorded", tone: "success", icon: "✓" },
  { key: "criticalEvents", label: "Critical Events", note: "Highest severity level", tone: "danger", icon: "◈" },
];

function AlertList({ items, emptyTitle, emptyText }) {
  if (items.length === 0) return <EmptyState title={emptyTitle} text={emptyText} />;
  return <ul className="alert-list">{items.map((a) => <AlertCard key={a.id} alert={a} />)}</ul>;
}

function Dashboard() {
  const { user } = useAuth();
  const { dashboard, events, alerts, reload } = useSecurityData();
  const status = computeStatus(events, alerts);
  const stats = dashboard.status === "ready" ? dashboard.data.stats : null;

  const h = new Date().getHours();
  const hello = h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";

  // Recent events come from the dashboard payload; if the dashboard request
  // failed, the real events list is used. Failures are never replaced by sample data.
  let recent;
  if (dashboard.status === "ready") recent = { status: "ready", data: { items: dashboard.data.recentEvents } };
  else if (events.status === "ready") recent = events;
  else if (dashboard.status === "loading" || events.status === "loading") recent = LOADING;
  else recent = dashboard;

  return (
    <>
      <PageHeader title={`${hello}, ${user.name || "there"}`} subtitle="Here's your security overview." />
      <SecurityStatus status={status} />
      {dashboard.status === "error" && <ErrorState kind={dashboard.error} label="security data" onRetry={reload} compact />}

      {dashboard.status === "loading" ? <SkeletonCards /> : (
        <section className="stats-grid" aria-label="Security statistics">
          {STAT_CARDS.map((c) => (
            <StatCard key={c.key} label={c.label} tone={c.tone} icon={c.icon}
              value={fmt(stats ? stats[c.key] : null)} note={stats ? c.note : "Data unavailable"} />
          ))}
        </section>
      )}

      <div className="grid grid-chart">
        <section className="card">
          <div className="card-header"><div><h2 className="card-title">Recent security events</h2><p className="card-subtitle">Latest activity recorded by the backend</p></div></div>
          <Async res={recent} onRetry={reload} label="security events" skeleton={<EventTable loading events={EMPTY} />}>
            {(data) => data.items.length === 0
              ? <EmptyState title="No security events recorded." text="Events will appear here as activity is recorded." />
              : <EventTable events={[...data.items].sort(newest).slice(0, 6)} />}
          </Async>
        </section>
        <section className="card">
          <div className="card-header"><div><h2 className="card-title">Threat overview</h2><p className="card-subtitle">Reported by the server</p></div></div>
          {dashboard.status === "loading" ? <LoadingState compact /> : !stats
            ? <EmptyState title="Severity data unavailable" text="Counts will appear when the dashboard data loads." />
            : stats.totalEvents === 0
              ? <EmptyState title="No security events recorded." />
              : (
                <>
                  <Meters rows={severityRows({ critical: stats.criticalEvents, high: stats.highEvents, medium: null, low: null })} />
                  <p className="fine" style={{ margin: "-4px 0 14px" }}>Medium and low severity counts aren't reported by the dashboard.</p>
                  <h3 className="drawer-sub">By status</h3>
                  <Meters wide rows={statusRows({ open: stats.openEvents, investigating: stats.investigatingEvents, resolved: stats.resolvedEvents })} />
                </>
              )}
        </section>
      </div>

      <section className="card">
        <div className="card-header"><div><h2 className="card-title">Recent alerts</h2><p className="card-subtitle">Open alerts are listed first</p></div><Link to="/threats" className="link-button">View all</Link></div>
        <Async res={alerts} onRetry={reload} label="security alerts" skeleton={<AlertSkeletons />}>
          {(data) => (
            <AlertList
              items={[...data.items].sort((a, b) => Number(isOpen(b)) - Number(isOpen(a)) || newest(a, b)).slice(0, 4)}
              emptyTitle="No active security alerts." emptyText="Alerts will appear here when something needs your attention."
            />
          )}
        </Async>
      </section>
    </>
  );
}

function SecurityEvents() {
  const { query, setQuery } = useOutletContext();
  const { events, reload } = useSecurityData();
  const [sev, setSev] = useState("all");
  const [type, setType] = useState("all");
  const [status, setStatus] = useState("all");
  const [sort, setSort] = useState("newest");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);

  useEffect(() => { setPage(1); }, [query, sev, type, status, sort]);

  const items = useMemo(() => (events.status === "ready" ? events.data.items : EMPTY), [events]);
  const types = useMemo(() => [...new Set(items.map((e) => e.type).filter(Boolean))].sort(), [items]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = items.filter((e) =>
      (sev === "all" || e.severity === sev) &&
      (type === "all" || e.type === type) &&
      (status === "all" || e.status === status) &&
      (!q || `${e.message} ${e.type} ${e.ip || ""} ${e.email || ""} ${e.userName || ""} ${e.id}`.toLowerCase().includes(q))
    );
    return list.sort((a, b) => (sort === "newest" ? newest(a, b) : -newest(a, b)));
  }, [items, query, sev, type, status, sort]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const visible = rows.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);

  return (
    <>
      <PageHeader title="Security Events" subtitle="Monitor and investigate security activity." />
      <section className="card">
        <div className="card-header">
          <div className="controls">
            <SearchBar value={query} onChange={setQuery} placeholder="Search events, IPs, emails..." label="Search events" />
            <select className="select" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity filter">
              <option value="all">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <select className="select" value={type} onChange={(e) => setType(e.target.value)} aria-label="Event type filter">
              <option value="all">All types</option>
              {types.map((t) => <option key={t} value={t}>{label(t)}</option>)}
            </select>
            <select className="select" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status filter">
              <option value="all">All statuses</option>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <select className="select" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort order">
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
            </select>
          </div>
        </div>
        <Async res={events} onRetry={reload} label="security events" skeleton={<EventTable loading events={EMPTY} />}>
          {(data) => data.items.length === 0 ? (
            <EmptyState title="No security events recorded." text="Events will appear here as activity is recorded." />
          ) : rows.length === 0 ? (
            <EmptyState title="No security events found" text="Try adjusting your search or filters." />
          ) : (
            <>
              <EventTable events={visible} onSelect={setSelected} />
              <p className="fine" style={{ marginTop: 12 }}>
                Showing {visible.length} of {rows.length} matching events
                {data.total !== null && data.total > data.items.length ? ` (the most recent ${data.items.length} of ${data.total} loaded)` : ""}.
              </p>
              <Pager page={current} pages={pages} onPage={setPage} />
            </>
          )}
        </Async>
      </section>
      {selected && <EventDrawer event={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function Threats() {
  const { dashboard, events, alerts, reload } = useSecurityData();
  const status = computeStatus(events, alerts);
  const stats = dashboard.status === "ready" ? dashboard.data.stats : null;
  const evItems = events.status === "ready" ? events.data.items : null;
  const open = alerts.status === "ready" ? alerts.data.items.filter(isOpen).sort(newest) : null;
  const high = evItems ? evItems.filter((e) => e.severity === "critical" || e.severity === "high").sort(newest) : null;
  const suspicious = evItems ? evItems.filter((e) => e.type === "suspicious_activity").sort(newest) : null;
  const timeline = evItems ? [...evItems].sort(newest).slice(0, 8) : null;
  const highTotal = stats && stats.criticalEvents !== null && stats.highEvents !== null ? stats.criticalEvents + stats.highEvents : null;

  return (
    <>
      <PageHeader title="Threat Monitoring" subtitle="Live view of the alerts and events recorded by your backend." />
      <SecurityStatus status={status} />
      <section className="stats-grid stats-three" aria-label="Threat summary">
        <StatCard label="Active Alerts" value={fmt(open && open.length)} note="Not yet resolved" tone="danger" icon="⚑" />
        <StatCard label="High & Critical Events" value={fmt(highTotal)} note="All recorded events" tone="warning" icon="◈" />
        <StatCard label="Open Events" value={fmt(stats && stats.openEvents)} note="Awaiting review" tone="info" icon="◉" />
      </section>
      <div className="grid grid-2">
        <section className="card">
          <div className="card-header"><h2 className="card-title">Active alerts</h2></div>
          <Async res={alerts} onRetry={reload} label="security alerts" skeleton={<AlertSkeletons />}>
            {() => <AlertList items={open.slice(0, 6)} emptyTitle="No active security alerts." emptyText="Nothing needs your attention right now." />}
          </Async>
        </section>
        <section className="card">
          <div className="card-header"><h2 className="card-title">High-severity events</h2></div>
          <Async res={events} onRetry={reload} label="security events" skeleton={<EventTable loading events={EMPTY} />}>
            {() => high.length === 0
              ? <EmptyState title="No high-severity events" text="High and critical events will be listed here." />
              : <EventTable events={high.slice(0, 5)} />}
          </Async>
        </section>
      </div>
      <div className="grid grid-2">
        <section className="card">
          <div className="card-header"><h2 className="card-title">Suspicious activity</h2></div>
          <Async res={events} onRetry={reload} label="security events" skeleton={<EventTable loading events={EMPTY} />}>
            {() => suspicious.length === 0
              ? <EmptyState title="No suspicious activity detected" text="Flagged events will be listed here." />
              : <EventTable events={suspicious.slice(0, 5)} />}
          </Async>
        </section>
        <section className="card">
          <div className="card-header"><h2 className="card-title">Recent threat timeline</h2></div>
          <Async res={events} onRetry={reload} label="security events" skeleton={<LoadingState compact />}>
            {() => timeline.length === 0
              ? <EmptyState title="No security events recorded." />
              : (
                <ol className="timeline">
                  {timeline.map((t) => {
                    const f = fmtDate(t.time);
                    return (
                      <li className="timeline-item" key={t.id}>
                        <span className="timeline-icon" aria-hidden="true">◉</span>
                        <div>
                          <h3 className="timeline-title">{t.message || label(t.type)}</h3>
                          <p className="timeline-detail"><span className="cap">{label(t.type)}</span>{t.ip ? ` · ${t.ip}` : ""}</p>
                        </div>
                        <time className="timeline-time">{f ? `${f.date}, ${f.time}` : "—"}</time>
                      </li>
                    );
                  })}
                </ol>
              )}
          </Async>
        </section>
      </div>
    </>
  );
}

function Analytics() {
  const { events, reload } = useSecurityData();
  const [range, setRange] = useState("week");
  const items = useMemo(() => (events.status === "ready" ? events.data.items : EMPTY), [events]);
  const { rows, inRange } = useMemo(() => buildSeries(items, range), [items, range]);
  const counts = useMemo(() => tally(inRange), [inRange]);

  return (
    <>
      <PageHeader title="Analytics" subtitle="Trends calculated from the security events returned by your backend.">
        <div className="segmented" role="group" aria-label="Time range">
          {Object.entries(RANGES).map(([k, l]) => (
            <button key={k} type="button" className={range === k ? "on" : ""} aria-pressed={range === k} onClick={() => setRange(k)}>{l}</button>
          ))}
        </div>
      </PageHeader>
      <Async res={events} onRetry={reload} label="analytics data" skeleton={<SkeletonCards count={2} />}>
        {(data) => inRange.length === 0 ? (
          <section className="card">
            <EmptyState
              title={data.items.length === 0 ? "No security events recorded." : "No events in this time range"}
              text={data.items.length === 0 ? "Analytics will appear once activity is recorded." : "Try a longer range."}
            />
          </section>
        ) : (
          <>
            <p className="fine">
              Based on {inRange.length} event{inRange.length === 1 ? "" : "s"} in the selected range
              {data.complete ? "." : ` (calculated from the ${data.items.length} most recent events loaded).`}
            </p>
            <div className="grid grid-2">
              <section className="card">
                <div className="card-header"><h2 className="card-title">Security event activity</h2></div>
                <Bars data={rows} series={[["all", "bar-a"]]} />
              </section>
              <section className="card">
                <div className="card-header">
                  <h2 className="card-title">Login success vs failure</h2>
                  <div className="legend"><span><i className="lg lg-a" />Success</span><span><i className="lg lg-b" />Failed</span></div>
                </div>
                <Bars data={rows} series={[["success", "bar-a"], ["failed", "bar-b"]]} />
              </section>
            </div>
            <div className="grid grid-2">
              <section className="card">
                <div className="card-header"><h2 className="card-title">Severity distribution</h2></div>
                <Meters rows={severityRows(counts)} />
              </section>
              <section className="card">
                <div className="card-header"><h2 className="card-title">Suspicious activity</h2></div>
                <Bars data={rows} series={[["suspicious", "bar-b"]]} />
              </section>
            </div>
          </>
        )}
      </Async>
    </>
  );
}

function Profile() {
  const { user } = useAuth();
  const created = fmtDate(user.createdAt);
  const active = user.isActive !== false;
  return (
    <>
      <PageHeader title="Profile" subtitle="Your account details from the CyberShield server." />
      <section className="card">
        <div className="card-header">
          <div className="user-profile" style={{ background: "none", boxShadow: "none", padding: 0 }}>
            <span className="user-avatar" style={{ width: 56, height: 56, fontSize: 18 }} aria-hidden="true">{initials(user)}</span>
            <div><h2 className="card-title">{user.name || "User"}</h2><p className="card-subtitle">{user.email}</p></div>
          </div>
          <span className={`badge ${active ? "badge-low" : "badge-critical"}`}>{active ? "Active" : "Deactivated"}</span>
        </div>
        <dl className="kv">
          <div><dt>Name</dt><dd>{user.name || "Not set"}</dd></div>
          <div><dt>Email</dt><dd>{user.email}</dd></div>
          <div><dt>Role</dt><dd className="cap">{user.role || "—"}</dd></div>
          <div><dt>Account status</dt><dd>{active ? "Active" : "Deactivated"}</dd></div>
          <div><dt>Account created</dt><dd>{created ? created.date : "Not available"}</dd></div>
        </dl>
      </section>
    </>
  );
}

function Settings() {
  const { user, token } = useAuth();
  const { logout } = useOutletContext();
  return (
    <>
      <PageHeader title="Settings" subtitle="Only settings supported by the backend are shown." />
      <div className="grid grid-2">
        <section className="card">
          <h2 className="card-title">Account</h2>
          <dl className="kv one">
            <div><dt>Name</dt><dd>{user.name || "Not set"}</dd></div>
            <div><dt>Email</dt><dd>{user.email}</dd></div>
            <div><dt>Role</dt><dd className="cap">{user.role || "—"}</dd></div>
          </dl>
          <p className="fine" style={{ marginTop: 12 }}>Editing account details isn't available yet.</p>
        </section>
        <section className="card">
          <h2 className="card-title">Security</h2>
          <dl className="kv one">
            <div><dt>Authentication</dt><dd>JWT bearer token</dd></div>
            <div><dt>Token storage</dt><dd>Browser localStorage</dd></div>
            <div><dt>Password changes</dt><dd>Not available yet</dd></div>
          </dl>
        </section>
      </div>
      <div className="grid grid-2">
        <section className="card">
          <h2 className="card-title">Notifications</h2>
          <EmptyState title="Notification preferences are unavailable" text="The backend doesn't support notification settings yet. Active alerts appear in the bell menu." />
        </section>
        <section className="card">
          <h2 className="card-title">Sessions</h2>
          <dl className="kv one">
            <div><dt>Signed in as</dt><dd>{user.email}</dd></div>
            <div><dt>Session expires</dt><dd>{tokenExpiry(token)}</dd></div>
          </dl>
          <div style={{ marginTop: 18 }}><button type="button" className="btn btn-danger" onClick={logout}>Logout</button></div>
        </section>
      </div>
    </>
  );
}

/* ================================== STYLES ================================== */
/* Extra styles for components in this file. They reuse the variables and
   classes from App.css and are rendered after it. App.css is not modified. */

const STYLES = `
.lp-section{scroll-margin-top:72px}
.fine{font-size:12.5px;color:var(--text-dim)}
.ts{display:grid;line-height:1.3}
.ts small{font-size:12px;color:var(--text-dim)}
.row-link{display:block;padding:0;font-weight:600;text-align:left;color:var(--text);transition:color .2s}
.row-link:hover{color:var(--green);text-decoration:underline}
.badge-unknown{color:var(--text-muted);box-shadow:inset 0 0 0 1px var(--border-strong)}
.empty-icon{display:block;margin-bottom:8px;font-size:26px;color:var(--text-dim)}
.empty p{max-width:420px;margin:0 auto;font-size:14px}

.state{display:grid;justify-items:center;gap:10px;padding:40px 20px;text-align:center;color:var(--text-muted)}
.state h3{font-size:16px;color:var(--text)}
.state p{max-width:440px;font-size:14px;line-height:1.55}
.state.compact{padding:24px 16px}
.state.full{align-content:center;min-height:100vh;background:var(--bg)}
.state-icon{display:grid;place-items:center;width:40px;height:40px;font-weight:800;color:#fca5a5;border-radius:50%;background:rgba(var(--red-rgb),.12);box-shadow:inset 0 0 0 1px rgba(var(--red-rgb),.35)}

.sec-status.sec-attention{background:linear-gradient(135deg,rgba(var(--red-rgb),.14),rgba(10,20,36,.78));border-color:rgba(var(--red-rgb),.35)}
.sec-status.sec-unknown,.sec-status.sec-loading{background:linear-gradient(135deg,rgba(var(--amber-rgb),.1),rgba(10,20,36,.78));border-color:rgba(var(--amber-rgb),.3)}
.sec-attention .sec-shield{color:var(--red);animation:none;background:rgba(var(--red-rgb),.14)}
.sec-unknown .sec-shield,.sec-loading .sec-shield{color:var(--amber);animation:none;background:rgba(var(--amber-rgb),.12)}
.pb-attention{color:#fca5a5;background:rgba(var(--red-rgb),.12);box-shadow:inset 0 0 0 1px rgba(var(--red-rgb),.38)}
.pb-unknown,.pb-loading{color:#fcd34d;background:rgba(var(--amber-rgb),.12);box-shadow:inset 0 0 0 1px rgba(var(--amber-rgb),.36)}
.status-dot.dot-attention{background:var(--red);animation:none}
.status-dot.dot-unknown,.status-dot.dot-loading{background:var(--amber);animation:none}
.security-status.ss-attention{color:#fca5a5;background:rgba(var(--red-rgb),.1);box-shadow:inset 0 0 0 1px rgba(var(--red-rgb),.35)}
.security-status.ss-unknown,.security-status.ss-loading{color:#fcd34d;background:rgba(var(--amber-rgb),.1);box-shadow:inset 0 0 0 1px rgba(var(--amber-rgb),.32)}

.topbar-search{flex:1;min-width:0;max-width:460px}
.topbar-search .search-box{max-width:none}
.sidebar-user{display:flex;align-items:center;gap:10px;min-width:0;padding:12px;border-radius:var(--radius-md);background:rgba(255,255,255,.035);box-shadow:var(--ring)}
.sidebar-user>div{min-width:0}
.sidebar-user .user-name,.sidebar-user .user-role{overflow:hidden;text-overflow:ellipsis;text-transform:none}
.stats-three{grid-template-columns:repeat(3,minmax(0,1fr))}
.kv.one{grid-template-columns:minmax(0,1fr)}
.meter-row.wide{grid-template-columns:120px minmax(0,1fr) 40px}
.meter-row .status-open,.meter-row .status-investigating,.meter-row .status-resolved{justify-self:start}
.legend{display:flex;gap:14px;font-size:12.5px;color:var(--text-muted)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.lg{display:inline-block;width:10px;height:10px;border-radius:3px}
.lg-a{background:var(--green)}
.lg-b{background:var(--red)}

.pager{display:flex;align-items:center;justify-content:center;gap:16px;margin-top:16px;font-size:13px;color:var(--text-muted)}
.pager .btn{min-height:38px;padding:8px 16px;font-size:13px}

.drawer-backdrop{position:fixed;inset:0;z-index:80;background:rgba(2,6,14,.7);-webkit-backdrop-filter:blur(3px);backdrop-filter:blur(3px);animation:fadeIn .2s var(--ease)}
.drawer{position:fixed;top:0;right:0;bottom:0;z-index:90;width:min(480px,100vw);padding:24px;overflow-y:auto;background:var(--glass-strong);border-left:1px solid var(--border-strong);box-shadow:-24px 0 60px rgba(0,0,0,.55);animation:drawerIn .3s var(--ease)}
.drawer-sub{margin:20px 0 10px;font-size:14px;color:var(--text-muted)}
.code{margin:0;padding:14px;overflow-x:auto;font-family:var(--mono);font-size:12.5px;line-height:1.55;color:var(--text-muted);border-radius:var(--radius-sm);background:rgba(255,255,255,.04);box-shadow:var(--ring)}
@keyframes drawerIn{from{opacity:0;transform:translateX(24px)}}

.net{display:block;width:100%;height:auto}
.net-line{stroke:rgba(34,197,94,.55);stroke-width:1.2;stroke-dasharray:4 6;animation:netDash 3s linear infinite}
.net-ring{stroke:rgba(6,182,212,.22);stroke-width:1}
.net-node{fill:#06b6d4;stroke:rgba(6,182,212,.35);stroke-width:6;animation:nodePulse 3s ease-in-out infinite}
.net-label{fill:var(--text-muted);font-size:12px;font-weight:500}
.net-core{fill:#08111f;stroke:var(--green);stroke-width:1.5}
.net-core-icon{fill:var(--green);font-size:30px}
@keyframes netDash{to{stroke-dashoffset:-20}}
@keyframes nodePulse{50%{opacity:.55}}

@media (max-width:1100px){.stats-three{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:760px){.stats-three{grid-template-columns:minmax(0,1fr)}}
@media (max-width:600px){
  .topbar .topbar-search{order:3;flex:1 1 100%;max-width:none}
  .drawer{padding:18px}
  .pager{gap:10px}
}
`;

/* ==================================== APP ==================================== */

export default function App() {
  // If main.jsx already wraps the app in a router, reuse it; otherwise provide one.
  const inRouter = useInRouterContext();
  const Router = inRouter ? Fragment : BrowserRouter;

  return (
    <Router>
      <style>{STYLES}</style>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/security-events" element={<SecurityEvents />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </Router>
  );
}