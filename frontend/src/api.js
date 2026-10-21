const API_BASE_URL = "https://cybersheild-theta.vercel.app/api";

/* =========================================================
   AUTHENTICATION
========================================================= */

export const registerUser = async (userData) => {
  const response = await fetch(`${API_BASE_URL}/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(userData),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message || "Registration failed");
  }

  return data;
};

export const loginUser = async (credentials) => {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(credentials),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message || "Login failed");
  }

  return data;
};

export const getCurrentUser = async (token) => {
  const response = await fetch(`${API_BASE_URL}/auth/me`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message || "Failed to get user");
  }

  return data;
};

/* =========================================================
   SECURITY DASHBOARD
========================================================= */

export const getDashboardData = async (token) => {
  if (!token) {
    throw new Error("Authentication token is missing");
  }

  const response = await fetch(`${API_BASE_URL}/security/dashboard`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.message || "Failed to load dashboard data"
    );
  }

  return data;
};

/* =========================================================
   SECURITY EVENTS
========================================================= */

export const getSecurityEvents = async (token) => {
  if (!token) {
    throw new Error("Authentication token is missing");
  }

  const response = await fetch(`${API_BASE_URL}/security/events`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.message || "Failed to load security events"
    );
  }

  return data;
};

/* =========================================================
   SECURITY ALERTS
========================================================= */

export const getSecurityAlerts = async (token) => {
  if (!token) {
    throw new Error("Authentication token is missing");
  }

  const response = await fetch(`${API_BASE_URL}/security/alerts`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.message || "Failed to load security alerts"
    );
  }

  return data;
};
