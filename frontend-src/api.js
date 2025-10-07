const PREFIX = "";

let __csrfToken = null;
const getCsrfToken = async () => {
  if (__csrfToken) return __csrfToken;
  const res = await fetch(`/api/csrf-token`, { credentials: "same-origin" });
  if (!res.ok) throw new Error("CSRF token fetch failed");
  const data = await res.json();
  __csrfToken = data && data.csrfToken;
  return __csrfToken;
};

const req = async (url, options = {}) => {
  const { body } = options;
  const method = (options.method || "GET").toUpperCase();
  const headers = { ...options.headers };
  if (body) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
    const token = await getCsrfToken();
    if (token) headers["X-CSRF-Token"] = token;
  }

  return fetch((PREFIX + url).replace(/\/\/$/, ""), {
    ...options,
    body: body ? JSON.stringify(body) : null,
    headers,
    credentials: "same-origin",
  }).then((res) =>
    res.ok
      ? res.json()
      : res.text().then((message) => {
          throw new Error(message);
        })
  );
};

export const getNotes = ({ age, search, page } = {}) => {
  const params = new URLSearchParams();
  if (age) params.set("age", age);
  if (search) params.set("search", search);
  if (page) params.set("page", page);
  const qs = params.toString();
  return req(`/api/notes${qs ? `?${qs}` : ""}`);
};

export const createNote = (title, text) => {
  return req(`/api/notes`, {
    method: "POST",
    body: { title, text },
  });
};

export const getNote = (id) => {
  return req(`/api/notes/${encodeURIComponent(id)}`);
};

export const archiveNote = (id) => {
  return req(`/api/notes/${encodeURIComponent(id)}/archive`, { method: "POST" });
};

export const unarchiveNote = (id) => {
  return req(`/api/notes/${encodeURIComponent(id)}/unarchive`, { method: "POST" });
};

export const editNote = (id, title, text) => {
  return req(`/api/notes/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: { title, text },
  });
};

export const deleteNote = (id) => {
  return req(`/api/notes/${encodeURIComponent(id)}`, { method: "DELETE" });
};

export const deleteAllArchived = () => {
  return req(`/api/notes/archived`, { method: "DELETE" });
};

export const notePdfUrl = (id) => {
  return `/api/notes/${encodeURIComponent(id)}/pdf`;
};
