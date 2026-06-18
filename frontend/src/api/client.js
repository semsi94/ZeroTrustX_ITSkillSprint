import axios from "axios";

const defaultBaseURL =
  typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.hostname}:8000`
    : "http://localhost:8000";
const baseURL = import.meta.env.VITE_API_URL || defaultBaseURL;

export const api = axios.create({
  baseURL,
  headers: { "Content-Type": "application/json" },
});

export function getApiError(err, fallback = "Request failed") {
  const data = err?.response?.data;
  if (typeof data?.error === "string") return data.error;
  if (typeof data?.message === "string") return data.message;
  if (typeof data?.detail === "string") return data.detail;
  if (Array.isArray(data?.detail)) {
    return data.detail.map((item) => item?.msg || item?.message || "Invalid field").join("; ");
  }
  return err?.message || fallback;
}

api.interceptors.request.use(async (config) => {
  const token = localStorage.getItem("ztx_token");
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      localStorage.removeItem("ztx_token");
      const path = window.location.pathname;
      if (!path.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  }
);

export function unwrap(res) {
  if (res?.data && typeof res.data === "object" && "data" in res.data) {
    return res.data.data;
  }
  return res.data;
}

export async function request(config, fallback = "Request failed") {
  try {
    const response = await api(config);
    const data = unwrap(response);
    if (data && typeof data === "object" && data.success === false) {
      const error = new Error(data.error || fallback);
      error.status = response?.status;
      error.data = data;
      throw error;
    }
    return data;
  } catch (err) {
    if (err instanceof Error && !err.response) throw err;
    const error = new Error(getApiError(err, fallback));
    error.status = err?.response?.status;
    error.data = err?.response?.data;
    throw error;
  }
}

export async function downloadBlob(config, fallback = "Download failed") {
  try {
    const response = await api({ ...config, responseType: "blob" });
    return response.data;
  } catch (err) {
    throw new Error(getApiError(err, fallback));
  }
}
