import { request } from "../api/client";

function cleanParams(params = {}) {
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== ""),
  );
}

export function getAssets(filters = {}) {
  return request(
    { method: "GET", url: "/assets", params: cleanParams(filters) },
    "Failed to load assets",
  );
}

export function getAsset(id) {
  return request({ method: "GET", url: `/assets/${id}` }, "Failed to load asset");
}

export function createAsset(payload) {
  return request({ method: "POST", url: "/assets", data: payload }, "Failed to create asset");
}
