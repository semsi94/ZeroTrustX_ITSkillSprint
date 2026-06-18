import { request } from "../api/client";

export function getFirewallStatus() {
  return request({ method: "GET", url: "/api/firewall/status" }, "Failed to load firewall status");
}

export function getFirewallActions() {
  return request({ method: "GET", url: "/api/firewall/actions" }, "Failed to load containment history");
}

export function getBlockedIps() {
  return request({ method: "GET", url: "/api/firewall/blocked-ips" }, "Failed to load blocked IPs");
}

export function runFirewallAction(payload) {
  return request({ method: "POST", url: "/api/firewall/action", data: payload }, "Firewall action failed");
}

export function blockIp(payload) {
  return request({ method: "POST", url: "/api/firewall/block-ip", data: payload }, "Failed to block IP");
}

export function unblockIp(payload) {
  return request({ method: "POST", url: "/api/firewall/unblock-ip", data: payload }, "Failed to unblock IP");
}

export function checkIp(payload) {
  return request({ method: "POST", url: "/api/firewall/check-ip", data: payload }, "Failed to check IP status");
}
