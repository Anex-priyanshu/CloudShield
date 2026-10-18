/**
 * CloudShield WebSocket Client with Auto-reconnect
 */
import { getToken } from "./api";

type Listener = (data: any) => void;

class WebSocketClient {
  private socket: WebSocket | null = null;
  private listeners: Map<string, Set<Listener>> = new Map();
  private reconnectTimeout: any = null;
  private isConnecting = false;
  private retryDelay = 1000;
  private maxRetryDelay = 30000;
  public isConnected = false;

  constructor() {}

  public connect() {
    if (typeof window === "undefined" || this.socket?.readyState === WebSocket.OPEN || this.isConnecting) {
      return;
    }

    const token = getToken();
    if (!token) return;

    this.isConnecting = true;
    const proto = typeof window !== "undefined" && window.location.protocol === "https:" ? "wss:" : "ws:";
    const defaultWs = typeof window !== "undefined" ? `${proto}//${window.location.hostname}:8000/ws` : "ws://localhost:8000/ws";
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || defaultWs;

    try {
      this.socket = new WebSocket(`${wsUrl}?token=${encodeURIComponent(token)}`);

      this.socket.onopen = () => {
        this.isConnected = true;
        this.isConnecting = false;
        this.retryDelay = 1000;
        this.emit("ws.status", { connected: true });
      };

      this.socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          const type = payload.type;
          const data = payload.data;
          this.emit(type, data);
        } catch (e) {
          console.warn("WS Parse error", e);
        }
      };

      this.socket.onclose = () => {
        this.isConnected = false;
        this.isConnecting = false;
        this.emit("ws.status", { connected: false });
        this.scheduleReconnect();
      };

      this.socket.onerror = () => {
        this.isConnected = false;
        this.isConnecting = false;
      };
    } catch (e) {
      this.isConnecting = false;
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
    this.reconnectTimeout = setTimeout(() => {
      this.retryDelay = Math.min(this.retryDelay * 2, this.maxRetryDelay);
      this.connect();
    }, this.retryDelay);
  }

  public on(event: string, callback: Listener) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
    return () => this.off(event, callback);
  }

  public off(event: string, callback: Listener) {
    this.listeners.get(event)?.delete(callback);
  }

  private emit(event: string, data: any) {
    this.listeners.get(event)?.forEach((cb) => {
      try {
        cb(data);
      } catch (err) {
        console.error("Listener error", err);
      }
    });
  }

  public disconnect() {
    if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.isConnected = false;
  }
}

export const wsClient = new WebSocketClient();
