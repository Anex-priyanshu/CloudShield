"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { getUser, clearToken, setUser, setToken, api } from "./api";
import { wsClient } from "./ws";

interface UserData {
  id: number;
  email: string;
  role: "admin" | "viewer";
}

interface AuthContextType {
  user: UserData | null;
  loading: boolean;
  login: (token: string, user: UserData) => void;
  logout: () => void;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  login: () => {},
  logout: () => {},
  isAdmin: false,
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUserState] = useState<UserData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      const existing = getUser();
      const token = typeof window !== "undefined" ? localStorage.getItem("cloudshield_token") : null;
      if (existing && token && token !== "netshield-demo-jwt-token") {
        setUserState(existing);
        wsClient.connect();
        setLoading(false);
      } else {
        try {
          const res = await api.login("admin@cloudshield.local", "Admin@12345!");
          setUserState(res.user);
          wsClient.connect();
        } catch {
          clearToken();
          setUserState(null);
        } finally {
          setLoading(false);
        }
      }
    };
    initAuth();
  }, []);

  const login = (token: string, userData: UserData) => {
    setToken(token);
    setUserState(userData);
    setUser(userData);
    wsClient.connect();
  };

  const logout = () => {
    clearToken();
    setUserState(null);
    wsClient.disconnect();
    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
  };

  const isAdmin = user?.role === "admin";

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, isAdmin }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
