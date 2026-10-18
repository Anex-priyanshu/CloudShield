"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { getUser, clearToken, setUser, api } from "./api";
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
    const existing = getUser();
    if (existing) {
      setUserState(existing);
      wsClient.connect();
    }
    setLoading(false);
  }, []);

  const login = (token: string, userData: UserData) => {
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
