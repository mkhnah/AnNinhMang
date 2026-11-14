import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Profile } from './pages/Profile';
import { Documents, DocumentDetail } from './pages/Documents';
import { AdminOverview } from './pages/AdminOverview';
import { Forbidden } from './pages/Forbidden';
import { NotFound } from './pages/NotFound';

const PublicOnlyRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (user) return <Navigate to="/" replace />;
  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <div className="min-h-screen bg-slate-50 flex flex-col font-sans">
          <Navbar />
          <main className="flex-1">
            <Routes>
              {/* Public Only Routes */}
              <Route
                path="/login"
                element={
                  <PublicOnlyRoute>
                    <Login />
                  </PublicOnlyRoute>
                }
              />
              <Route
                path="/register"
                element={
                  <PublicOnlyRoute>
                    <Register />
                  </PublicOnlyRoute>
                }
              />

              {/* Protected User Routes */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <Documents />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/profile"
                element={
                  <ProtectedRoute>
                    <Profile />
                  </ProtectedRoute>
                }
              />

              <Route path="/documents" element={<ProtectedRoute><Documents /></ProtectedRoute>} />
              <Route path="/documents/:id" element={<ProtectedRoute><DocumentDetail /></ProtectedRoute>} />

              {/* Admin Protected Routes */}
              <Route
                path="/admin"
                element={
                  <ProtectedRoute requiredRole="ADMIN">
                    <AdminOverview />
                  </ProtectedRoute>
                }
              />

              {/* Error Routes */}
              <Route path="/forbidden" element={<Forbidden />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
        </div>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
