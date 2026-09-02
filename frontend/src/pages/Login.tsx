import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { setSession } from "../api";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError("Enter any username and password (demo mode).");
      return;
    }
    setSession(username.trim());
    navigate("/");
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h1>
          <span className="logo">🛡️</span> ForenSight
        </h1>
        <p className="muted">AI-powered digital forensic investigation &amp; cyber-triage</p>
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="analyst" />
        <label>Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="demo mode — any password"
        />
        {error && <p className="error">{error}</p>}
        <button className="btn btn-accent btn-block" type="submit">
          Sign in
        </button>
        <p className="muted small">Demo authentication — credentials are not verified against a backend.</p>
      </form>
    </div>
  );
}
