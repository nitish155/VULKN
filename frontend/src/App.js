import React, { useState } from "react";
import "./App.css";
import bg from "./bg.jpg";

function App() {
  const [urlInput, setUrlInput] = useState("");
  const [status, setStatus] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  const handleScan = () => {
    if (!urlInput) return;

    setIsScanning(true);
    setStatus(null);

    setTimeout(() => {
      const isMalicious = Math.random() > 0.5;
      setStatus(isMalicious ? "danger" : "safe");
      setIsScanning(false);
    }, 2000);
  };

  return (
    <div
      style={{
        background: `url(${bg}) no-repeat center center/cover`,
        minHeight: "100vh",
      }}
    >
      <div className="container">

        <h1 className="main-title">VULKN</h1>

        <p className={`tagline ${status}`}>
          Spot Vulnerabilities of your website
        </p>

        {/* 🔥 FIXED INPUT */}
        <input
          type="text"
          value={urlInput}
          onChange={(e) => {
            setUrlInput(e.target.value);
            setStatus(null); // ✅ clears previous result instantly
          }}
          placeholder="Enter URL (e.g., http://example.com)"
          className="glass-input"
        />

        {/* Fingerprint Scan */}
        <div className={`scan-box ${isScanning ? "scanning" : ""}`}>
          <img className="fingerprint" src="/fingerprint.png" alt="fingerprint" />
          <div className="scan-line"></div>
        </div>

        <div className="ping"></div>

        <button className="scan-btn" onClick={handleScan} disabled={isScanning}>
          <span>{isScanning ? "Scanning..." : "Scan Now"}</span>
        </button>

        {/* Result */}
        {status && (
          <div className={`result ${status}`}>
            {status === "danger"
              ? "⚠ THREAT DETECTED — THIS LINK IS UNSAFE"
              : "✅ LINK VERIFIED — SAFE TO USE"}
          </div>
        )}

      </div>
    </div>
  );
}

export default App;