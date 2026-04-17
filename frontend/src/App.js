import React, { useState, useEffect, useRef } from "react";
import "./App.css";
import bg from "./bg.jpg"; // Assuming you have this in your folder

function App() {
  const [urlInput, setUrlInput] = useState("");
  const [status, setStatus] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null); // Holds the massive JSON payload!

  // We use a ref to store the interval so we can stop it later
  const pollInterval = useRef(null);

  // Cleanup interval if the user closes the page early
  useEffect(() => {
    return () => {
      if (pollInterval.current) clearInterval(pollInterval.current);
    };
  }, []);

  const handleScan = async () => {
    if (!urlInput) return;

    setIsScanning(true);
    setStatus(null);
    setScanResults(null);

    try {
      // 1. Kickoff: Send the URL to Nitish's FastAPI backend
      const response = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlInput }),
      });

      if (!response.ok) throw new Error("Failed to connect to VULKN engine");

      const data = await response.json();
      const scanId = data.scan_id;

      // 2. The Radar: Poll the database every 3 seconds to ask "Are you done?"
      pollInterval.current = setInterval(async () => {
        try {
          const statusRes = await fetch(`http://localhost:8000/scan/${scanId}`);
          const statusData = await statusRes.json();

          // 3. The Reveal: If completed, fetch the final MongoDB report
          if (statusData.status === "Completed") {
            clearInterval(pollInterval.current); // Stop polling
            
            const resultsRes = await fetch(`http://localhost:8000/scan/${scanId}/results`);
            const resultsData = await resultsRes.json();

            setScanResults(resultsData);
            
            // If the scanners found vulnerabilities, trigger the danger state!
            if (resultsData.findings && resultsData.findings.length > 0) {
              setStatus("danger");
            } else {
              setStatus("safe");
            }
            
            setIsScanning(false);
            
          } else if (statusData.status === "Failed") {
            clearInterval(pollInterval.current);
            setIsScanning(false);
            alert("The backend scan failed. Check the server logs.");
          }
        } catch (err) {
          console.error("Polling error:", err);
        }
      }, 3000); // 3000ms = 3 seconds

    } catch (error) {
      console.error("Error starting scan:", error);
      setIsScanning(false);
      alert("Could not connect to backend. Make sure Docker/FastAPI is running on port 8000!");
    }
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

        <input
          type="text"
          value={urlInput}
          onChange={(e) => {
            setUrlInput(e.target.value);
            setStatus(null);
            setScanResults(null);
          }}
          placeholder="Enter URL (e.g., http://testphp.vulnweb.com)"
          className="glass-input"
        />

        <div className={`scan-box ${isScanning ? "scanning" : ""}`}>
          <img className="fingerprint" src="/fingerprint.png" alt="fingerprint" />
          <div className="scan-line"></div>
        </div>

        <div className="ping"></div>

        <button className="scan-btn" onClick={handleScan} disabled={isScanning}>
          <span>{isScanning ? "Scanning Target..." : "Launch AI Scan"}</span>
        </button>

        {/* High-level status text */}
        {status && !isScanning && (
          <div className={`result ${status}`}>
            {status === "danger"
              ? "⚠ THREATS DETECTED — VULNERABILITIES FOUND"
              : "✅ SCAN CLEAN — NO THREATS DETECTED"}
          </div>
        )}

        {/* --- NEW: Display the actual backend findings! --- */}
        {scanResults && status === "danger" && (
            <div style={{ marginTop: '20px', background: 'rgba(0,0,0,0.7)', padding: '20px', borderRadius: '10px', color: 'white', textAlign: 'left', maxHeight: '300px', overflowY: 'auto' }}>
                <h3 style={{ color: '#F87171', borderBottom: '1px solid #555', paddingBottom: '10px' }}>Scanner Findings ({scanResults.findings.length}):</h3>
                {scanResults.findings.map((finding, index) => (
                    <div key={index} style={{ marginBottom: '15px' }}>
                        <strong style={{ color: '#FBBF24' }}>{finding.type}</strong>
                        <span style={{ marginLeft: '10px', fontSize: '12px', background: '#DC2626', padding: '2px 6px', borderRadius: '4px' }}>{finding.severity}</span>
                        <p style={{ fontSize: '14px', margin: '5px 0' }}>{finding.description}</p>
                    </div>
                ))}
            </div>
        )}

      </div>
    </div>
  );
}

export default App;