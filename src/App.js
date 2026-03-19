function HelloWASS({ projectName, role }) {
  return (
    <div style={{ padding: '40px', fontFamily: 'sans-serif', textAlign: 'center' }}>
      <h1>Welcome to {projectName} 👋</h1>
      <p>Your role: <strong>{role}</strong></p>
      <p style={{ color: 'green' }}>Frontend is live! 🚀</p>
    </div>
  );
}

function App() {
  return (
    <div>
      <HelloWASS projectName="WASS" role="Frontend Developer" />
    </div>
  );
}

export default App;
