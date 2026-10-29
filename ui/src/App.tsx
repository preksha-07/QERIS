import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { Dashboard } from './pages/Dashboard';
import { Flows } from './pages/Flows';
import { Devices } from './pages/Devices';
import { Policies } from './pages/Policies';
import { Security } from './pages/Security';
import { AuditLogs } from './pages/AuditLogs';
import { getGatewayStatus } from './services/api';

function App() {
  const [gatewayOnline, setGatewayOnline] = useState(false);

  useEffect(() => {
    // Check gateway status on load and every 15s
    const check = async () => {
      const status = await getGatewayStatus();
      setGatewayOnline(status.online);
    };
    check();
    const interval = setInterval(check, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar gatewayOnline={gatewayOnline} />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard gatewayOnline={gatewayOnline} />} />
            <Route path="/flows" element={<Flows />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/security" element={<Security />} />
            <Route path="/audit" element={<AuditLogs />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
