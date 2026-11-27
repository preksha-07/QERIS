import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { CyberBackground } from './components/CyberBackground';
import { Overview } from './pages/Overview';
import { Flows } from './pages/Flows';
import { Devices } from './pages/Devices';
import { Playground } from './pages/Playground';
import { Policies } from './pages/Policies';
import { Security } from './pages/Security';
import { CloudMonitor } from './pages/Cloud';
import { Reports } from './pages/Reports';
import { getGatewayStatus } from './services/api';
import type { GatewayStatus } from './types/qeris';

function App() {
  const [gatewayOnline, setGatewayOnline] = useState(false);
  const [gwStatus, setGwStatus] = useState<GatewayStatus | null>(null);

  useEffect(() => {
    const check = async () => {
      const status = await getGatewayStatus();
      setGatewayOnline(status.online);
      setGwStatus(status);
    };
    check();
    const interval = setInterval(check, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <BrowserRouter>
      <div className="app-layout">
        <CyberBackground />
        <Sidebar
          gatewayOnline={gatewayOnline}
          baselineMode={gwStatus?.baseline_mode}
          policyVersion={gwStatus?.active_policy_version}
        />
        <div className="main-wrapper">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/flows" element={<Flows />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/playground" element={<Playground />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/security" element={<Security />} />
            <Route path="/cloud" element={<CloudMonitor />} />
            <Route path="/reports" element={<Reports />} />
            {/* Fallback legacy redirect */}
            <Route path="/audit" element={<Navigate to="/flows" replace />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;
