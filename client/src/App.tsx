import { BrowserRouter, Route, Routes } from "react-router-dom";
import { ThemeProvider } from "./lib/theme";
import { TooltipProvider } from "./components/ui/tooltip";
import { Layout } from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import IncidentDetail from "./pages/IncidentDetail";
import Research from "./pages/Research";
import Connect from "./pages/Connect";
import Search from "./pages/Search";

function App() {
  return (
    <ThemeProvider>
      <TooltipProvider>
        <BrowserRouter>
          <Layout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/incident/:id" element={<IncidentDetail />} />
              <Route path="/research" element={<Research />} />
              <Route path="/connect" element={<Connect />} />
              <Route path="/search" element={<Search />} />
            </Routes>
          </Layout>
        </BrowserRouter>
      </TooltipProvider>
    </ThemeProvider>
  );
}

export default App;
