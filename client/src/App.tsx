import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import IncidentDetail from './pages/IncidentDetail'
import Research from './pages/Research'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/incident/:id" element={<IncidentDetail />} />
        <Route path="/research" element={<Research />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
