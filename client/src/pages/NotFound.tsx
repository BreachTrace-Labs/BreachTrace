import { Link } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { Button } from '@/components/ui/button'
import './settings.css'
export default function NotFound() { const { user } = useAuth(); return <main className="not-found"><p>404</p><h1>Page not found</h1><span>The page you’re looking for doesn’t exist or you don’t have access to it.</span><Button asChild><Link to={user ? '/dashboard' : '/'}>{user ? 'Go to Dashboard' : 'Go to home'}</Link></Button></main> }
