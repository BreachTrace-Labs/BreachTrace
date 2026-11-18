import { Component, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'

type State = { failed: boolean }
export default class ErrorBoundary extends Component<{children: ReactNode}, State> {
  state: State = { failed: false }
  static getDerivedStateFromError(): State { return { failed: true } }
  render() {
    if (this.state.failed) return <main className="not-found"><h1>Something went wrong</h1><span>Reload the app to try again.</span><Button onClick={() => window.location.reload()}>Retry</Button></main>
    return this.props.children
  }
}
