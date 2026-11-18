import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold tracking-wide uppercase transition-colors',
  {
    variants: {
      variant: {
        neutral: 'border-transparent bg-[var(--color-secondary)] text-[var(--color-secondary-foreground)]',
        success: 'border-transparent bg-[var(--color-sev-low-bg)] text-[var(--color-sev-low)]',
        warning: 'border-transparent bg-[var(--color-sev-medium-bg)] text-[var(--color-sev-medium)]',
        default: 'border-transparent bg-[var(--color-primary)] text-[var(--color-primary-foreground)]',
        secondary: 'border-transparent bg-[var(--color-secondary)] text-[var(--color-secondary-foreground)]',
        outline: 'border-[var(--color-border)] text-[var(--color-foreground)]',
        low: 'border-transparent bg-[var(--color-sev-low-bg)] text-[var(--color-sev-low)]',
        medium: 'border-transparent bg-[var(--color-sev-medium-bg)] text-[var(--color-sev-medium)]',
        high: 'border-transparent bg-[var(--color-sev-high-bg)] text-[var(--color-sev-high)]',
        critical: 'border-transparent bg-[var(--color-sev-critical-bg)] text-[var(--color-sev-critical)]',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge }
