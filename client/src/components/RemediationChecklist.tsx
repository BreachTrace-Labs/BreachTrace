interface Props {
  steps: string[]
}

const RemediationChecklist: React.FC<Props> = ({ steps }) => {
  return (
    <div className="p-4 border rounded">
      <h2 className="text-lg font-semibold mb-2">Remediation Checklist</h2>
      <ul className="space-y-1">
        {steps.map((step, i) => (
          <li key={i} className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-0.5" readOnly />
            <span>{step}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default RemediationChecklist
